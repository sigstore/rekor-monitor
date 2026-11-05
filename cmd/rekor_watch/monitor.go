//
// Copyright 2026 The Sigstore Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"context"
	"errors"
	"fmt"
	"log"

	"github.com/sigstore/rekor-monitor/pkg/identity"
	rekor_v2 "github.com/sigstore/rekor-monitor/pkg/rekor/v2"
	"github.com/sigstore/rekor-monitor/pkg/store"
	"github.com/sigstore/rekor-monitor/pkg/tiles"
	tdlog "github.com/transparency-dev/formats/log"
)

// monitor runs a single Rekor v2 monitoring iteration: it refreshes the shard
// set, then catches up every shard the tracker knows about and records matches
// and checkpoints. Its dependencies are stable for the lifetime of the loop;
// per-iteration state (subscriptions, shards) is loaded inside runOnce.
type monitor struct {
	tracker    *shardTracker
	store      store.TransactionalStore
	searchOpts []identity.SearchOption
	maxMatches int
}

// runOnce performs one monitoring iteration. It satisfies IterationFunc.
//
// It catches up every shard the tracker knows about, not just the active one:
// a rollover otherwise strands the tail of the previous shard and skips the
// entries already on the new shard.
func (m *monitor) runOnce(ctx context.Context) error {
	if err := m.tracker.refresh(ctx); err != nil {
		// A refresh failure (e.g. transient TUF/network error) must not halt
		// monitoring: the existing shards are still valid, so continue and
		// retry on the next iteration.
		log.Printf("WARNING: refreshing Rekor shards failed, continuing with existing shards: %v\n", err)
	}

	// Load all subscriptions so matches continue to be recorded even when
	// webhook delivery is temporarily disabled or backing off.
	subs, err := m.store.ListSubscriptions(ctx)
	if err != nil {
		return fmt.Errorf("error loading subscriptions: %w", err)
	}
	monitoredValues := collectMonitoredValues(subs)
	subsByValue := groupSubscriptionsByValue(subs)
	log.Printf("Loaded %d unique monitored values from %d subscriptions", len(monitoredValues), len(subs))

	// Computed once per iteration: a multi-shard first deploy must not see its
	// own just-saved checkpoint and mistake a later shard for a rollover.
	hasAnyCheckpoint, err := m.store.HasAnyCheckpoint(ctx)
	if err != nil {
		return fmt.Errorf("error checking for existing checkpoints in database: %w", err)
	}

	// Each shard is caught up in its own transaction, so the order is irrelevant.
	var errs error
	for origin := range m.tracker.shards {
		if err := m.catchUpShard(ctx, origin, hasAnyCheckpoint, monitoredValues, subsByValue); err != nil {
			errs = errors.Join(errs, fmt.Errorf("shard %s: %w", origin, err))
		}
	}
	return errs
}

// decideSearchRange returns the (startIdx, endIdx] range to scan on the shard
// being processed this iteration, or search=false to skip the scan entirely.
// When search is false the index values carry no meaning.
//
// When there is no checkpoint for this shard's origin, hasAnyCheckpoint
// distinguishes a true first-time deploy (no checkpoints anywhere, monitor
// going forward only) from a rollover to a new shard while checkpoints for
// prior origins still exist (back-search the new shard so pre-existing
// entries match subscriptions).
func decideSearchRange(prev, current *tdlog.Checkpoint, hasAnyCheckpoint bool) (startIdx, endIdx int64, search bool) {
	if prev == nil {
		if !hasAnyCheckpoint || current.Size == 0 {
			return 0, 0, false
		}
		// Rollover: (-1, current.Size-1] covers indices [0, current.Size).
		return -1, int64(current.Size) - 1, true //nolint: gosec // G115, log will never be large enough to overflow
	}
	startIdx = int64(prev.Size) - 1  //nolint: gosec // G115, log will never be large enough to overflow
	endIdx = int64(current.Size) - 1 //nolint: gosec // G115, log will never be large enough to overflow
	return startIdx, endIdx, startIdx < endIdx
}

// catchUpShard scans a single shard's new entries and records any matches and
// its updated checkpoint in one transaction.
func (m *monitor) catchUpShard(ctx context.Context, origin string, hasAnyCheckpoint bool, monitoredValues identity.MonitoredValues, subsByValue map[string][]*store.Subscription) error {
	// Load previous checkpoint from database
	log.Printf("Loading checkpoint for origin: %s", origin)
	prevCheckpoint, err := m.store.LoadCheckpoint(ctx, origin)
	if err != nil {
		return fmt.Errorf("error loading checkpoint from database: %w", err)
	}

	switch {
	case prevCheckpoint != nil:
		log.Printf("Previous checkpoint loaded: size=%d", prevCheckpoint.Size)
	case hasAnyCheckpoint:
		log.Printf("No checkpoint for origin %s but prior origins exist; treating as a shard rollover", origin)
	default:
		log.Println("No previous checkpoint found in database")
	}

	// Run consistency check (verifies log hasn't been tampered with)
	log.Println("Running consistency check...")
	currentCheckpoint, err := tiles.VerifyConsistencyWithCheckpoint(ctx, m.tracker.shards, origin, prevCheckpoint)
	if err != nil {
		return fmt.Errorf("error running consistency check: %w", err)
	}
	log.Printf("Consistency check passed for %s. Current log size: %d", origin, currentCheckpoint.Size)

	// Already caught up: skip the scan and a redundant, identical checkpoint write.
	if prevCheckpoint != nil && prevCheckpoint.Size == currentCheckpoint.Size {
		log.Printf("No new entries to process for %s (size %d unchanged)", origin, prevCheckpoint.Size)
		return nil
	}

	foundEntries := []identity.MonitoredIdentity{}
	failedEntries := []identity.FailedLogEntry{}

	startIndex, endIndex, shouldSearch := decideSearchRange(prevCheckpoint, currentCheckpoint, hasAnyCheckpoint)

	switch {
	case shouldSearch && prevCheckpoint != nil:
		log.Printf("Resuming from saved checkpoint at size %d (startIndex: %d)", prevCheckpoint.Size, startIndex)
	case shouldSearch:
		log.Printf("Back-searching new shard %s after rollover (range (%d, %d])", origin, startIndex, endIndex)
	default:
		log.Println("No previous checkpoint found, this is the first run")
	}

	if shouldSearch {
		log.Printf("Searching entries with index in range (%d, %d] (%d new entries)", startIndex, endIndex, endIndex-startIndex)
		if err := identity.VerifyMonitoredValues(monitoredValues); err == nil {
			log.Println("Starting identity search...")
			foundEntries, failedEntries, err = rekor_v2.IdentitySearch(ctx, m.tracker.shards, origin, monitoredValues, startIndex, endIndex, m.searchOpts...)
			if err != nil {
				return fmt.Errorf("error searching for identities: %w", err)
			}
			log.Printf("Identity search completed: found %d matching entries, %d failed entries", len(foundEntries), len(failedEntries))
		} else {
			log.Printf("Error verifying monitored values: %v, skipping identity search", err)
		}
	}

	if len(failedEntries) > 0 {
		log.Printf("Warning: %d entries failed to parse; persisting them for later investigation", len(failedEntries))
	}

	// Start transaction for saving matches, failed entries, and checkpoint
	tx, err := m.store.BeginTx(ctx)
	if err != nil {
		return fmt.Errorf("error starting transaction: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck

	// Save matches as we process them — one per (entry, subscription) pair.
	// Track which subscriptions received matches so we can trim them once
	// per iteration before commit, keeping retention atomic with the inserts.
	matchCount := 0
	affectedSubs := make(map[int64]bool)
	if len(foundEntries) > 0 {
		log.Printf("Processing %d found identity entries...", len(foundEntries))
		for _, monitoredEntry := range foundEntries {
			fmt.Printf("\tIdentity: %s\n", monitoredEntry.Identity)
			for _, entry := range monitoredEntry.FoundIdentityEntries {
				fmt.Printf("LogEntry:\n")
				matchedStr, err := entry.MatchedIdentity.String()
				if err != nil {
					return fmt.Errorf("error getting string representation of matched identity: %w", err)
				}
				fmt.Printf("\tMatchedIdentity: %s\n", matchedStr)
				fmt.Printf("\tIndex: %d\n", entry.Index)
				fmt.Printf("\tUUID: %s\n", entry.UUID)
				fmt.Printf("\tCertSubject: %s\n", entry.CertSubject)
				fmt.Printf("\tIssuer: %s\n", entry.Issuer)
				fmt.Printf("\tFingerprint: %s\n", entry.Fingerprint)
				fmt.Printf("\tSubject: %s\n", entry.Subject)
				fmt.Printf("\tOIDExtension: %s\n", entry.OIDExtension)
				fmt.Printf("\tExtensionValue: %s\n\n", entry.ExtensionValue)
				fmt.Println("--------------------------------")
				for _, sub := range subsByValue[matchedStr] {
					match := &store.Match{
						Origin:         origin,
						LogIndex:       entry.Index,
						UUID:           entry.UUID,
						CertSubject:    entry.CertSubject,
						Issuer:         entry.Issuer,
						Fingerprint:    entry.Fingerprint,
						Subject:        entry.Subject,
						OIDExtension:   entry.OIDExtension.String(),
						ExtensionValue: entry.ExtensionValue,
						SubscriptionID: sub.ID,
					}
					if err := tx.SaveMatch(ctx, match); err != nil {
						return fmt.Errorf(
							"error saving match (index %d, sub %d): %w",
							entry.Index, sub.ID, err,
						)
					}
					affectedSubs[sub.ID] = true
					matchCount++
					log.Printf(
						"Saved match: origin=%s, index=%d, identity=%s, subscription=%d",
						origin, entry.Index, matchedStr, sub.ID,
					)
				}
			}
		}
	} else {
		log.Println("No matching identities found in the searched range")
	}

	// Persist entries that failed to parse so operators can investigate them
	// later instead of losing them to log output. Kept in the same
	// transaction as matches and the checkpoint so a write failure rolls the
	// whole iteration back rather than advancing past unrecorded failures.
	for _, fe := range failedEntries {
		if err := tx.SaveFailedEntry(ctx, &store.FailedEntry{
			Origin:   origin,
			LogIndex: fe.Index,
			UUID:     fe.UUID,
			Error:    fe.Error,
		}); err != nil {
			return fmt.Errorf("error saving failed entry (index %d): %w", fe.Index, err)
		}
	}

	// Enforce per-subscription retention: cap how many matches each affected
	// subscription retains, evicting the oldest FIFO. Runs inside the same
	// transaction so the cap is observed atomically with the inserts.
	for subID := range affectedSubs {
		if err := tx.TrimMatches(ctx, subID, m.maxMatches); err != nil {
			return fmt.Errorf("error trimming matches for subscription %d: %w", subID, err)
		}
	}

	// Save the current checkpoint after successful processing
	log.Printf("Saving checkpoint for %s at size %d", origin, currentCheckpoint.Size)
	if err := tx.SaveCheckpoint(ctx, currentCheckpoint); err != nil {
		return fmt.Errorf("error saving checkpoint: %w", err)
	}

	// Commit transaction
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("error committing transaction: %w", err)
	}

	log.Printf("Transaction committed for %s: %d matches saved, %d failed entries saved, checkpoint at size %d", origin, matchCount, len(failedEntries), currentCheckpoint.Size)
	return nil
}

// collectMonitoredValues extracts deduplicated MonitoredValues from
// subscriptions. Values are keyed by their string representation;
// subscriptions with unparseable values are skipped.
func collectMonitoredValues(subs []*store.Subscription) identity.MonitoredValues {
	seen := make(map[string]bool)
	var vals identity.MonitoredValues
	for _, sub := range subs {
		key, err := sub.MonitoredValue.String()
		if err != nil {
			log.Printf("error getting string representation of monitored value: %v, skipping", err)
			continue
		}
		if !seen[key] {
			seen[key] = true
			vals = append(vals, sub.MonitoredValue)
		}
	}
	return vals
}

// groupSubscriptionsByValue indexes subscriptions by their
// MonitoredValue string representation, so callers can look up which
// subscriptions (and webhook URLs) correspond to a matched identity.
func groupSubscriptionsByValue(
	subs []*store.Subscription,
) map[string][]*store.Subscription {
	m := make(map[string][]*store.Subscription)
	for _, sub := range subs {
		key, err := sub.MonitoredValue.String()
		if err != nil {
			log.Printf("error getting string representation of monitored value: %v, skipping", err)
			continue
		}
		m[key] = append(m[key], sub)
	}
	return m
}
