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
	"fmt"
	"log"
	"math/rand/v2"
	"net/http"
	"net/url"
	"time"

	"github.com/sigstore/rekor-monitor/cmd/rekor_watch/notifications"
	"github.com/sigstore/rekor-monitor/cmd/rekor_watch/web"
	"github.com/sigstore/rekor-monitor/pkg/store"
)

const (
	notificationBackoffBase            = 1 * time.Minute
	notificationBackoffMax             = 1 * time.Hour
	notificationMaxConsecutiveFailures = 10
	notificationBackoffJitter          = 0.25 // ±25% jitter

	// MaxMatchesPerBatch caps the number of matches carried by a single
	// webhook POST. A subscription with more pending matches drains over
	// successive polling cycles, preserving consumer backpressure.
	MaxMatchesPerBatch = 100
)

// notificationBackoff returns the base backoff duration for the given number of
// consecutive failures. The progression is 1m, 2m, 4m, 8m, 16m, 32m, 1h
// (capped at notificationBackoffMax). This is deterministic; use
// notificationBackoffWithJitter at call sites to add randomized jitter.
func notificationBackoff(failures int) time.Duration {
	if failures <= 0 {
		return 0
	}
	d := notificationBackoffBase
	for i := 1; i < failures; i++ {
		d *= 2
		if d >= notificationBackoffMax {
			return notificationBackoffMax
		}
	}
	return d
}

// notificationBackoffWithJitter returns the backoff duration with ±25% random
// jitter applied. The jitter spreads out retry storms when many
// subscriptions fail at the same time.
func notificationBackoffWithJitter(failures int) time.Duration {
	base := notificationBackoff(failures)
	if base == 0 {
		return 0
	}
	// jitter in [-0.25, +0.25] of base; given base >= 1m, the result
	// is always >= 45s, so no negative clamp is needed.
	jitter := (rand.Float64()*2 - 1) * notificationBackoffJitter * float64(base) //nolint:gosec // backoff jitter does not need crypto-strength randomness
	d := time.Duration(float64(base) + jitter)
	if d > notificationBackoffMax {
		d = notificationBackoffMax
	}
	return d
}

// notifier delivers pending matches to their subscribers.
type notifier struct {
	store   store.Store
	webhook *notifications.WebhookSender
	email   web.EmailSender
	limiter *web.RateLimiter
}

func newNotifier(dbStore store.Store, userAgent string, httpClient *http.Client, limiter *web.RateLimiter, emailSender web.EmailSender) *notifier {
	return &notifier{
		store:   dbStore,
		webhook: notifications.NewWebhookSender(userAgent, httpClient),
		email:   emailSender,
		limiter: limiter,
	}
}

// runOnce queries for un-notified matches, groups them by subscription, and
// dispatches each subscription's batch through its channel (webhook or email).
// Delivery failures feed the shared per-subscription backoff and auto-disable;
// delivered matches are marked notified. now is the dispatch cycle's wall-clock
// time, used for backoff comparisons and payload timestamps.
func (n *notifier) runOnce(ctx context.Context, now time.Time) error {
	pending, err := n.store.ListPendingMatches(ctx)
	if err != nil {
		return err
	}
	if len(pending) == 0 {
		return nil
	}

	log.Printf(
		"Sending notifications for %d pending matches",
		len(pending),
	)

	// Group pending matches by subscription ID.
	groups := make(map[int64][]*store.PendingMatch)
	for _, pm := range pending {
		groups[pm.Subscription.ID] = append(groups[pm.Subscription.ID], pm)
	}

	for subID, matches := range groups {
		sub := matches[0].Subscription

		// Skip disabled subscriptions
		if sub.DisabledAt != nil {
			continue
		}

		// Check backoff: if a next-retry time was set on the last
		// failure, skip until that time has elapsed.
		if sub.NextRetryAt != nil && now.Before(*sub.NextRetryAt) {
			log.Printf(
				"Skipping subscription %d: backing off until %s (%d consecutive failures)",
				subID, sub.NextRetryAt.Format(time.RFC3339), sub.ConsecutiveFailures,
			)
			continue
		}

		// ListPendingMatches returns oldest-first per its interface
		// contract, so a slice prefix drains the oldest work first.
		batch := matches
		if len(batch) > MaxMatchesPerBatch {
			batch = batch[:MaxMatchesPerBatch]
		}

		mvJSON, err := sub.MonitoredValue.MarshalJSON()
		if err != nil {
			log.Printf("Failed to marshal monitored value for subscription %d: %v", subID, err)
			continue
		}

		entries := make([]notifications.NotificationMatch, len(batch))
		matchIDs := make([]int64, len(batch))
		for i, pm := range batch {
			entries[i] = notifications.NotificationMatch{
				Origin:         pm.Origin,
				LogIndex:       pm.LogIndex,
				UUID:           pm.UUID,
				CertSubject:    pm.CertSubject,
				Issuer:         pm.Issuer,
				Fingerprint:    pm.Fingerprint,
				Subject:        pm.Subject,
				OIDExtension:   pm.OIDExtension,
				ExtensionValue: pm.ExtensionValue,
			}
			matchIDs[i] = pm.ID
		}

		payload := notifications.NotificationPayload{
			Type:      notifications.NotificationEventTypeMatchCreated,
			Timestamp: now.UTC().Format(time.RFC3339),
			Data: notifications.NotificationData{
				SubscriptionName: sub.Name,
				MonitoredValue:   mvJSON,
				Entries:          entries,
			},
		}

		var sendErr error
		switch sub.NotificationType {
		case store.NotificationTypeWebhook:
			// Rate-limit per destination host. Consumed once per batch.
			if n.limiter != nil {
				host := webhookHost(sub.WebhookURL)
				if allowed, _ := n.limiter.Allow(host); !allowed {
					log.Printf(
						"Webhook rate limit hit for %s, skipping subscription %d (%d matches deferred)",
						host, subID, len(batch),
					)
					continue
				}
			}
			sendErr = n.webhook.Send(ctx, sub.WebhookURL, payload)
		case store.NotificationTypeEmail:
			user := matches[0].User
			subject, body := notifications.RenderMatchEmail(payload)
			sendErr = n.email.Send(ctx, user.Email, subject, body)
		default:
			sendErr = fmt.Errorf("unknown notification_type %q", sub.NotificationType)
		}

		if sendErr != nil {
			log.Printf("Failed to send %s notification for subscription %d (%d matches): %v", sub.NotificationType, subID, len(batch), sendErr)
			nextRetry := now.Add(notificationBackoffWithJitter(sub.ConsecutiveFailures + 1))
			newCount, recErr := n.store.RecordNotificationFailure(ctx, subID, now, nextRetry)
			if recErr != nil {
				log.Printf("Failed to record notification failure for subscription %d: %v", subID, recErr)
			} else if newCount >= notificationMaxConsecutiveFailures {
				if disErr := n.store.SetSubscriptionEnabled(ctx, subID, sub.UserID, false); disErr != nil {
					log.Printf("Failed to disable subscription %d: %v", subID, disErr)
				} else {
					log.Printf("Subscription %d disabled after %d consecutive notification failures", subID, newCount)
				}
			}
			continue
		}

		if err := n.store.MarkMatchesNotified(ctx, matchIDs); err != nil {
			log.Printf("Failed to mark %d matches as notified for subscription %d: %v", len(matchIDs), subID, err)
		}
		if err := n.store.RecordNotificationSuccess(ctx, subID); err != nil {
			log.Printf("Failed to record notification success for subscription %d: %v", subID, err)
		}
	}

	return nil
}

// webhookHost extracts the host (including port when present) from a
// webhook URL. Different ports are treated as different destinations
// since they typically represent different services. On parse failure
// it returns the raw URL so the limiter still keys on something
// consistent.
func webhookHost(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	return u.Host
}
