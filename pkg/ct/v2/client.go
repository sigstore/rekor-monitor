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

package v2

import (
	"context"
	"crypto"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/sigstore/rekor-monitor/pkg/tiles"
	"github.com/sigstore/sigstore-go/pkg/root"
	tdlog "github.com/transparency-dev/formats/log"
	tdnote "github.com/transparency-dev/formats/note"
	"github.com/transparency-dev/tessera/api/layout"
	tclient "github.com/transparency-dev/tessera/client"
	"golang.org/x/mod/sumdb/note"
)

type Client struct {
	client   *tclient.HTTPFetcher
	origin   string
	verifier note.Verifier
	fetch    func(context.Context, string) ([]byte, error)
}

func ShardClients(shardConfig []string, userAgent string, tlsConfig *tls.Config, trustedRoot *root.TrustedRoot) (map[string]*Client, string, error) {
	latestShardOrigin := ""
	shards := make(map[string]*Client)
	for _, shard := range shardConfig {
		parts := strings.Split(shard, ",")
		if len(parts) < 1 {
			return nil, "", fmt.Errorf("failed to parse shard config")
		}
		url := parts[0]
		var origin string
		var err error
		if len(parts) == 1 {
			origin, err = tiles.GetOrigin(url)
			if err != nil {
				return nil, "", fmt.Errorf("failed to parse origin: %w", err)
			}
		} else {
			origin = parts[1]
		}
		if latestShardOrigin == "" {
			latestShardOrigin = origin
		}
		client, err := NewClient(url, origin, userAgent, tlsConfig, trustedRoot)
		if err != nil {
			return nil, "", fmt.Errorf("getting CT client: %w", err)
		}
		shards[origin] = client
	}
	return shards, latestShardOrigin, nil
}

type Entry struct {
	Entry *staticCTEntry
	Index int64
}

func getLogPublicKey(baseURL string, trustedRoot root.TrustedMaterial) (crypto.PublicKey, error) {
	var matchingLogInstance *root.TransparencyLog
	ctLogs := trustedRoot.CTLogs()
	for _, v := range ctLogs {
		if v.BaseURL == baseURL {
			matchingLogInstance = v
			break
		}
	}
	if matchingLogInstance == nil {
		return nil, fmt.Errorf("couldn't find matching log instance with baseURL %s", baseURL)
	}
	return matchingLogInstance.PublicKey, nil
}

type roundTripper struct {
	http.RoundTripper
	userAgent string
}

func (rt *roundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if rt.userAgent != "" {
		req.Header.Set("User-Agent", rt.userAgent)
	}
	return rt.RoundTripper.RoundTrip(req)
}

func NewClient(baseURL, origin, userAgent string, tlsConfig *tls.Config, trustedRoot *root.TrustedRoot) (*Client, error) {
	pubKey, err := getLogPublicKey(baseURL, trustedRoot)
	if err != nil {
		return nil, fmt.Errorf("getting log verifier: %w", err)
	}
	verifierKey, err := tdnote.RFC6962VerifierString(origin, pubKey)
	if err != nil {
		return nil, fmt.Errorf("getting RFC6962 verifier string for public key: %w", err)
	}
	verifier, err := tdnote.NewVerifier(verifierKey)
	if err != nil {
		return nil, fmt.Errorf("getting log verifier: %w", err)
	}
	transport := http.DefaultTransport
	if tlsConfig != nil {
		transport = &http.Transport{
			TLSClientConfig: tlsConfig,
		}
	}
	if userAgent != "" {
		transport = &roundTripper{RoundTripper: transport, userAgent: userAgent}
	}
	httpClient := &http.Client{
		Transport: transport,
	}
	parsedURL, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("parsing URL: %w", err)
	}
	tileClient, err := tclient.NewHTTPFetcher(parsedURL, httpClient)
	if err != nil {
		return nil, fmt.Errorf("getting tile client: %w", err)
	}

	// Copied from https://github.com/transparency-dev/tessera/blob/da0fd786de1531fb8a50706e90efefa8bb44480c/client/fetcher.go#L63
	fetch := func(ctx context.Context, p string) ([]byte, error) {
		u, err := parsedURL.Parse(p)
		if err != nil {
			return nil, fmt.Errorf("invalid URL: %v", err)
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
		if err != nil {
			return nil, fmt.Errorf("NewRequestWithContext(%q): %v", u.String(), err)
		}
		r, err := httpClient.Do(req)
		if err != nil {
			return nil, fmt.Errorf("get(%q): %v", u.String(), err)
		}
		switch r.StatusCode {
		case http.StatusOK:
			// All good, continue below
		case http.StatusNotFound:
			// Need to return ErrNotExist here, by contract.
			return nil, fmt.Errorf("get(%q): %w", u.String(), os.ErrNotExist)
		default:
			return nil, fmt.Errorf("get(%q): %v", u.String(), r.StatusCode)
		}

		defer func() {
			if err := r.Body.Close(); err != nil {
				log.Printf("resp.Body.Close(): %v", err)
			}
		}()
		return io.ReadAll(r.Body)
	}

	return &Client{
		client:   tileClient,
		origin:   origin,
		verifier: verifier,
		fetch:    fetch,
	}, nil
}

func (c *Client) ReadCheckpoint(ctx context.Context) (*tdlog.Checkpoint, *note.Note, error) {
	cp, _, n, err := tclient.FetchCheckpoint(ctx, c.client.ReadCheckpoint, c.verifier, c.origin)
	if err != nil {
		return nil, nil, fmt.Errorf("fetching checkpoint: %w", err)
	}
	return cp, n, nil
}

func (c *Client) ReadTile(ctx context.Context, level, index uint64, p uint8) ([]byte, error) {
	return c.client.ReadTile(ctx, level, index, p)
}

func (c *Client) ReadEntryBundle(ctx context.Context, index uint64, p uint8) ([]byte, error) {
	return PartialOrFullResource(ctx, p, func(ctx context.Context, p uint8) ([]byte, error) {
		return c.fetch(ctx, ctEntriesPath(index, p))
	})
}

func getEntriesFromTile(ctx context.Context, client tiles.Client, fullTileIndex int64, partialTileWidth uint8) ([]Entry, error) {
	bundleBytes, err := client.ReadEntryBundle(ctx, uint64(fullTileIndex), partialTileWidth) //nolint: gosec // G115
	if err != nil {
		return nil, fmt.Errorf("failed to fetch entry bundle: %w", err)
	}
	var bundle EntryBundle
	err = bundle.UnmarshalText(bundleBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse entry bundle: %w", err)
	}
	var entries []Entry
	for i, entryBytes := range bundle.Entries {
		logEntry := &staticCTEntry{}
		err = logEntry.UnmarshalText(entryBytes)
		if err != nil {
			return nil, fmt.Errorf("unmarshaling entry: %w", err)
		}
		entries = append(entries, Entry{Entry: logEntry, Index: fullTileIndex*layout.TileWidth + int64(i)})
	}
	return entries, nil
}
