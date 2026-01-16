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
	"bytes"
	"context"
	"crypto"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"net/http"
	"net/url"
	"os"

	"github.com/sigstore/rekor-monitor/pkg/tiles"
	"github.com/sigstore/sigstore-go/pkg/root"
	tdlog "github.com/transparency-dev/formats/log"
	tdnote "github.com/transparency-dev/formats/note"
	"github.com/transparency-dev/tessera/api/layout"
	tclient "github.com/transparency-dev/tessera/client"
	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/mod/sumdb/note"
)

type Client struct {
	client   *tclient.HTTPFetcher
	origin   string
	verifier note.Verifier
	fetch    func(context.Context, string) ([]byte, error)
}

// staticCTEntry represents a CT log entry.
// Copied from https://github.com/transparency-dev/tesseract/blob/2d7433c6bac600b988cce7a92bde6f0c69c27254/internal/types/staticct/staticct.go#L213
type staticCTEntry struct {
	Timestamp uint64
	IsPrecert bool
	// Certificate holds different things depending on whether the entry represents a Certificate or a Precertificate submission:
	//   - IsPrecert == false: the bytes here are the x509 certificate submitted for logging.
	//   - IsPrecert == true: the bytes here are the TBS certificate extracted from the submitted precert.
	Certificate []byte
	// Precertificate holds the precertificate to be logged, only used when IsPrecert is true.
	Precertificate    []byte
	IssuerKeyHash     []byte
	RawFingerprints   string
	FingerprintsChain [][32]byte
	RawExtensions     string
	LeafIndex         uint64
}

// UnmarshalText implements encoding/TextUnmarshaler and reads EntryBundles
// which are encoded using the Static CT API spec.
// https://github.com/transparency-dev/tesseract/blob/2d7433c6bac600b988cce7a92bde6f0c69c27254/internal/types/staticct/staticct.go#L246
func (t *staticCTEntry) UnmarshalText(raw []byte) error {
	s := cryptobyte.String(raw)

	entry := []byte{}
	var entryType uint16
	var extensions, fingerprints cryptobyte.String
	if !s.ReadUint64(&t.Timestamp) || !s.ReadUint16(&entryType) || t.Timestamp > math.MaxInt64 {
		return fmt.Errorf("invalid data tile")
	}

	bb := []byte{}
	b := cryptobyte.NewBuilder(bb)
	b.AddUint64(t.Timestamp)
	b.AddUint16(entryType)

	switch entryType {
	case 0: // x509_entry
		t.IsPrecert = false
		if !s.ReadUint24LengthPrefixed((*cryptobyte.String)(&entry)) ||
			!s.ReadUint16LengthPrefixed(&extensions) ||
			!s.ReadUint16LengthPrefixed(&fingerprints) {
			return fmt.Errorf("invalid data tile x509_entry")
		}
		b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddBytes(entry)
			t.Certificate = bytes.Clone(entry)
		})
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddBytes(extensions)
			t.RawExtensions = string(extensions)
		})
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddBytes(fingerprints)
			t.RawFingerprints = string(fingerprints)
		})

	case 1: // precert_entry
		t.IsPrecert = true
		IssuerKeyHash := [32]byte{}
		var defangedCrt, extensions cryptobyte.String
		if !s.CopyBytes(IssuerKeyHash[:]) ||
			!s.ReadUint24LengthPrefixed(&defangedCrt) ||
			!s.ReadUint16LengthPrefixed(&extensions) ||
			!s.ReadUint24LengthPrefixed((*cryptobyte.String)(&entry)) ||
			!s.ReadUint16LengthPrefixed(&fingerprints) {
			return fmt.Errorf("invalid data tile precert_entry")
		}
		b.AddBytes(IssuerKeyHash[:])
		t.IssuerKeyHash = bytes.Clone(IssuerKeyHash[:])
		b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddBytes(defangedCrt)
			t.Certificate = bytes.Clone(defangedCrt)
		})
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddBytes(extensions)
			t.RawExtensions = string(extensions)
		})
		b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddBytes(entry)
			t.Precertificate = bytes.Clone(entry)
		})
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddBytes(fingerprints)
			t.RawFingerprints = string(fingerprints)
		})
	default:
		return fmt.Errorf("invalid data tile: unknown type %d", entryType)
	}

	var err error
	t.LeafIndex, err = ParseCTExtensions(base64.StdEncoding.EncodeToString([]byte(t.RawExtensions)))
	if err != nil {
		return fmt.Errorf("can't parse extensions: %v", err)
	}

	rfp := cryptobyte.String(t.RawFingerprints)
	for i := 0; len(rfp) > 0; i++ {
		fp := [32]byte{}
		if !rfp.CopyBytes(fp[:]) {
			return fmt.Errorf("can't extract fingerprint number %d", i)
		}
		t.FingerprintsChain = append(t.FingerprintsChain, fp)
	}

	if len(s) > 0 {
		return fmt.Errorf("trailing %d bytes after entry", len(s))
	}

	return nil
}

// EntryBundle represents a sequence of entries in the log.
// These entries correspond to a leaf tile in the hash tree.
// Copied from https://github.com/transparency-dev/tesseract/blob/2d7433c6bac600b988cce7a92bde6f0c69c27254/internal/types/staticct/staticct.go#L38
type EntryBundle struct {
	// Entries stores the leaf entries of the log, in order.
	Entries [][]byte
}

// UnmarshalText implements encoding/TextUnmarshaler and reads EntryBundles
// which are encoded using the Static CT API spec.
// TODO(phbnf): we can probably parse every individual leaf directly, since most callers
// of this method tend to do so.
// Copied from https://github.com/transparency-dev/tesseract/blob/2d7433c6bac600b988cce7a92bde6f0c69c27254/internal/types/staticct/staticct.go#L47
func (t *EntryBundle) UnmarshalText(raw []byte) error {
	entries := make([][]byte, 0, layout.EntryBundleWidth)
	s := cryptobyte.String(raw)

	for len(s) > 0 {
		entry := []byte{}
		var timestamp uint64
		var entryType uint16
		var extensions, fingerprints cryptobyte.String
		if !s.ReadUint64(&timestamp) || !s.ReadUint16(&entryType) || timestamp > math.MaxInt64 {
			return fmt.Errorf("invalid data tile")
		}

		bb := []byte{}
		b := cryptobyte.NewBuilder(bb)
		b.AddUint64(timestamp)
		b.AddUint16(entryType)

		switch entryType {
		case 0: // x509_entry
			if !s.ReadUint24LengthPrefixed((*cryptobyte.String)(&entry)) ||
				!s.ReadUint16LengthPrefixed(&extensions) ||
				!s.ReadUint16LengthPrefixed(&fingerprints) {
				return fmt.Errorf("invalid data tile x509_entry")
			}
			b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
				b.AddBytes(entry)
			})
			b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
				b.AddBytes(extensions)
			})
			b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
				b.AddBytes(fingerprints)
			})

		case 1: // precert_entry
			IssuerKeyHash := [32]byte{}
			var defangedCrt, extensions cryptobyte.String
			if !s.CopyBytes(IssuerKeyHash[:]) ||
				!s.ReadUint24LengthPrefixed(&defangedCrt) ||
				!s.ReadUint16LengthPrefixed(&extensions) ||
				!s.ReadUint24LengthPrefixed((*cryptobyte.String)(&entry)) ||
				!s.ReadUint16LengthPrefixed(&fingerprints) {
				return fmt.Errorf("invalid data tile precert_entry")
			}
			b.AddBytes(IssuerKeyHash[:])
			b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
				b.AddBytes(defangedCrt)
			})
			b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
				b.AddBytes(extensions)
			})
			b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
				b.AddBytes(entry)
			})
			b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
				b.AddBytes(fingerprints)
			})
		default:
			return fmt.Errorf("invalid data tile: unknown type %d", entryType)
		}
		entries = append(entries, b.BytesOrPanic())
	}

	t.Entries = entries
	return nil
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

// PartialOrFullResource calls the provided function with the provided partial resource size value in order to fetch and return a static resource.
// If p is non-zero, and f returns os.ErrNotExist, this function will try to fetch the corresponding full resource by calling f a second time passing
// zero.
// Copied from https://github.com/transparency-dev/tessera/blob/da0fd786de1531fb8a50706e90efefa8bb44480c/internal/fetcher/fallback.go#L27
func PartialOrFullResource(ctx context.Context, p uint8, f func(context.Context, uint8) ([]byte, error)) ([]byte, error) {
	sRaw, err := f(ctx, p)
	switch {
	case errors.Is(err, os.ErrNotExist) && p == 0:
		return sRaw, fmt.Errorf("resource not found: %w", err)
	case errors.Is(err, os.ErrNotExist) && p > 0:
		// It could be that the partial resource was removed as the tree has grown and a full resource is now present, so try
		// falling back to that.
		sRaw, err = f(ctx, 0)
		if err != nil {
			return sRaw, fmt.Errorf("neither partial nor full resource found: %w", err)
		}
		return sRaw, nil
	case err != nil:
		return sRaw, fmt.Errorf("failed to fetch resource: %v", err)
	default:
		return sRaw, nil
	}
}

// Copied from https://github.com/transparency-dev/tesseract/blob/2d7433c6bac600b988cce7a92bde6f0c69c27254/internal/client/fetcher.go#L199
func ctEntriesPath(n uint64, p uint8) string {
	return fmt.Sprintf("tile/data/%s", layout.NWithSuffix(0, n, p))
}

func getEntriesFromTile(ctx context.Context, client *Client, fullTileIndex int64, partialTileWidth uint8) ([]Entry, error) {
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

func GetEntriesByIndexRange(ctx context.Context, client *Client, start, end int64) ([]Entry, error) {
	if start > end {
		return nil, fmt.Errorf("start (%d) must be less than or equal to end (%d)", start, end)
	}

	var entries []Entry
	if start == end {
		return entries, nil
	}

	startTileIndex := tiles.GetTileIndex(start)
	startLogSize := start + 1
	endTileIndex := tiles.GetTileIndex(end)
	endLogSize := end + 1

	// If the start and end tiles are different, first we get any remaining unread
	// entries from the start tile
	if startTileIndex < endTileIndex {
		partialBundleSize := startLogSize % layout.TileWidth
		// A partial bundle size of 0 means the start tile was read in full,
		// so no need to read it again. Otherwise, we've only read the tile
		// partially, and we need to read the remaining entries.
		if partialBundleSize > 0 {
			allStartEntries, err := getEntriesFromTile(ctx, client, startTileIndex, 0)
			if err != nil {
				return nil, fmt.Errorf("error getting bundle for tile: %d. Error: %v", startTileIndex, err)
			}
			unreadEntries := allStartEntries[partialBundleSize:]
			entries = append(entries, unreadEntries...)
		}
	}

	// We get all the entries from the full tiles in (start, end)
	for i := startTileIndex + 1; i < endTileIndex; i++ {
		currentEntries, err := getEntriesFromTile(ctx, client, i, 0)
		if err != nil {
			return nil, fmt.Errorf("error getting bundle for tile: %d. Error: %v", i, err)
		}
		entries = append(entries, currentEntries...)
	}

	// Finally, we get all the entries available in the last tile
	partialBundleSize := uint8(endLogSize % layout.TileWidth) //nolint: gosec // G115
	endEntries, err := getEntriesFromTile(ctx, client, endTileIndex, partialBundleSize)
	if err != nil {
		return nil, fmt.Errorf("error getting bundle for tile: %d, width: %d. Error: %v", endTileIndex, partialBundleSize, err)
	}
	entries = append(entries, endEntries...)

	return entries, nil
}

// ParseCTExtensions parses CTExtensions into an index.
// Code is inspired by https://github.com/FiloSottile/sunlight/blob/main/tile.go.
// Copied from https://github.com/transparency-dev/tesseract/blob/2d7433c6bac600b988cce7a92bde6f0c69c27254/internal/types/staticct/staticct.go#L172
func ParseCTExtensions(ext string) (uint64, error) {
	extensionBytes, err := base64.StdEncoding.DecodeString(ext)
	if err != nil {
		return 0, fmt.Errorf("can't decode extensions: %v", err)
	}
	extensions := cryptobyte.String(extensionBytes)
	var extensionType uint8
	var extensionData cryptobyte.String
	var leafIdx uint64
	if !extensions.ReadUint8(&extensionType) {
		return 0, fmt.Errorf("can't read extension type")
	}
	if extensionType != 0 {
		return 0, fmt.Errorf("wrong extension type %d, want 0", extensionType)
	}
	if !extensions.ReadUint16LengthPrefixed(&extensionData) {
		return 0, fmt.Errorf("can't read extension data")
	}
	if !readUint40(&extensionData, &leafIdx) {
		return 0, fmt.Errorf("can't read leaf index from extension")
	}
	if !extensionData.Empty() ||
		!extensions.Empty() {
		return 0, fmt.Errorf("invalid SCT extension data: %v", ext)
	}
	return leafIdx, nil
}

// readUint40 decodes a big-endian, 40-bit value into out and advances over it.
// It reports whether the read was successful.
// Code is copied from https://github.com/FiloSottile/sunlight/blob/main/extensions.go.
// Copied from https://github.com/transparency-dev/tesseract/blob/2d7433c6bac600b988cce7a92bde6f0c69c27254/internal/types/staticct/staticct.go#L203
func readUint40(s *cryptobyte.String, out *uint64) bool {
	var v []byte
	if !s.ReadBytes(&v, 5) {
		return false
	}
	*out = uint64(v[0])<<32 | uint64(v[1])<<24 | uint64(v[2])<<16 | uint64(v[3])<<8 | uint64(v[4])
	return true
}
