// Copyright 2024 The Sigstore Authors.
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

package ct

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

const (
	ValidSTHResponseTreeSize                 = 3721782
	ValidSTHResponseTimestamp         uint64 = 1396609800587
	ValidSTHResponseSHA256RootHash           = "SxKOxksguvHPyUaKYKXoZHzXl91Q257+JQ0AUMlFfeo="
	ValidSTHResponseTreeHeadSignature        = "BAMARjBEAiBUYO2tODlUUw4oWGiVPUHqZadRRyXs9T2rSXchA79VsQIgLASkQv3cu4XdPFCZbgFkIUefniNPCpO3LzzHX53l+wg="
	GetSTHConsistencyEmptyResp               = `{ "consistency": [ ] }`
)

// serverHandlerAt returns a test HTTP server that only expects requests at the given path, and invokes
// the provided handler for that path.
func serverHandlerAt(t *testing.T, path string, handler func(http.ResponseWriter, *http.Request)) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == path {
			handler(w, r)
		} else {
			t.Fatalf("Incorrect URL path: %s", r.URL.Path)
		}
	}))
}

// serveRspAt returns a test HTTP server that returns a canned response body rsp for a given path.
func serveRspAt(t *testing.T, path, rsp string) *httptest.Server {
	t.Helper()
	return serverHandlerAt(t, path, func(w http.ResponseWriter, _ *http.Request) {
		if _, err := fmt.Fprint(w, rsp); err != nil {
			t.Fatal(err)
		}
	})
}
