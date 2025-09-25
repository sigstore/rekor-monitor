#
# Copyright 2021 The Sigstore Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

.PHONY: all test clean ldflags

all: build

GIT_VERSION ?= $(shell git describe --tags --always --dirty)
GIT_HASH ?= $(shell git rev-parse HEAD)
DATE_FMT = +%Y-%m-%dT%H:%M:%SZ
SOURCE_DATE_EPOCH ?= $(shell git log -1 --pretty=%ct)
ifdef SOURCE_DATE_EPOCH
    BUILD_DATE ?= $(shell date -u -d "@$(SOURCE_DATE_EPOCH)" "$(DATE_FMT)" 2>/dev/null || date -u -r "$(SOURCE_DATE_EPOCH)" "$(DATE_FMT)" 2>/dev/null || date -u "$(DATE_FMT)")
else
    BUILD_DATE ?= $(shell date "$(DATE_FMT)")
endif
GIT_TREESTATE = "clean"
DIFF = $(shell git diff --quiet >/dev/null 2>&1; if [ $$? -eq 1 ]; then echo "1"; fi)
ifeq ($(DIFF), 1)
    GIT_TREESTATE = "dirty"
endif

MONITOR_LDFLAGS=-buildid= \
	-X sigs.k8s.io/release-utils/version.gitVersion=$(GIT_VERSION) \
	-X sigs.k8s.io/release-utils/version.gitCommit=$(GIT_HASH) \
	-X sigs.k8s.io/release-utils/version.gitTreeState=$(GIT_TREESTATE) \
	-X sigs.k8s.io/release-utils/version.buildDate=$(BUILD_DATE)

build:
	go build -ldflags "$(MONITOR_LDFLAGS)" ./cmd/rekor_monitor
	go build -ldflags "$(MONITOR_LDFLAGS)" ./cmd/ct_monitor

ldflags: ## Print ldflags
	@echo $(MONITOR_LDFLAGS)

test:
	go test ./...

clean:
	rm -f ./rekor_monitor
	rm -f ./ct_monitor

.PHONY: build test clean
