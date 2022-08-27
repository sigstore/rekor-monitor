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

FROM golang:1.19.0@sha256:1860373709cc04bacfcf3bb1aaa8c14bb1243e971e9c4e70607ffa05f72466d6

WORKDIR /build

COPY go.mod ./
COPY go.sum ./

RUN mkdir mirroring
COPY ./mirroring/*.go ./mirroring
COPY ./cmd/mirroring/main.go ./

RUN go build -o /mirroring

ENTRYPOINT [ "/mirroring" ]