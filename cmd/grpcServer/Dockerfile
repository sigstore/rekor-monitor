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

# Apply multi-stage build
FROM golang:alpine AS builder
WORKDIR /builder

# Copy go source files for build
COPY go.mod ./
COPY go.sum ./
COPY cmd/grpcServer/main.go ./
COPY ./internal ./internal
COPY ./mirroring ./mirroring 

RUN go build -o grpcServer

# Final image only contains go executable with alpine base image
FROM alpine
WORKDIR /monitor-grpc-service
COPY --from=builder /builder/grpcServer ./
ENTRYPOINT [ "/monitor-grpc-service/grpcServer" ]
EXPOSE 9000
