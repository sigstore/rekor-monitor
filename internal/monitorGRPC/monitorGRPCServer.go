//
// Copyright 2021 The Sigstore Authors.
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

package monitorGRPC

import (
	context "context"

	"github.com/sigstore/rekor-monitor/mirroring"
)

const (
	logInfoFileName = "/monitor/logInfo.txt"
)

type Server struct {
	UnimplementedMonitorServiceServer
}

func NewServer() *Server {
	return &Server{}
}

func (s *Server) GetLastSnapshot(ctx context.Context, request *Request) (*Response, error) {
	treeSize, root, err := mirroring.ReadLogInfo(logInfoFileName)
	if err != nil {
		return &Response{}, err
	}
	return &Response{TreeSize: treeSize, Root: root}, nil
}
