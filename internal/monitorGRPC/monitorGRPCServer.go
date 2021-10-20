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
