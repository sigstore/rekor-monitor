// Code generated by protoc-gen-go-grpc. DO NOT EDIT.

package monitorGRPC

import (
	context "context"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
)

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
// Requires gRPC-Go v1.32.0 or later.
const _ = grpc.SupportPackageIsVersion7

// MonitorServiceClient is the client API for MonitorService service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type MonitorServiceClient interface {
	GetLastSnapshot(ctx context.Context, in *LastSnapshotRequest, opts ...grpc.CallOption) (*LastSnapshotResponse, error)
}

type monitorServiceClient struct {
	cc grpc.ClientConnInterface
}

func NewMonitorServiceClient(cc grpc.ClientConnInterface) MonitorServiceClient {
	return &monitorServiceClient{cc}
}

func (c *monitorServiceClient) GetLastSnapshot(ctx context.Context, in *LastSnapshotRequest, opts ...grpc.CallOption) (*LastSnapshotResponse, error) {
	out := new(LastSnapshotResponse)
	err := c.cc.Invoke(ctx, "/monitor.MonitorService/GetLastSnapshot", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// MonitorServiceServer is the server API for MonitorService service.
// All implementations must embed UnimplementedMonitorServiceServer
// for forward compatibility
type MonitorServiceServer interface {
	GetLastSnapshot(context.Context, *LastSnapshotRequest) (*LastSnapshotResponse, error)
	mustEmbedUnimplementedMonitorServiceServer()
}

// UnimplementedMonitorServiceServer must be embedded to have forward compatible implementations.
type UnimplementedMonitorServiceServer struct {
}

func (UnimplementedMonitorServiceServer) GetLastSnapshot(context.Context, *LastSnapshotRequest) (*LastSnapshotResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetLastSnapshot not implemented")
}
func (UnimplementedMonitorServiceServer) mustEmbedUnimplementedMonitorServiceServer() {}

// UnsafeMonitorServiceServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to MonitorServiceServer will
// result in compilation errors.
type UnsafeMonitorServiceServer interface {
	mustEmbedUnimplementedMonitorServiceServer()
}

func RegisterMonitorServiceServer(s grpc.ServiceRegistrar, srv MonitorServiceServer) {
	s.RegisterService(&MonitorService_ServiceDesc, srv)
}

func _MonitorService_GetLastSnapshot_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(LastSnapshotRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(MonitorServiceServer).GetLastSnapshot(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/monitor.MonitorService/GetLastSnapshot",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(MonitorServiceServer).GetLastSnapshot(ctx, req.(*LastSnapshotRequest))
	}
	return interceptor(ctx, in, info, handler)
}

// MonitorService_ServiceDesc is the grpc.ServiceDesc for MonitorService service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var MonitorService_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "monitor.MonitorService",
	HandlerType: (*MonitorServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "GetLastSnapshot",
			Handler:    _MonitorService_GetLastSnapshot_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "monitor.proto",
}