package plugin

import (
	"context"
	"encoding/json"
	"io"

	"github.com/hashicorp/go-plugin"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/x0c/agent-dbctl/internal/types"
)

const (
	// HandshakeCookieKey and Value guard subprocess attachment under hashicorp/go-plugin.
	HandshakeCookieKey   = "AGENT_DBCTL_DRIVER_PLUGIN"
	HandshakeCookieValue = "driver-v1"
	PluginMapKey         = "driver"
)

// Handshake is the shared v1 plugin handshake configuration.
var Handshake = plugin.HandshakeConfig{
	ProtocolVersion:  1,
	MagicCookieKey:   HandshakeCookieKey,
	MagicCookieValue: HandshakeCookieValue,
}

// VersionedHandshake is used with go-plugin VersionedPlugins to negotiate v1 or v2.
var VersionedHandshake = plugin.HandshakeConfig{
	MagicCookieKey:   HandshakeCookieKey,
	MagicCookieValue: HandshakeCookieValue,
}

// TargetSpec describes connection attributes transmitted across gRPC.
type TargetSpec struct {
	Engine       string            `json:"engine"`
	Host         string            `json:"host"`
	Port         int               `json:"port"`
	DatabaseName string            `json:"database_name"`
	Username     string            `json:"username"`
	Password     string            `json:"password"`
	ReadOnly     bool              `json:"read_only"`
	TLSMode      string            `json:"tls_mode,omitempty"`
	Params       map[string]string `json:"params,omitempty"`
}

// ExecuteChunk is one frame in the server-side Execute gRPC stream.
type ExecuteChunk struct {
	Kind          string         `json:"kind"` // header | row | summary
	Family        string         `json:"family,omitempty"`
	Columns       []types.Column `json:"columns,omitempty"`
	Rows          [][]any        `json:"rows,omitempty"`
	Documents     []any          `json:"documents,omitempty"`
	KVResult      any            `json:"kv_result,omitempty"`
	RawText       string         `json:"raw_text,omitempty"`
	AffectedRows  *int64         `json:"affected_rows,omitempty"`
	FetchedRows   int            `json:"fetched_rows,omitempty"`
	Truncated     bool           `json:"truncated,omitempty"`
	CutoffReason  string         `json:"cutoff_reason,omitempty"`
	Messages      []string       `json:"messages,omitempty"`
	LatencyMs     int64          `json:"latency_ms,omitempty"`
	Error         string         `json:"error,omitempty"`
}

// Service is the Go interface implemented by both plugin servers and host gRPC clients.
type Service interface {
	Metadata(ctx context.Context) (types.DriverMetadata, error)
	Ping(ctx context.Context, spec TargetSpec) (types.PingResult, error)
	ListDatabases(ctx context.Context, spec TargetSpec) ([]string, error)
	Classify(ctx context.Context, raw string) (types.Classification, error)
	Preflight(ctx context.Context, spec TargetSpec, raw string) (*types.PreflightReport, error)
	ExecuteStream(ctx context.Context, spec TargetSpec, raw string, maxRows int, maxBytes int64, onChunk func(ExecuteChunk) error) error
}

// CancelableService extends Service with v2 operation-ID execution tracking and out-of-band Cancel RPCs.
type CancelableService interface {
	Service
	ExecuteStreamWithOp(ctx context.Context, opID string, spec TargetSpec, raw string, maxRows int, maxBytes int64, onChunk func(ExecuteChunk) error) error
	Cancel(ctx context.Context, opID string) (bool, string, error)
}

// GRPCPlugin adapts Service to hashicorp/go-plugin's GRPCPlugin.
type GRPCPlugin struct {
	plugin.NetRPCUnsupportedPlugin
	Impl Service
}

func (p *GRPCPlugin) GRPCServer(_ *plugin.GRPCBroker, s *grpc.Server) error {
	s.RegisterService(&driverServiceDesc, p.Impl)
	return nil
}

func (p *GRPCPlugin) GRPCClient(_ context.Context, _ *plugin.GRPCBroker, c *grpc.ClientConn) (any, error) {
	return &grpcClient{cc: c}, nil
}

const serviceName = "driver.v1.DriverPlugin"

var driverServiceDesc = grpc.ServiceDesc{
	ServiceName: serviceName,
	HandlerType: (*Service)(nil),
	Methods: []grpc.MethodDesc{
		{MethodName: "Metadata", Handler: handleMetadata},
		{MethodName: "Ping", Handler: handlePing},
		{MethodName: "ListDatabases", Handler: handleListDatabases},
		{MethodName: "Classify", Handler: handleClassify},
		{MethodName: "Preflight", Handler: handlePreflight},
	},
	Streams: []grpc.StreamDesc{
		{StreamName: "Execute", Handler: handleExecute, ServerStreams: true},
	},
	Metadata: "proto/driver/v1/driver.proto",
}

func toStruct(v any) (*structpb.Struct, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	return structpb.NewStruct(m)
}

func fromStruct[T any](st *structpb.Struct) (T, error) {
	var zero T
	if st == nil {
		return zero, nil
	}
	raw, err := json.Marshal(st.AsMap())
	if err != nil {
		return zero, err
	}
	var out T
	if err := json.Unmarshal(raw, &out); err != nil {
		return zero, err
	}
	return out, nil
}

func handleMetadata(srv any, ctx context.Context, dec func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
	in := new(structpb.Struct)
	if err := dec(in); err != nil {
		return nil, err
	}
	fn := func(ctx context.Context, _ any) (any, error) {
		res, err := srv.(Service).Metadata(ctx)
		if err != nil {
			return nil, err
		}
		return toStruct(res)
	}
	if interceptor == nil {
		return fn(ctx, in)
	}
	return interceptor(ctx, in, &grpc.UnaryServerInfo{Server: srv, FullMethod: "/" + serviceName + "/Metadata"}, fn)
}

func handlePing(srv any, ctx context.Context, dec func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
	in := new(structpb.Struct)
	if err := dec(in); err != nil {
		return nil, err
	}
	fn := func(ctx context.Context, req any) (any, error) {
		spec, err := fromStruct[TargetSpec](req.(*structpb.Struct))
		if err != nil {
			return nil, err
		}
		res, err := srv.(Service).Ping(ctx, spec)
		if err != nil {
			return nil, err
		}
		return toStruct(res)
	}
	if interceptor == nil {
		return fn(ctx, in)
	}
	return interceptor(ctx, in, &grpc.UnaryServerInfo{Server: srv, FullMethod: "/" + serviceName + "/Ping"}, fn)
}

func handleListDatabases(srv any, ctx context.Context, dec func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
	in := new(structpb.Struct)
	if err := dec(in); err != nil {
		return nil, err
	}
	fn := func(ctx context.Context, req any) (any, error) {
		spec, err := fromStruct[TargetSpec](req.(*structpb.Struct))
		if err != nil {
			return nil, err
		}
		dbs, err := srv.(Service).ListDatabases(ctx, spec)
		if err != nil {
			return nil, err
		}
		return toStruct(map[string]any{"databases": dbs})
	}
	if interceptor == nil {
		return fn(ctx, in)
	}
	return interceptor(ctx, in, &grpc.UnaryServerInfo{Server: srv, FullMethod: "/" + serviceName + "/ListDatabases"}, fn)
}

func handleClassify(srv any, ctx context.Context, dec func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
	in := new(structpb.Struct)
	if err := dec(in); err != nil {
		return nil, err
	}
	fn := func(ctx context.Context, req any) (any, error) {
		payload, err := fromStruct[struct {
			Raw string `json:"raw"`
		}](req.(*structpb.Struct))
		if err != nil {
			return nil, err
		}
		res, err := srv.(Service).Classify(ctx, payload.Raw)
		if err != nil {
			return nil, err
		}
		return toStruct(res)
	}
	if interceptor == nil {
		return fn(ctx, in)
	}
	return interceptor(ctx, in, &grpc.UnaryServerInfo{Server: srv, FullMethod: "/" + serviceName + "/Classify"}, fn)
}

func handlePreflight(srv any, ctx context.Context, dec func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
	in := new(structpb.Struct)
	if err := dec(in); err != nil {
		return nil, err
	}
	fn := func(ctx context.Context, req any) (any, error) {
		payload, err := fromStruct[struct {
			Spec TargetSpec `json:"spec"`
			Raw  string     `json:"raw"`
		}](req.(*structpb.Struct))
		if err != nil {
			return nil, err
		}
		res, err := srv.(Service).Preflight(ctx, payload.Spec, payload.Raw)
		if err != nil {
			return nil, err
		}
		return toStruct(res)
	}
	if interceptor == nil {
		return fn(ctx, in)
	}
	return interceptor(ctx, in, &grpc.UnaryServerInfo{Server: srv, FullMethod: "/" + serviceName + "/Preflight"}, fn)
}

func handleExecute(srv any, stream grpc.ServerStream) error {
	in := new(structpb.Struct)
	if err := stream.RecvMsg(in); err != nil {
		return err
	}
	payload, err := fromStruct[struct {
		Spec     TargetSpec `json:"spec"`
		Raw      string     `json:"raw"`
		MaxRows  int        `json:"max_rows"`
		MaxBytes int64      `json:"max_bytes"`
	}](in)
	if err != nil {
		return err
	}
	return srv.(Service).ExecuteStream(stream.Context(), payload.Spec, payload.Raw, payload.MaxRows, payload.MaxBytes, func(chunk ExecuteChunk) error {
		st, err := toStruct(chunk)
		if err != nil {
			return err
		}
		return stream.SendMsg(st)
	})
}

type grpcClient struct {
	cc *grpc.ClientConn
}

func (c *grpcClient) Metadata(ctx context.Context) (types.DriverMetadata, error) {
	req, _ := toStruct(map[string]any{})
	resp := new(structpb.Struct)
	if err := c.cc.Invoke(ctx, "/"+serviceName+"/Metadata", req, resp); err != nil {
		return types.DriverMetadata{}, err
	}
	return fromStruct[types.DriverMetadata](resp)
}

func (c *grpcClient) Ping(ctx context.Context, spec TargetSpec) (types.PingResult, error) {
	req, err := toStruct(spec)
	if err != nil {
		return types.PingResult{}, err
	}
	resp := new(structpb.Struct)
	if err := c.cc.Invoke(ctx, "/"+serviceName+"/Ping", req, resp); err != nil {
		return types.PingResult{}, err
	}
	return fromStruct[types.PingResult](resp)
}

func (c *grpcClient) ListDatabases(ctx context.Context, spec TargetSpec) ([]string, error) {
	req, err := toStruct(spec)
	if err != nil {
		return nil, err
	}
	resp := new(structpb.Struct)
	if err := c.cc.Invoke(ctx, "/"+serviceName+"/ListDatabases", req, resp); err != nil {
		return nil, err
	}
	out, err := fromStruct[struct {
		Databases []string `json:"databases"`
	}](resp)
	return out.Databases, err
}

func (c *grpcClient) Classify(ctx context.Context, raw string) (types.Classification, error) {
	req, err := toStruct(map[string]any{"raw": raw})
	if err != nil {
		return types.Classification{}, err
	}
	resp := new(structpb.Struct)
	if err := c.cc.Invoke(ctx, "/"+serviceName+"/Classify", req, resp); err != nil {
		return types.Classification{}, err
	}
	return fromStruct[types.Classification](resp)
}

func (c *grpcClient) Preflight(ctx context.Context, spec TargetSpec, raw string) (*types.PreflightReport, error) {
	req, err := toStruct(map[string]any{"spec": spec, "raw": raw})
	if err != nil {
		return nil, err
	}
	resp := new(structpb.Struct)
	if err := c.cc.Invoke(ctx, "/"+serviceName+"/Preflight", req, resp); err != nil {
		return nil, err
	}
	out, err := fromStruct[types.PreflightReport](resp)
	return &out, err
}

func (c *grpcClient) ExecuteStream(ctx context.Context, spec TargetSpec, raw string, maxRows int, maxBytes int64, onChunk func(ExecuteChunk) error) error {
	streamCtx, cancelStream := context.WithCancel(ctx)
	defer cancelStream()
	stream, err := c.cc.NewStream(streamCtx, &driverServiceDesc.Streams[0], "/"+serviceName+"/Execute")
	if err != nil {
		return err
	}
	req, err := toStruct(map[string]any{
		"spec":      spec,
		"raw":       raw,
		"max_rows":  maxRows,
		"max_bytes": maxBytes,
	})
	if err != nil {
		return err
	}
	if err := stream.SendMsg(req); err != nil {
		return err
	}
	if err := stream.CloseSend(); err != nil {
		return err
	}
	for {
		msg := new(structpb.Struct)
		err := stream.RecvMsg(msg)
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		chunk, err := fromStruct[ExecuteChunk](msg)
		if err != nil {
			return err
		}
		if err := onChunk(chunk); err != nil {
			return err
		}
	}
}
