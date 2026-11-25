package plugin

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"time"

	"github.com/hashicorp/go-plugin"
	"google.golang.org/grpc"

	"github.com/x0c/agent-dbctl/internal/driver/plugin/v2pb"
	"github.com/x0c/agent-dbctl/internal/types"
)

// GRPCPluginV2 adapts CancelableService to hashicorp/go-plugin's GRPCPlugin using typed Protobuf v2.
type GRPCPluginV2 struct {
	plugin.NetRPCUnsupportedPlugin
	Impl CancelableService
}

func (p *GRPCPluginV2) GRPCServer(_ *plugin.GRPCBroker, s *grpc.Server) error {
	v2pb.RegisterDriverPluginServer(s, &grpcV2Server{impl: p.Impl})
	return nil
}

func (p *GRPCPluginV2) GRPCClient(_ context.Context, _ *plugin.GRPCBroker, c *grpc.ClientConn) (any, error) {
	return &grpcV2Client{client: v2pb.NewDriverPluginClient(c)}, nil
}

type grpcV2Server struct {
	v2pb.UnimplementedDriverPluginServer
	impl CancelableService
}

func (s *grpcV2Server) Metadata(ctx context.Context, _ *v2pb.Empty) (*v2pb.DriverMetadata, error) {
	meta, err := s.impl.Metadata(ctx)
	if err != nil {
		return nil, err
	}
	return metadataToV2(meta), nil
}

func (s *grpcV2Server) Ping(ctx context.Context, req *v2pb.TargetSpec) (*v2pb.PingResult, error) {
	res, err := s.impl.Ping(ctx, targetSpecFromV2(req))
	if err != nil {
		return nil, err
	}
	return pingResultToV2(res), nil
}

func (s *grpcV2Server) ListDatabases(ctx context.Context, req *v2pb.TargetSpec) (*v2pb.DatabaseList, error) {
	dbs, err := s.impl.ListDatabases(ctx, targetSpecFromV2(req))
	if err != nil {
		return nil, err
	}
	return &v2pb.DatabaseList{Databases: dbs}, nil
}

func (s *grpcV2Server) Classify(ctx context.Context, req *v2pb.ClassifyRequest) (*v2pb.Classification, error) {
	cls, err := s.impl.Classify(ctx, req.GetRaw())
	if err != nil {
		return nil, err
	}
	return classificationToV2(cls), nil
}

func (s *grpcV2Server) Preflight(ctx context.Context, req *v2pb.PreflightRequest) (*v2pb.PreflightReport, error) {
	rep, err := s.impl.Preflight(ctx, targetSpecFromV2(req.GetSpec()), req.GetRaw())
	if err != nil {
		return nil, err
	}
	return preflightToV2(rep), nil
}

func (s *grpcV2Server) Execute(req *v2pb.ExecuteRequest, stream v2pb.DriverPlugin_ExecuteServer) error {
	spec := targetSpecFromV2(req.GetSpec())
	return s.impl.ExecuteStreamWithOp(stream.Context(), req.GetOperationId(), spec, req.GetRaw(), int(req.GetMaxRows()), req.GetMaxBytes(), func(chunk ExecuteChunk) error {
		return stream.Send(chunkToV2(chunk))
	})
}

func (s *grpcV2Server) Cancel(ctx context.Context, req *v2pb.CancelRequest) (*v2pb.CancelResponse, error) {
	ok, msg, err := s.impl.Cancel(ctx, req.GetOperationId())
	if err != nil {
		return nil, err
	}
	return &v2pb.CancelResponse{Cancelled: ok, Message: msg}, nil
}

type grpcV2Client struct {
	client v2pb.DriverPluginClient
}

func (c *grpcV2Client) Metadata(ctx context.Context) (types.DriverMetadata, error) {
	resp, err := c.client.Metadata(ctx, &v2pb.Empty{})
	if err != nil {
		return types.DriverMetadata{}, err
	}
	return metadataFromV2(resp), nil
}

func (c *grpcV2Client) Ping(ctx context.Context, spec TargetSpec) (types.PingResult, error) {
	resp, err := c.client.Ping(ctx, targetSpecToV2(spec))
	if err != nil {
		return types.PingResult{}, err
	}
	return pingResultFromV2(resp), nil
}

func (c *grpcV2Client) ListDatabases(ctx context.Context, spec TargetSpec) ([]string, error) {
	resp, err := c.client.ListDatabases(ctx, targetSpecToV2(spec))
	if err != nil {
		return nil, err
	}
	return resp.GetDatabases(), nil
}

func (c *grpcV2Client) Classify(ctx context.Context, raw string) (types.Classification, error) {
	resp, err := c.client.Classify(ctx, &v2pb.ClassifyRequest{Raw: raw})
	if err != nil {
		return types.Classification{}, err
	}
	return classificationFromV2(resp), nil
}

func (c *grpcV2Client) Preflight(ctx context.Context, spec TargetSpec, raw string) (*types.PreflightReport, error) {
	resp, err := c.client.Preflight(ctx, &v2pb.PreflightRequest{
		Spec: targetSpecToV2(spec),
		Raw:  raw,
	})
	if err != nil {
		return nil, err
	}
	return preflightFromV2(resp), nil
}

func (c *grpcV2Client) ExecuteStream(ctx context.Context, spec TargetSpec, raw string, maxRows int, maxBytes int64, onChunk func(ExecuteChunk) error) error {
	return c.ExecuteStreamWithOp(ctx, "", spec, raw, maxRows, maxBytes, onChunk)
}

func (c *grpcV2Client) ExecuteStreamWithOp(ctx context.Context, opID string, spec TargetSpec, raw string, maxRows int, maxBytes int64, onChunk func(ExecuteChunk) error) error {
	streamCtx, cancelStream := context.WithCancel(ctx)
	defer cancelStream()

	stream, err := c.client.Execute(streamCtx, &v2pb.ExecuteRequest{
		OperationId: opID,
		Spec:        targetSpecToV2(spec),
		Raw:         raw,
		MaxRows:     int32(maxRows),
		MaxBytes:    maxBytes,
	})
	if err != nil {
		return err
	}
	for {
		msg, err := stream.Recv()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		if err := onChunk(chunkFromV2(msg)); err != nil {
			return err
		}
	}
}

func (c *grpcV2Client) Cancel(ctx context.Context, opID string) (bool, string, error) {
	resp, err := c.client.Cancel(ctx, &v2pb.CancelRequest{OperationId: opID})
	if err != nil {
		return false, "", err
	}
	return resp.GetCancelled(), resp.GetMessage(), nil
}

func targetSpecToV2(s TargetSpec) *v2pb.TargetSpec {
	return &v2pb.TargetSpec{
		Engine:       s.Engine,
		Host:         s.Host,
		Port:         int32(s.Port),
		DatabaseName: s.DatabaseName,
		Username:     s.Username,
		Password:     s.Password,
		ReadOnly:     s.ReadOnly,
		TlsMode:      s.TLSMode,
		Params:       s.Params,
	}
}

func targetSpecFromV2(p *v2pb.TargetSpec) TargetSpec {
	if p == nil {
		return TargetSpec{}
	}
	return TargetSpec{
		Engine:       p.GetEngine(),
		Host:         p.GetHost(),
		Port:         int(p.GetPort()),
		DatabaseName: p.GetDatabaseName(),
		Username:     p.GetUsername(),
		Password:     p.GetPassword(),
		ReadOnly:     p.GetReadOnly(),
		TLSMode:      p.GetTlsMode(),
		Params:       p.GetParams(),
	}
}

func metadataToV2(m types.DriverMetadata) *v2pb.DriverMetadata {
	return &v2pb.DriverMetadata{
		Id:                m.ID,
		Engine:            m.Engine,
		DisplayName:       m.DisplayName,
		Family:            string(m.Family),
		Tier:              m.Tier,
		Version:           m.Version,
		HostApiVersion:    int32(m.HostAPIVersion),
		Capabilities:      m.Capabilities,
		Verified:          m.Verified,
		VerificationError: m.VerificationErr,
		Labels:            m.Labels,
	}
}

func metadataFromV2(p *v2pb.DriverMetadata) types.DriverMetadata {
	if p == nil {
		return types.DriverMetadata{}
	}
	return types.DriverMetadata{
		ID:              p.GetId(),
		Engine:          p.GetEngine(),
		DisplayName:     p.GetDisplayName(),
		Family:          types.EngineFamily(p.GetFamily()),
		Tier:            p.GetTier(),
		Version:         p.GetVersion(),
		HostAPIVersion:  int(p.GetHostApiVersion()),
		Capabilities:    p.GetCapabilities(),
		Verified:        p.GetVerified(),
		VerificationErr: p.GetVerificationError(),
		Labels:          p.GetLabels(),
	}
}

func capabilitiesToV2(c *types.ServerCapabilities) *v2pb.ServerCapabilities {
	if c == nil {
		return nil
	}
	return &v2pb.ServerCapabilities{
		Engine:                   c.Engine,
		Dialect:                  c.Dialect,
		ServerVersion:            c.ServerVersion,
		MajorVersion:             int32(c.MajorVersion),
		MinorVersion:             int32(c.MinorVersion),
		ExplainFormat:            c.ExplainFormat,
		SupportsExplain:          c.SupportsExplain,
		SupportsExplainJson:      c.SupportsExplainJSON,
		SupportsReadOnlySession:  c.SupportsReadOnlySession,
		SupportsCancelQuery:      c.SupportsCancelQuery,
		SupportsReturning:        c.SupportsReturning,
		SupportsResp3:            c.SupportsRESP3,
		ClusterMode:              c.ClusterMode,
		SupportsAuthorizedDbList: c.SupportsAuthorizedDBList,
		DetectedAtUtc:            c.DetectedAtUTC,
	}
}

func capabilitiesFromV2(p *v2pb.ServerCapabilities) *types.ServerCapabilities {
	if p == nil {
		return nil
	}
	return &types.ServerCapabilities{
		Engine:                   p.GetEngine(),
		Dialect:                  p.GetDialect(),
		ServerVersion:            p.GetServerVersion(),
		MajorVersion:             int(p.GetMajorVersion()),
		MinorVersion:             int(p.GetMinorVersion()),
		ExplainFormat:            p.GetExplainFormat(),
		SupportsExplain:          p.GetSupportsExplain(),
		SupportsExplainJSON:      p.GetSupportsExplainJson(),
		SupportsReadOnlySession:  p.GetSupportsReadOnlySession(),
		SupportsCancelQuery:      p.GetSupportsCancelQuery(),
		SupportsReturning:        p.GetSupportsReturning(),
		SupportsRESP3:            p.GetSupportsResp3(),
		ClusterMode:              p.GetClusterMode(),
		SupportsAuthorizedDBList: p.GetSupportsAuthorizedDbList(),
		DetectedAtUTC:            p.GetDetectedAtUtc(),
	}
}

func pingResultToV2(r types.PingResult) *v2pb.PingResult {
	return &v2pb.PingResult{
		TargetRef:     r.TargetRef,
		InstanceId:    r.InstanceID,
		Engine:        r.Engine,
		Dialect:       r.Dialect,
		Role:          r.Role,
		Reachable:     r.Reachable,
		ServerVersion: r.ServerVersion,
		Capabilities:  capabilitiesToV2(r.Capabilities),
		LatencyMs:     r.LatencyMs,
		Error:         r.Error,
	}
}

func pingResultFromV2(p *v2pb.PingResult) types.PingResult {
	if p == nil {
		return types.PingResult{}
	}
	return types.PingResult{
		TargetRef:     p.GetTargetRef(),
		InstanceID:    p.GetInstanceId(),
		Engine:        p.GetEngine(),
		Dialect:       p.GetDialect(),
		Role:          p.GetRole(),
		Reachable:     p.GetReachable(),
		ServerVersion: p.GetServerVersion(),
		Capabilities:  capabilitiesFromV2(p.GetCapabilities()),
		LatencyMs:     p.GetLatencyMs(),
		Error:         p.GetError(),
	}
}

func classificationToV2(c types.Classification) *v2pb.Classification {
	stmts := make([]*v2pb.StatementSummary, 0, len(c.Statements))
	for _, s := range c.Statements {
		stmts = append(stmts, &v2pb.StatementSummary{
			StatementType: s.StatementType,
			RiskLevel:     string(s.RiskLevel),
			Flags:         s.Flags,
			Snippet:       s.Snippet,
		})
	}
	return &v2pb.Classification{
		Engine:         c.Engine,
		Family:         string(c.Family),
		RiskLevel:      string(c.RiskLevel),
		IsReadOnly:     c.IsReadOnly,
		StatementCount: int32(c.StatementCount),
		Statements:     stmts,
		RiskFlags:      c.RiskFlags,
		Summary:        c.Summary,
	}
}

func classificationFromV2(p *v2pb.Classification) types.Classification {
	if p == nil {
		return types.Classification{}
	}
	stmts := make([]types.StatementSummary, 0, len(p.GetStatements()))
	for _, s := range p.GetStatements() {
		stmts = append(stmts, types.StatementSummary{
			StatementType: s.GetStatementType(),
			RiskLevel:     types.RiskLevel(s.GetRiskLevel()),
			Flags:         s.GetFlags(),
			Snippet:       s.GetSnippet(),
		})
	}
	return types.Classification{
		Engine:         p.GetEngine(),
		Family:         types.EngineFamily(p.GetFamily()),
		RiskLevel:      types.RiskLevel(p.GetRiskLevel()),
		IsReadOnly:     p.GetIsReadOnly(),
		StatementCount: int(p.GetStatementCount()),
		Statements:     stmts,
		RiskFlags:      p.GetRiskFlags(),
		Summary:        p.GetSummary(),
	}
}

func preflightToV2(r *types.PreflightReport) *v2pb.PreflightReport {
	if r == nil {
		return &v2pb.PreflightReport{}
	}
	var rawJSON []byte
	if r.PlanRaw != nil {
		rawJSON, _ = json.Marshal(r.PlanRaw)
	}
	return &v2pb.PreflightReport{
		Supported:     r.Supported,
		Executed:      r.Executed,
		FullScan:      r.FullScan,
		EstimatedRows: r.EstimatedRows,
		Format:        r.Format,
		PlanSummary:   r.PlanSummary,
		PlanRawJson:   rawJSON,
		Warnings:      r.Warnings,
	}
}

func preflightFromV2(p *v2pb.PreflightReport) *types.PreflightReport {
	if p == nil {
		return &types.PreflightReport{}
	}
	var raw any
	if len(p.GetPlanRawJson()) > 0 {
		_ = json.Unmarshal(p.GetPlanRawJson(), &raw)
	}
	return &types.PreflightReport{
		Supported:     p.GetSupported(),
		Executed:      p.GetExecuted(),
		FullScan:      p.GetFullScan(),
		EstimatedRows: p.GetEstimatedRows(),
		Format:        p.GetFormat(),
		PlanSummary:   p.GetPlanSummary(),
		PlanRaw:       raw,
		Warnings:      p.GetWarnings(),
	}
}

func chunkToV2(ch ExecuteChunk) *v2pb.ExecuteChunk {
	cols := make([]*v2pb.Column, 0, len(ch.Columns))
	for _, c := range ch.Columns {
		cols = append(cols, &v2pb.Column{Name: c.Name, TypeName: c.TypeName})
	}
	rows := make([]*v2pb.Row, 0, len(ch.Rows))
	for _, row := range ch.Rows {
		vals := make([]*v2pb.TypedValue, 0, len(row))
		for _, cell := range row {
			vals = append(vals, goToTypedValue(cell))
		}
		rows = append(rows, &v2pb.Row{Values: vals})
	}
	docs := make([]*v2pb.TypedValue, 0, len(ch.Documents))
	for _, doc := range ch.Documents {
		docs = append(docs, goToTypedValue(doc))
	}
	var kv *v2pb.TypedValue
	if ch.KVResult != nil {
		kv = goToTypedValue(ch.KVResult)
	}
	return &v2pb.ExecuteChunk{
		Kind:         ch.Kind,
		Family:       ch.Family,
		Columns:      cols,
		Rows:         rows,
		Documents:    docs,
		KvResult:     kv,
		RawText:      ch.RawText,
		AffectedRows: ch.AffectedRows,
		FetchedRows:  int32(ch.FetchedRows),
		Truncated:    ch.Truncated,
		CutoffReason: ch.CutoffReason,
		Messages:     ch.Messages,
		LatencyMs:    ch.LatencyMs,
		Error:        ch.Error,
	}
}

func chunkFromV2(p *v2pb.ExecuteChunk) ExecuteChunk {
	if p == nil {
		return ExecuteChunk{}
	}
	cols := make([]types.Column, 0, len(p.GetColumns()))
	for _, c := range p.GetColumns() {
		cols = append(cols, types.Column{Name: c.GetName(), TypeName: c.GetTypeName()})
	}
	rows := make([][]any, 0, len(p.GetRows()))
	for _, r := range p.GetRows() {
		cells := make([]any, 0, len(r.GetValues()))
		for _, v := range r.GetValues() {
			cells = append(cells, typedValueToGo(v))
		}
		rows = append(rows, cells)
	}
	docs := make([]any, 0, len(p.GetDocuments()))
	for _, d := range p.GetDocuments() {
		docs = append(docs, typedValueToGo(d))
	}
	var kv any
	if p.GetKvResult() != nil {
		kv = typedValueToGo(p.GetKvResult())
	}
	return ExecuteChunk{
		Kind:         p.GetKind(),
		Family:       p.GetFamily(),
		Columns:      cols,
		Rows:         rows,
		Documents:    docs,
		KVResult:     kv,
		RawText:      p.GetRawText(),
		AffectedRows: p.AffectedRows,
		FetchedRows:  int(p.GetFetchedRows()),
		Truncated:    p.GetTruncated(),
		CutoffReason: p.GetCutoffReason(),
		Messages:     p.GetMessages(),
		LatencyMs:    p.GetLatencyMs(),
		Error:        p.GetError(),
	}
}

func goToTypedValue(v any) *v2pb.TypedValue {
	switch x := v.(type) {
	case nil:
		return &v2pb.TypedValue{Kind: &v2pb.TypedValue_NullValue{NullValue: true}}
	case bool:
		return &v2pb.TypedValue{Kind: &v2pb.TypedValue_BoolValue{BoolValue: x}}
	case int:
		return &v2pb.TypedValue{Kind: &v2pb.TypedValue_Int64Value{Int64Value: int64(x)}}
	case int8:
		return &v2pb.TypedValue{Kind: &v2pb.TypedValue_Int64Value{Int64Value: int64(x)}}
	case int16:
		return &v2pb.TypedValue{Kind: &v2pb.TypedValue_Int64Value{Int64Value: int64(x)}}
	case int32:
		return &v2pb.TypedValue{Kind: &v2pb.TypedValue_Int64Value{Int64Value: int64(x)}}
	case int64:
		return &v2pb.TypedValue{Kind: &v2pb.TypedValue_Int64Value{Int64Value: x}}
	case uint:
		return &v2pb.TypedValue{Kind: &v2pb.TypedValue_Uint64Value{Uint64Value: uint64(x)}}
	case uint8:
		return &v2pb.TypedValue{Kind: &v2pb.TypedValue_Uint64Value{Uint64Value: uint64(x)}}
	case uint16:
		return &v2pb.TypedValue{Kind: &v2pb.TypedValue_Uint64Value{Uint64Value: uint64(x)}}
	case uint32:
		return &v2pb.TypedValue{Kind: &v2pb.TypedValue_Uint64Value{Uint64Value: uint64(x)}}
	case uint64:
		return &v2pb.TypedValue{Kind: &v2pb.TypedValue_Uint64Value{Uint64Value: x}}
	case float32:
		return floatToTypedValue(float64(x))
	case float64:
		return floatToTypedValue(x)
	case json.Number:
		if i, err := x.Int64(); err == nil {
			return &v2pb.TypedValue{Kind: &v2pb.TypedValue_Int64Value{Int64Value: i}}
		}
		if f, err := x.Float64(); err == nil {
			return floatToTypedValue(f)
		}
		return &v2pb.TypedValue{Kind: &v2pb.TypedValue_StringValue{StringValue: x.String()}}
	case string:
		return &v2pb.TypedValue{Kind: &v2pb.TypedValue_StringValue{StringValue: x}}
	case []byte:
		return &v2pb.TypedValue{Kind: &v2pb.TypedValue_BytesValue{BytesValue: append([]byte(nil), x...)}}
	case time.Time:
		return &v2pb.TypedValue{Kind: &v2pb.TypedValue_StringValue{StringValue: x.UTC().Format(time.RFC3339Nano)}}
	case []any:
		vals := make([]*v2pb.TypedValue, 0, len(x))
		for _, item := range x {
			vals = append(vals, goToTypedValue(item))
		}
		return &v2pb.TypedValue{Kind: &v2pb.TypedValue_ListValue{ListValue: &v2pb.ListValue{Values: vals}}}
	case []string:
		vals := make([]*v2pb.TypedValue, 0, len(x))
		for _, item := range x {
			vals = append(vals, goToTypedValue(item))
		}
		return &v2pb.TypedValue{Kind: &v2pb.TypedValue_ListValue{ListValue: &v2pb.ListValue{Values: vals}}}
	case map[string]any:
		fields := make(map[string]*v2pb.TypedValue, len(x))
		for k, val := range x {
			fields[k] = goToTypedValue(val)
		}
		return &v2pb.TypedValue{Kind: &v2pb.TypedValue_StructValue{StructValue: &v2pb.StructValue{Fields: fields}}}
	default:
		if b, err := json.Marshal(x); err == nil {
			return &v2pb.TypedValue{Kind: &v2pb.TypedValue_JsonValue{JsonValue: b}}
		}
		return &v2pb.TypedValue{Kind: &v2pb.TypedValue_StringValue{StringValue: fmt.Sprint(x)}}
	}
}

func floatToTypedValue(f float64) *v2pb.TypedValue {
	if math.IsNaN(f) {
		return &v2pb.TypedValue{Kind: &v2pb.TypedValue_StringValue{StringValue: "NaN"}}
	}
	if math.IsInf(f, 1) {
		return &v2pb.TypedValue{Kind: &v2pb.TypedValue_StringValue{StringValue: "Infinity"}}
	}
	if math.IsInf(f, -1) {
		return &v2pb.TypedValue{Kind: &v2pb.TypedValue_StringValue{StringValue: "-Infinity"}}
	}
	return &v2pb.TypedValue{Kind: &v2pb.TypedValue_Float64Value{Float64Value: f}}
}

func typedValueToGo(tv *v2pb.TypedValue) any {
	if tv == nil {
		return nil
	}
	switch k := tv.Kind.(type) {
	case *v2pb.TypedValue_NullValue:
		return nil
	case *v2pb.TypedValue_BoolValue:
		return k.BoolValue
	case *v2pb.TypedValue_Int64Value:
		return k.Int64Value
	case *v2pb.TypedValue_Uint64Value:
		return k.Uint64Value
	case *v2pb.TypedValue_Float64Value:
		return k.Float64Value
	case *v2pb.TypedValue_StringValue:
		return k.StringValue
	case *v2pb.TypedValue_BytesValue:
		return append([]byte(nil), k.BytesValue...)
	case *v2pb.TypedValue_ListValue:
		if k.ListValue == nil {
			return []any(nil)
		}
		out := make([]any, 0, len(k.ListValue.Values))
		for _, item := range k.ListValue.Values {
			out = append(out, typedValueToGo(item))
		}
		return out
	case *v2pb.TypedValue_StructValue:
		if k.StructValue == nil {
			return map[string]any(nil)
		}
		out := make(map[string]any, len(k.StructValue.Fields))
		for fk, fv := range k.StructValue.Fields {
			out[fk] = typedValueToGo(fv)
		}
		return out
	case *v2pb.TypedValue_JsonValue:
		var out any
		if err := json.Unmarshal(k.JsonValue, &out); err == nil {
			return out
		}
		return string(k.JsonValue)
	default:
		return nil
	}
}
