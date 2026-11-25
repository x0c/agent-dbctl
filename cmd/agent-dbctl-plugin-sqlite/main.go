package main

import (
	"context"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-plugin"

	"github.com/x0c/agent-dbctl/internal/driver"
	"github.com/x0c/agent-dbctl/internal/driver/builtin"
	drvplugin "github.com/x0c/agent-dbctl/internal/driver/plugin"
	"github.com/x0c/agent-dbctl/internal/secrets"
	"github.com/x0c/agent-dbctl/internal/types"
)

// sqliteExtService implements the Tier-3 gRPC DriverPlugin contract over SQLite.
type sqliteExtService struct {
	inner builtin.SQLiteDriver
}

func (s *sqliteExtService) Metadata(_ context.Context) (types.DriverMetadata, error) {
	return types.DriverMetadata{
		ID:             "custom-sqlite",
		Engine:         "sqlite-ext",
		DisplayName:    "SQLite External Plugin",
		Family:         types.FamilySQL,
		Tier:           "plugin",
		Version:        "0.1.0",
		HostAPIVersion: drvplugin.SupportedHostAPIVersion,
		Capabilities:   []string{"ping", "list_databases", "preflight", "execute_stream"},
		Verified:       true,
	}, nil
}

func (s *sqliteExtService) openConn(ctx context.Context, spec drvplugin.TargetSpec) (driver.Conn, error) {
	return s.inner.Open(ctx, driver.ConnectionConfig{
		Engine:       spec.Engine,
		Host:         spec.Host,
		Port:         spec.Port,
		DatabaseName: spec.DatabaseName,
		ReadOnly:     spec.ReadOnly,
		Params:       spec.Params,
		Credential: secrets.ResolvedSecret{
			Username: spec.Username,
			Secret:   spec.Password,
		},
	})
}

func (s *sqliteExtService) Ping(ctx context.Context, spec drvplugin.TargetSpec) (types.PingResult, error) {
	c, err := s.openConn(ctx, spec)
	if err != nil {
		return types.PingResult{Engine: spec.Engine, Reachable: false, Error: err.Error()}, err
	}
	defer func() { _ = c.Close() }()
	res, err := c.Ping(ctx)
	res.Engine = spec.Engine
	return res, err
}

func (s *sqliteExtService) ListDatabases(ctx context.Context, spec drvplugin.TargetSpec) ([]string, error) {
	c, err := s.openConn(ctx, spec)
	if err != nil {
		return nil, err
	}
	defer func() { _ = c.Close() }()
	return c.ListDatabases(ctx)
}

func (s *sqliteExtService) Classify(ctx context.Context, raw string) (types.Classification, error) {
	cls, err := s.inner.Classify(ctx, raw)
	cls.Engine = "sqlite-ext"
	return cls, err
}

func (s *sqliteExtService) Preflight(ctx context.Context, spec drvplugin.TargetSpec, raw string) (*types.PreflightReport, error) {
	c, err := s.openConn(ctx, spec)
	if err != nil {
		return nil, err
	}
	defer func() { _ = c.Close() }()
	return c.Preflight(ctx, raw, driver.PreflightOpts{})
}

func (s *sqliteExtService) ExecuteStream(ctx context.Context, spec drvplugin.TargetSpec, raw string, maxRows int, maxBytes int64, onChunk func(drvplugin.ExecuteChunk) error) error {
	start := time.Now()
	c, err := s.openConn(ctx, spec)
	if err != nil {
		return err
	}
	defer func() { _ = c.Close() }()

	res, err := c.Execute(ctx, raw, driver.ExecOpts{MaxRows: maxRows, MaxBytes: maxBytes})
	if err != nil {
		return onChunk(drvplugin.ExecuteChunk{Kind: "summary", Error: err.Error()})
	}
	if err := onChunk(drvplugin.ExecuteChunk{
		Kind:    "header",
		Family:  string(res.Family),
		Columns: res.Columns,
	}); err != nil {
		return err
	}
	// Stream rows in small batches to validate streaming behavior end-to-end.
	const batchSize = 50
	for i := 0; i < len(res.Rows); i += batchSize {
		end := i + batchSize
		if end > len(res.Rows) {
			end = len(res.Rows)
		}
		if err := onChunk(drvplugin.ExecuteChunk{
			Kind: "row",
			Rows: res.Rows[i:end],
		}); err != nil {
			return err
		}
	}
	return onChunk(drvplugin.ExecuteChunk{
		Kind:         "summary",
		Family:       string(res.Family),
		AffectedRows: res.AffectedRows,
		Messages:     res.Messages,
		LatencyMs:    time.Since(start).Milliseconds(),
	})
}

func main() {
	plugin.Serve(&plugin.ServeConfig{
		HandshakeConfig: drvplugin.Handshake,
		Plugins: map[string]plugin.Plugin{
			drvplugin.PluginMapKey: &drvplugin.GRPCPlugin{Impl: &sqliteExtService{}},
		},
		GRPCServer: plugin.DefaultGRPCServer,
		Logger:     hclog.NewNullLogger(),
	})
}
