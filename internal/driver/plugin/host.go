package plugin

import (
	"context"
	"fmt"
	"os/exec"
	"sync"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-plugin"

	"github.com/x0c/agent-dbctl/internal/driver"
	"github.com/x0c/agent-dbctl/internal/types"
)

// Manager discovers, verifies, and hosts external gRPC driver plugin subprocesses.
type Manager struct {
	pluginsDir string
	registry   *driver.Registry

	mu         sync.Mutex
	discovered []DiscoveredPlugin
	clients    map[string]*hostedPlugin
}

type hostedPlugin struct {
	info   DiscoveredPlugin
	client *plugin.Client
	svc    Service
}

// NewManager creates a Tier-3 plugin manager backed by pluginsDir.
func NewManager(pluginsDir string, registry *driver.Registry) *Manager {
	return &Manager{
		pluginsDir: pluginsDir,
		registry:   registry,
		clients:    make(map[string]*hostedPlugin),
	}
}

// Reload scans pluginsDir, verifies manifests/hashes, and registers valid plugin drivers.
func (m *Manager) Reload() ([]DiscoveredPlugin, error) {
	items, err := ScanPlugins(m.pluginsDir)
	if err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, hp := range m.clients {
		hp.client.Kill()
	}
	m.clients = make(map[string]*hostedPlugin)
	m.registry.ClearTier("plugin")
	m.discovered = items

	for _, item := range items {
		if !item.Verified {
			continue
		}
		m.registry.Register(&pluginDriverAdapter{manager: m, info: item})
	}
	return append([]DiscoveredPlugin(nil), items...), nil
}

// ListDiscovered returns all scanned plugins including failed verifications.
func (m *Manager) ListDiscovered() []DiscoveredPlugin {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]DiscoveredPlugin(nil), m.discovered...)
}

// Shutdown terminates all running plugin subprocesses cleanly.
func (m *Manager) Shutdown() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, hp := range m.clients {
		hp.client.Kill()
	}
	m.clients = make(map[string]*hostedPlugin)
}

func (m *Manager) getOrStart(info DiscoveredPlugin) (Service, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if hp, ok := m.clients[info.Manifest.ID]; ok && !hp.client.Exited() {
		return hp.svc, nil
	}
	if old, ok := m.clients[info.Manifest.ID]; ok {
		old.client.Kill()
		delete(m.clients, info.Manifest.ID)
	}

	// Re-verify SHA-256 right before spawning to prevent TOCTOU tampering.
	rechecked := verifyOnePlugin(info.Dir, info.Dir+"/manifest.json")
	if !rechecked.Verified {
		return nil, fmt.Errorf("plugin %s verification failed: %s", info.Manifest.ID, rechecked.VerificationErr)
	}

	client := plugin.NewClient(&plugin.ClientConfig{
		HandshakeConfig:  Handshake,
		Plugins:          map[string]plugin.Plugin{PluginMapKey: &GRPCPlugin{}},
		Cmd:              exec.Command(rechecked.BinaryPath), //nolint:gosec // Verified SHA-256 against manifest.json.
		AllowedProtocols: []plugin.Protocol{plugin.ProtocolGRPC},
		AutoMTLS:         true,
		Logger:           hclog.NewNullLogger(),
	})
	rpcClient, err := client.Client()
	if err != nil {
		client.Kill()
		return nil, fmt.Errorf("start plugin %s: %w", info.Manifest.ID, err)
	}
	raw, err := rpcClient.Dispense(PluginMapKey)
	if err != nil {
		client.Kill()
		return nil, fmt.Errorf("dispense plugin %s: %w", info.Manifest.ID, err)
	}
	svc, ok := raw.(Service)
	if !ok {
		client.Kill()
		return nil, fmt.Errorf("plugin %s returned unexpected RPC type", info.Manifest.ID)
	}
	m.clients[info.Manifest.ID] = &hostedPlugin{info: rechecked, client: client, svc: svc}
	return svc, nil
}

type pluginDriverAdapter struct {
	manager *Manager
	info    DiscoveredPlugin
}

func (p *pluginDriverAdapter) Metadata() types.DriverMetadata {
	return types.DriverMetadata{
		ID:              p.info.Manifest.ID,
		Engine:          p.info.Manifest.Engine,
		DisplayName:     p.info.Manifest.DisplayName,
		Family:          p.info.Manifest.Family,
		Tier:            "plugin",
		Version:         p.info.Manifest.Version,
		HostAPIVersion:  p.info.Manifest.HostAPIVersion,
		Capabilities:    p.info.Manifest.Capabilities,
		Verified:        p.info.Verified,
		VerificationErr: p.info.VerificationErr,
	}
}

func (p *pluginDriverAdapter) Classify(ctx context.Context, raw string) (types.Classification, error) {
	svc, err := p.manager.getOrStart(p.info)
	if err != nil {
		return types.Classification{}, err
	}
	return svc.Classify(ctx, raw)
}

func (p *pluginDriverAdapter) Open(_ context.Context, cfg driver.ConnectionConfig) (driver.Conn, error) {
	svc, err := p.manager.getOrStart(p.info)
	if err != nil {
		return nil, err
	}
	spec := TargetSpec{
		Engine:       p.info.Manifest.Engine,
		Host:         cfg.Host,
		Port:         cfg.Port,
		DatabaseName: cfg.DatabaseName,
		Username:     cfg.Credential.Username,
		Password:     cfg.Credential.Secret,
		ReadOnly:     cfg.ReadOnly,
		Params:       cfg.Params,
	}
	return &pluginConn{svc: svc, spec: spec, closeHook: cfg.CloseHook}, nil
}

type pluginConn struct {
	svc       Service
	spec      TargetSpec
	closeHook func() error
}

func (c *pluginConn) Ping(ctx context.Context) (types.PingResult, error) {
	return c.svc.Ping(ctx, c.spec)
}

func (c *pluginConn) ListDatabases(ctx context.Context) ([]string, error) {
	return c.svc.ListDatabases(ctx, c.spec)
}

func (c *pluginConn) Preflight(ctx context.Context, raw string, _ driver.PreflightOpts) (*types.PreflightReport, error) {
	return c.svc.Preflight(ctx, c.spec, raw)
}

func (c *pluginConn) Execute(ctx context.Context, raw string, opts driver.ExecOpts) (*types.ExecResult, error) {
	start := time.Now()
	res := &types.ExecResult{Family: types.FamilySQL}
	buf := driver.RowBuffer{MaxRows: opts.MaxRows, MaxBytes: opts.MaxBytes}

	err := c.svc.ExecuteStream(ctx, c.spec, raw, opts.MaxRows, opts.MaxBytes, func(chunk ExecuteChunk) error {
		if chunk.Error != "" {
			return fmt.Errorf("%s", chunk.Error)
		}
		if chunk.Family != "" {
			res.Family = types.EngineFamily(chunk.Family)
		}
		if len(chunk.Columns) > 0 && len(res.Columns) == 0 {
			res.Columns = chunk.Columns
		}
		for _, row := range chunk.Rows {
			if buf.TryAcceptRow(row) {
				res.Rows = append(res.Rows, row)
			}
		}
		for _, doc := range chunk.Documents {
			if buf.TryAcceptRow(doc) {
				res.Documents = append(res.Documents, doc)
			}
		}
		if chunk.KVResult != nil {
			res.KVResult = chunk.KVResult
		}
		if chunk.RawText != "" {
			res.RawText = chunk.RawText
		}
		if chunk.AffectedRows != nil {
			res.AffectedRows = chunk.AffectedRows
		}
		if len(chunk.Messages) > 0 {
			res.Messages = append(res.Messages, chunk.Messages...)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	res.FetchedRows = buf.FetchedRows
	res.ReturnedRows = len(res.Rows) + len(res.Documents)
	if res.Family == types.FamilyKV && res.KVResult != nil && res.ReturnedRows == 0 {
		res.ReturnedRows = 1
	}
	res.ReturnedBytes = buf.ReturnedBytes
	res.Truncated = buf.Truncated
	res.CutoffReason = buf.CutoffReason
	res.LatencyMs = time.Since(start).Milliseconds()
	return res, nil
}

func (c *pluginConn) CancelAndDiscard() error {
	return c.Close()
}

func (c *pluginConn) Close() error {
	if c.closeHook != nil {
		return c.closeHook()
	}
	return nil
}
