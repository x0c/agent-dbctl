package plugin

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-plugin"

	"github.com/x0c/agent-dbctl/internal/driver"
	"github.com/x0c/agent-dbctl/internal/types"
)

var errStopStream = errors.New("stop stream")

// Manager discovers, verifies, and hosts external gRPC driver plugin subprocesses.
type Manager struct {
	pluginsDir string
	registry   *driver.Registry

	mu         sync.Mutex
	discovered []DiscoveredPlugin
	clients    map[string]*hostedPlugin
	startLocks map[string]*sync.Mutex
}

type hostedPlugin struct {
	info            DiscoveredPlugin
	client          *plugin.Client
	svc             Service
	protocolVersion int
}

// NewManager creates a Tier-3 plugin manager backed by pluginsDir.
func NewManager(pluginsDir string, registry *driver.Registry) *Manager {
	return &Manager{
		pluginsDir: pluginsDir,
		registry:   registry,
		clients:    make(map[string]*hostedPlugin),
		startLocks: make(map[string]*sync.Mutex),
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

func (m *Manager) lockForPlugin(id string) *sync.Mutex {
	m.mu.Lock()
	defer m.mu.Unlock()
	lk, ok := m.startLocks[id]
	if !ok {
		lk = &sync.Mutex{}
		m.startLocks[id] = lk
	}
	return lk
}

func (m *Manager) getOrStart(info DiscoveredPlugin) (Service, int, error) {
	m.mu.Lock()
	if hp, ok := m.clients[info.Manifest.ID]; ok && !hp.client.Exited() {
		m.mu.Unlock()
		return hp.svc, hp.protocolVersion, nil
	}
	m.mu.Unlock()

	// Serialize startup per plugin ID without blocking other plugins or ListDiscovered.
	startMu := m.lockForPlugin(info.Manifest.ID)
	startMu.Lock()
	defer startMu.Unlock()

	m.mu.Lock()
	if hp, ok := m.clients[info.Manifest.ID]; ok && !hp.client.Exited() {
		m.mu.Unlock()
		return hp.svc, hp.protocolVersion, nil
	}
	if old, ok := m.clients[info.Manifest.ID]; ok {
		old.client.Kill()
		delete(m.clients, info.Manifest.ID)
	}
	m.mu.Unlock()

	// Re-verify SHA-256 right before spawning to prevent TOCTOU tampering.
	rechecked := verifyOnePlugin(info.Dir, filepath.Join(info.Dir, "manifest.json"))
	if !rechecked.Verified {
		return nil, 0, fmt.Errorf("plugin %s verification failed: %s", info.Manifest.ID, rechecked.VerificationErr)
	}

	var pImpl plugin.Plugin
	switch rechecked.Manifest.HostAPIVersion {
	case 1:
		pImpl = &GRPCPlugin{}
	case 2:
		pImpl = &GRPCPluginV2{}
	default:
		return nil, 0, fmt.Errorf("unsupported host_api_version %d", rechecked.Manifest.HostAPIVersion)
	}

	client := plugin.NewClient(&plugin.ClientConfig{
		HandshakeConfig: VersionedHandshake,
		VersionedPlugins: map[int]plugin.PluginSet{
			rechecked.Manifest.HostAPIVersion: {PluginMapKey: pImpl},
		},
		Cmd:              exec.Command(rechecked.BinaryPath), //nolint:gosec // Verified SHA-256 against manifest.json.
		AllowedProtocols: []plugin.Protocol{plugin.ProtocolGRPC},
		AutoMTLS:         true,
		Logger:           hclog.NewNullLogger(),
	})
	rpcClient, err := client.Client()
	if err != nil {
		client.Kill()
		return nil, 0, fmt.Errorf("start plugin %s: %w", info.Manifest.ID, err)
	}
	negotiated := client.NegotiatedVersion()
	if negotiated != rechecked.Manifest.HostAPIVersion {
		client.Kill()
		return nil, 0, fmt.Errorf("plugin %s negotiated protocol v%d, want v%d", info.Manifest.ID, negotiated, rechecked.Manifest.HostAPIVersion)
	}
	raw, err := rpcClient.Dispense(PluginMapKey)
	if err != nil {
		client.Kill()
		return nil, 0, fmt.Errorf("dispense plugin %s: %w", info.Manifest.ID, err)
	}
	svc, ok := raw.(Service)
	if !ok {
		client.Kill()
		return nil, 0, fmt.Errorf("plugin %s returned unexpected RPC type", info.Manifest.ID)
	}

	m.mu.Lock()
	m.clients[info.Manifest.ID] = &hostedPlugin{
		info:            rechecked,
		client:          client,
		svc:             svc,
		protocolVersion: negotiated,
	}
	m.mu.Unlock()
	return svc, negotiated, nil
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
	svc, _, err := p.manager.getOrStart(p.info)
	if err != nil {
		return types.Classification{}, err
	}
	return svc.Classify(ctx, raw)
}

func (p *pluginDriverAdapter) Open(ctx context.Context, cfg driver.ConnectionConfig) (driver.Conn, error) {
	svc, protoVer, err := p.manager.getOrStart(p.info)
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
		TLSMode:      cfg.TLSMode,
		Params:       cfg.Params,
	}

	var bridgeClose func() error
	if cfg.NeedsDialBridge && cfg.DialContext != nil && cfg.Host != "" && cfg.Port > 0 {
		targetAddr := net.JoinHostPort(cfg.Host, strconv.Itoa(cfg.Port))
		host, port, closeBridge, err := startDialBridge(ctx, cfg.DialContext, targetAddr)
		if err != nil {
			return nil, fmt.Errorf("start plugin dial bridge: %w", err)
		}
		spec.Host = host
		spec.Port = port
		bridgeClose = closeBridge
	}

	combinedClose := driver.CloseOnce(func() error {
		var firstErr error
		if bridgeClose != nil {
			firstErr = bridgeClose()
		}
		if cfg.CloseHook != nil {
			if err := cfg.CloseHook(); err != nil && firstErr == nil {
				firstErr = err
			}
		}
		return firstErr
	})

	capSet := make(map[string]struct{}, len(p.info.Manifest.Capabilities))
	for _, capName := range p.info.Manifest.Capabilities {
		if norm := strings.ToLower(strings.TrimSpace(capName)); norm != "" {
			capSet[norm] = struct{}{}
		}
	}

	return &pluginConn{
		svc:             svc,
		spec:            spec,
		closeHook:       combinedClose,
		protocolVersion: protoVer,
		capabilities:    capSet,
	}, nil
}

func startDialBridge(parentCtx context.Context, dialFn func(context.Context, string, string) (net.Conn, error), targetAddr string) (string, int, func() error, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", 0, nil, err
	}
	tcpAddr, ok := ln.Addr().(*net.TCPAddr)
	if !ok {
		_ = ln.Close()
		return "", 0, nil, fmt.Errorf("unexpected listener address type %T", ln.Addr())
	}

	bridgeCtx, cancel := context.WithCancel(context.Background())
	go func() {
		defer cancel()
		for {
			localConn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(lc net.Conn) {
				defer func() { _ = lc.Close() }()
				dialCtx, dialCancel := context.WithTimeout(bridgeCtx, 15*time.Second)
				if dl, ok := parentCtx.Deadline(); ok && time.Until(dl) < 15*time.Second && time.Until(dl) > 0 {
					dialCtx, dialCancel = context.WithDeadline(bridgeCtx, dl)
				}
				remoteConn, err := dialFn(dialCtx, "tcp", targetAddr)
				dialCancel()
				if err != nil {
					return
				}
				defer func() { _ = remoteConn.Close() }()

				done := make(chan struct{}, 2)
				go func() {
					_, _ = io.Copy(remoteConn, lc)
					done <- struct{}{}
				}()
				go func() {
					_, _ = io.Copy(lc, remoteConn)
					done <- struct{}{}
				}()
				select {
				case <-done:
				case <-bridgeCtx.Done():
				}
			}(localConn)
		}
	}()

	closeFn := func() error {
		cancel()
		return ln.Close()
	}
	return "127.0.0.1", tcpAddr.Port, closeFn, nil
}

type pluginConn struct {
	svc             Service
	spec            TargetSpec
	closeHook       func() error
	protocolVersion int
	capabilities    map[string]struct{}

	opSeq      atomic.Uint64
	opMu       sync.Mutex
	activeOpID string
	cancelExec context.CancelFunc
}

func (c *pluginConn) hasCapability(name string) bool {
	if len(c.capabilities) == 0 && c.protocolVersion <= 1 {
		return true
	}
	_, ok := c.capabilities[strings.ToLower(strings.TrimSpace(name))]
	return ok
}

func (c *pluginConn) Ping(ctx context.Context) (types.PingResult, error) {
	return c.svc.Ping(ctx, c.spec)
}

func (c *pluginConn) ListDatabases(ctx context.Context) ([]string, error) {
	if !c.hasCapability("list_databases") {
		return nil, fmt.Errorf("plugin %q does not declare list_databases capability", c.spec.Engine)
	}
	return c.svc.ListDatabases(ctx, c.spec)
}

func (c *pluginConn) Preflight(ctx context.Context, raw string, _ driver.PreflightOpts) (*types.PreflightReport, error) {
	if !c.hasCapability("preflight") {
		return &types.PreflightReport{
			Supported: false,
			Executed:  false,
			Warnings:  []string{fmt.Sprintf("plugin %q does not declare preflight capability", c.spec.Engine)},
		}, nil
	}
	return c.svc.Preflight(ctx, c.spec, raw)
}

func (c *pluginConn) Execute(ctx context.Context, raw string, opts driver.ExecOpts) (*types.ExecResult, error) {
	start := time.Now()
	res := &types.ExecResult{Family: types.FamilySQL}
	buf := driver.RowBuffer{MaxRows: opts.MaxRows, MaxBytes: opts.MaxBytes}

	var pluginFetched int
	var pluginTruncated bool
	var pluginCutoff string

	onChunk := func(chunk ExecuteChunk) error {
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
			} else if buf.Truncated {
				return errStopStream
			}
		}
		for _, doc := range chunk.Documents {
			if buf.TryAcceptRow(doc) {
				res.Documents = append(res.Documents, doc)
			} else if buf.Truncated {
				return errStopStream
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
		if chunk.FetchedRows > pluginFetched {
			pluginFetched = chunk.FetchedRows
		}
		if chunk.Truncated {
			pluginTruncated = true
			if chunk.CutoffReason != "" {
				pluginCutoff = chunk.CutoffReason
			}
		}
		if len(chunk.Messages) > 0 {
			res.Messages = append(res.Messages, chunk.Messages...)
		}
		return nil
	}

	var err error
	if cs, ok := c.svc.(CancelableService); ok {
		opID := fmt.Sprintf("plugop_%d_%d", time.Now().UnixNano(), c.opSeq.Add(1))
		execCtx, cancelExec := context.WithCancel(ctx)
		c.opMu.Lock()
		c.activeOpID = opID
		c.cancelExec = cancelExec
		c.opMu.Unlock()

		defer func() {
			cancelExec()
			c.opMu.Lock()
			if c.activeOpID == opID {
				c.activeOpID = ""
				c.cancelExec = nil
			}
			c.opMu.Unlock()
		}()

		err = cs.ExecuteStreamWithOp(execCtx, opID, c.spec, raw, opts.MaxRows, opts.MaxBytes, onChunk)
	} else {
		err = c.svc.ExecuteStream(ctx, c.spec, raw, opts.MaxRows, opts.MaxBytes, onChunk)
	}
	if err != nil && !errors.Is(err, errStopStream) {
		return nil, err
	}
	res.FetchedRows = buf.FetchedRows
	if pluginFetched > res.FetchedRows {
		res.FetchedRows = pluginFetched
	}
	res.ReturnedRows = len(res.Rows) + len(res.Documents)
	if res.Family == types.FamilyKV && res.KVResult != nil && res.ReturnedRows == 0 {
		res.ReturnedRows = 1
	}
	res.ReturnedBytes = buf.ReturnedBytes
	res.Truncated = buf.Truncated || pluginTruncated
	if buf.Truncated {
		res.CutoffReason = buf.CutoffReason
	} else if pluginTruncated {
		res.CutoffReason = pluginCutoff
	}
	res.LatencyMs = time.Since(start).Milliseconds()
	return res, nil
}

func (c *pluginConn) CancelAndDiscard() error {
	c.opMu.Lock()
	opID := c.activeOpID
	cancelExec := c.cancelExec
	c.opMu.Unlock()

	if opID != "" && c.hasCapability("cancel") {
		if cs, ok := c.svc.(CancelableService); ok {
			cancelCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			_, _, _ = cs.Cancel(cancelCtx, opID)
			cancel()
		}
	}
	if cancelExec != nil {
		cancelExec()
	}
	return c.Close()
}

func (c *pluginConn) Close() error {
	if c.closeHook != nil {
		return c.closeHook()
	}
	return nil
}
