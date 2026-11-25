package daemon

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/x0c/agent-dbctl/internal/approval"
	"github.com/x0c/agent-dbctl/internal/audit"
	"github.com/x0c/agent-dbctl/internal/auth"
	"github.com/x0c/agent-dbctl/internal/classify"
	"github.com/x0c/agent-dbctl/internal/config"
	"github.com/x0c/agent-dbctl/internal/driver"
	"github.com/x0c/agent-dbctl/internal/driver/builtin"
	drvplugin "github.com/x0c/agent-dbctl/internal/driver/plugin"
	"github.com/x0c/agent-dbctl/internal/netdial"
	"github.com/x0c/agent-dbctl/internal/policy"
	"github.com/x0c/agent-dbctl/internal/rbac"
	"github.com/x0c/agent-dbctl/internal/secrets"
	"github.com/x0c/agent-dbctl/internal/store"
	"github.com/x0c/agent-dbctl/internal/types"
)

// Identity identifies the running daemon process so CLIs detect stale versions cleanly.
type Identity struct {
	Version       string           `json:"version"`
	Commit        string           `json:"commit"`
	PID           int              `json:"pid,omitempty"`
	Session       string           `json:"session,omitempty"`
	ConfigHome    string           `json:"config_home,omitempty"`
	WebURL        string           `json:"web_url"`
	StartedAt     string           `json:"started_at_utc"`
	Mode          types.ServerMode `json:"mode,omitempty"`
	APIVersion    int              `json:"api_version,omitempty"`
	MinCLIVersion string           `json:"min_cli_version,omitempty"`
	NodeID        string           `json:"node_id,omitempty"`
}

// Event is pushed over SSE to live Web Console subscribers and cross-node Pub/Sub.
type Event struct {
	Type    string          `json:"type"`
	Data    any             `json:"data,omitempty"`
	RawData json.RawMessage `json:"-"`
}

type sseSubscriber struct {
	ch        chan Event
	principal types.Principal
}

// Service owns all local or remote daemon business orchestration.
type Service struct {
	mode         types.ServerMode
	nodeID       string
	serverCfg    *config.ServerConfig
	paths        config.Paths
	store        *store.Store
	secrets      secrets.Store
	drivers      *driver.Registry
	plugins      *drvplugin.Manager
	approvals    *approval.Manager
	localWeb     *approval.LocalWebProvider
	slots        audit.ResultRelay
	bus          EventBus
	tunnels      *netdial.TunnelPool
	connPool     *driver.ConnPool
	dialPolicy   netdial.DialPolicy
	secretPolicy secrets.ServerPolicy
	oidcClient   *auth.OIDCClient
	identity     Identity

	rootCtx    context.Context
	cancelRoot context.CancelFunc
	wgMu       sync.RWMutex
	stopping   bool
	wg         sync.WaitGroup

	opMu      sync.Mutex
	opWaiters map[string]chan types.ExecResponse
	opActive  map[string]context.CancelFunc

	sseMu   sync.Mutex
	sseSubs map[*sseSubscriber]struct{}

	uiSessionToken string
	uiCSRFToken    string
}

// NewService wires up Store, Secrets, Drivers, Plugins, Approvals, TunnelPool, ConnPool, and ResultSlots for local mode.
func NewService(ctx context.Context, paths config.Paths, version, commit string) (*Service, error) {
	st, err := store.Open(ctx, paths.DBPath)
	if err != nil {
		return nil, err
	}
	sec := secrets.NewStore(paths)
	reg := driver.NewRegistry()
	builtin.RegisterAll(reg)

	pm := drvplugin.NewManager(paths.PluginsDir, reg)
	_, _ = pm.Reload()

	slots := audit.NewMemoryResultRelay(10 * time.Minute)
	appMgr := approval.NewManager(st)
	tunnels := netdial.NewTunnelPool(netdial.TunnelPoolConfig{})
	connPool := driver.NewConnPool(driver.ConnPoolConfig{})
	bus := NewMemoryEventBus()

	rootCtx, cancelRoot := context.WithCancel(context.Background())
	svc := &Service{
		mode:      types.ModeLocal,
		nodeID:    "local-" + randomHexToken(4),
		paths:     paths,
		store:     st,
		secrets:   sec,
		drivers:   reg,
		plugins:   pm,
		approvals: appMgr,
		slots:     slots,
		bus:       bus,
		tunnels:   tunnels,
		connPool:  connPool,
		identity: Identity{
			Version:    version,
			Commit:     commit,
			PID:        os.Getpid(),
			Session:    paths.Session,
			ConfigHome: paths.ConfigHome,
			StartedAt:  time.Now().UTC().Format(time.RFC3339),
			Mode:       types.ModeLocal,
			APIVersion: 1,
		},
		rootCtx:        rootCtx,
		cancelRoot:     cancelRoot,
		opWaiters:      make(map[string]chan types.ExecResponse),
		opActive:       make(map[string]context.CancelFunc),
		sseSubs:        make(map[*sseSubscriber]struct{}),
		uiSessionToken: randomHexToken(32),
		uiCSRFToken:    randomHexToken(32),
	}

	lw := approval.NewLocalWebProvider(func(approvalID string) {
		svc.broadcast(Event{Type: "approval_created", Data: map[string]string{"approval_id": approvalID}})
	})
	svc.localWeb = lw
	appMgr.RegisterProvider(lw)

	_ = bus.Start(rootCtx, svc.handleBusEvent)
	slots.Start(rootCtx)
	return svc, nil
}

// SetWebURL updates the active loopback Web Console URL after binding.
func (s *Service) SetWebURL(u string) {
	s.identity.WebURL = u
	s.localWeb.SetBaseURL(u)
}

// Identity returns daemon runtime metadata.
func (s *Service) Identity() Identity {
	return s.identity
}

// Store exposes the transactional SQLite store for HTTP CRUD handlers.
func (s *Service) Store() *store.Store {
	return s.store
}

// Secrets exposes the credential secret store.
func (s *Service) Secrets() secrets.Store {
	return s.secrets
}

// Drivers exposes the driver registry.
func (s *Service) Drivers() *driver.Registry {
	return s.drivers
}

// Plugins exposes the external plugin manager.
func (s *Service) Plugins() *drvplugin.Manager {
	return s.plugins
}

// UISessionToken returns the daemon-scoped cryptographic browser session cookie token.
func (s *Service) UISessionToken() string {
	return s.uiSessionToken
}

// UICSRFToken returns the daemon-scoped cryptographic CSRF token required on mutating Web API calls.
func (s *Service) UICSRFToken() string {
	return s.uiCSRFToken
}

// CredentialSetupURL builds a deep-link URL to open the password-entry dialog for a credential in Web UI.
func (s *Service) CredentialSetupURL(credID string) string {
	base := strings.TrimRight(s.identity.WebURL, "/")
	if base == "" || credID == "" {
		return ""
	}
	return base + "/catalog?subtab=credentials&credential=" + url.QueryEscape(credID)
}

func randomHexToken(nBytes int) string {
	b := make([]byte, nBytes)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// Done returns a channel closed when the daemon begins shutting down.
func (s *Service) Done() <-chan struct{} {
	return s.rootCtx.Done()
}

// CancelBackground cancels long-lived background streams/waiters at shutdown start.
func (s *Service) CancelBackground() {
	s.wgMu.Lock()
	s.stopping = true
	if s.cancelRoot != nil {
		s.cancelRoot()
	}
	s.wgMu.Unlock()
}

func (s *Service) goBackground(fn func(context.Context)) bool {
	if s == nil {
		return false
	}
	s.wgMu.RLock()
	if s.stopping || s.rootCtx == nil || s.rootCtx.Err() != nil {
		s.wgMu.RUnlock()
		return false
	}
	s.wg.Add(1)
	s.wgMu.RUnlock()
	go func() {
		defer s.wg.Done()
		fn(s.rootCtx)
	}()
	return true
}

// Shutdown gracefully stops background workers, slots, pools, approvals, plugins, and store.
func (s *Service) Shutdown() {
	s.CancelBackground()
	s.approvals.Shutdown()
	s.wg.Wait()
	s.slots.Wait()
	_ = s.slots.Close()
	if s.bus != nil {
		_ = s.bus.Close()
	}
	if s.connPool != nil {
		_ = s.connPool.Close()
	}
	if s.tunnels != nil {
		_ = s.tunnels.Close()
	}
	s.plugins.Shutdown()
	_ = s.store.Close()
}

// Mode returns the active daemon runtime mode ("local" or "server").
func (s *Service) Mode() types.ServerMode {
	if s.mode == "" {
		return types.ModeLocal
	}
	return s.mode
}

// IsServerMode reports whether Service is running as a multi-user remote server.
func (s *Service) IsServerMode() bool {
	return s.Mode() == types.ModeServer
}

// ServerConfig returns the active server configuration (nil in local mode).
func (s *Service) ServerConfig() *config.ServerConfig {
	return s.serverCfg
}

// InvalidateCatalogPools clears pooled connections/tunnels locally and notifies replicas.
func (s *Service) InvalidateCatalogPools(kind, id string) {
	s.invalidateLocalPools(kind, id)
	s.broadcast(Event{Type: "catalog_updated", Data: map[string]string{"kind": kind, "id": id}})
}

func (s *Service) invalidateLocalPools(kind, id string) {
	if s.connPool != nil {
		switch kind {
		case "target":
			s.connPool.InvalidateTarget(id)
		case "instance":
			s.connPool.InvalidateInstance(id)
		case "network", "network_profile":
			s.connPool.InvalidateNetwork(id)
		case "credential":
			s.connPool.InvalidateCredential(id)
		default:
			s.connPool.InvalidateAll()
		}
	}
	if s.tunnels != nil {
		if (kind == "network" || kind == "network_profile") && id != "" {
			s.tunnels.InvalidateProfile(id)
		} else if kind == "topology" || kind == "" || kind == "credential" {
			s.tunnels.InvalidateAll()
		}
	}
}

func (s *Service) handleBusEvent(ev Event) {
	switch ev.Type {
	case "approval_resolved":
		if len(ev.RawData) > 0 {
			var app types.ApprovalRequest
			if json.Unmarshal(ev.RawData, &app) == nil && app.ID != "" {
				s.approvals.NotifyExternalResolution(app)
			}
		}
	case "operation_cancel":
		if len(ev.RawData) > 0 {
			var payload struct {
				OperationID string `json:"operation_id"`
			}
			if json.Unmarshal(ev.RawData, &payload) == nil && payload.OperationID != "" {
				s.opMu.Lock()
				cancelFn := s.opActive[payload.OperationID]
				s.opMu.Unlock()
				if cancelFn != nil {
					cancelFn()
				}
			}
		}
		return
	case "catalog_updated":
		if len(ev.RawData) > 0 {
			var payload struct {
				Kind string `json:"kind"`
				ID   string `json:"id"`
			}
			if json.Unmarshal(ev.RawData, &payload) == nil {
				s.invalidateLocalPools(payload.Kind, payload.ID)
			}
		}
	}
	s.broadcastLocalSSE(ev)
}

func (s *Service) subscribeSSE(p types.Principal) *sseSubscriber {
	sub := &sseSubscriber{
		ch:        make(chan Event, 32),
		principal: p,
	}
	s.sseMu.Lock()
	s.sseSubs[sub] = struct{}{}
	s.sseMu.Unlock()
	return sub
}

func (s *Service) unsubscribeSSE(sub *sseSubscriber) {
	s.sseMu.Lock()
	delete(s.sseSubs, sub)
	s.sseMu.Unlock()
	close(sub.ch)
}

func (s *Service) broadcast(ev Event) {
	s.broadcastLocalSSE(ev)
	if s.bus != nil {
		_ = s.bus.Publish(context.Background(), ev)
	}
}

func (s *Service) broadcastLocalSSE(ev Event) {
	s.sseMu.Lock()
	defer s.sseMu.Unlock()
	for sub := range s.sseSubs {
		filtered, allowed := s.filterEventForPrincipal(sub.principal, ev)
		if !allowed {
			continue
		}
		select {
		case sub.ch <- filtered:
		default:
		}
	}
}

func (s *Service) filterEventForPrincipal(p types.Principal, ev Event) (Event, bool) {
	if !s.IsServerMode() || rbac.IsPlatformAdmin(p) {
		return ev, true
	}
	switch ev.Type {
	case "operation_updated":
		var op types.Operation
		if rawOp, ok := ev.Data.(types.Operation); ok {
			op = rawOp
		} else if len(ev.RawData) > 0 {
			_ = json.Unmarshal(ev.RawData, &op)
		}
		if op.ID != "" && !rbac.CanViewOperation(p, op) {
			return Event{}, false
		}
		// Never broadcast raw unredacted SQL over SSE in server mode.
		op.QueryText = ""
		ev.Data = op
		return ev, true
	case "approval_resolved":
		var app types.ApprovalRequest
		if rawApp, ok := ev.Data.(types.ApprovalRequest); ok {
			app = rawApp
		} else if len(ev.RawData) > 0 {
			_ = json.Unmarshal(ev.RawData, &app)
		}
		if app.ID != "" && (app.PrincipalID == "" || app.PrincipalID != p.ID) {
			sysID := ""
			if app.SystemSlug != "" {
				if sys, err := s.store.ResolveSystem(context.Background(), app.SystemSlug); err == nil {
					sysID = sys.ID
				}
			}
			if rbac.EffectiveRoleForScope(p, rbac.ResourceScope{
				SystemID:        sysID,
				SystemSlug:      app.SystemSlug,
				EnvironmentCode: app.EnvironmentCode,
			}) == "" {
				return Event{}, false
			}
		}
		app.QueryText = ""
		ev.Data = app
		return ev, true
	default:
		return ev, true
	}
}

func (s *Service) hasCredentialSecret(ctx context.Context, cp types.CredentialProfile) bool {
	switch cp.Kind {
	case types.CredKeychain:
		ok, err := s.secrets.Has(ctx, "cred:"+cp.ID)
		return err == nil && ok
	case types.CredEnvRef:
		return cp.EnvVarName != "" && os.Getenv(cp.EnvVarName) != ""
	case types.CredExecProvider:
		return strings.TrimSpace(cp.ExecCommand) != ""
	default:
		return false
	}
}

// BuildDisplayCatalog constructs server-driven metadata catalogs (zero hardcoded labels in frontend).
func (s *Service) BuildDisplayCatalog(ctx context.Context) (types.DisplayCatalog, error) {
	envs, err := s.store.ListEnvironments(ctx)
	if err != nil {
		return types.DisplayCatalog{}, err
	}
	envItems := make([]types.DisplayMetaItem, 0, len(envs))
	for _, e := range envs {
		envItems = append(envItems, types.DisplayMetaItem{
			Code:   e.Code,
			Labels: e.Labels,
			Color:  e.Color,
			Order:  e.SortOrder,
		})
	}
	drvList := s.drivers.List()
	engineItems := make([]types.DisplayMetaItem, 0, len(drvList))
	for i, d := range drvList {
		lbl := d.Labels
		if len(lbl) == 0 {
			lbl = map[string]string{"en": d.DisplayName, "zh": d.DisplayName}
		}
		color := "#4B5563"
		if d.Tier == "plugin" {
			color = "#7C3AED"
		}
		engineItems = append(engineItems, types.DisplayMetaItem{
			Code:   d.Engine,
			Labels: lbl,
			Color:  color,
			Order:  (i + 1) * 10,
		})
	}

	providerNames := s.approvals.ProviderNames()
	if len(providerNames) == 0 {
		providerNames = []string{"local-web"}
	}
	sort.Slice(providerNames, func(i, j int) bool {
		rank := func(name string) int {
			switch name {
			case "local-web":
				return 0
			case "webhook":
				return 1
			default:
				return 2
			}
		}
		ri, rj := rank(providerNames[i]), rank(providerNames[j])
		if ri != rj {
			return ri < rj
		}
		return providerNames[i] < providerNames[j]
	})
	approvalItems := make([]types.DisplayMetaItem, 0, len(providerNames))
	for i, name := range providerNames {
		item := types.DisplayMetaItem{
			Code:  name,
			Color: "#4B5563",
			Order: (i + 1) * 10,
		}
		switch name {
		case "local-web":
			item.Labels = map[string]string{"en": "Local Web Popup", "zh": "本机 Web 弹窗确认"}
			item.Color = "#2563EB"
		case "webhook":
			item.Labels = map[string]string{"en": "Webhook Notification", "zh": "Webhook 外部审批"}
			item.Color = "#7C3AED"
		default:
			item.Labels = map[string]string{"en": name, "zh": name}
		}
		approvalItems = append(approvalItems, item)
	}

	return types.DisplayCatalog{
		CatalogVersion: 1,
		Environments:   envItems,
		OperationStatuses: []types.DisplayMetaItem{
			{Code: string(types.OpPending), Labels: map[string]string{"en": "Pending", "zh": "排队中"}, Color: "#6B7280", Order: 10},
			{Code: string(types.OpWaitingApproval), Labels: map[string]string{"en": "Waiting Approval", "zh": "待人工审批"}, Color: "#D97706", Order: 20},
			{Code: string(types.OpRunning), Labels: map[string]string{"en": "Running", "zh": "执行中"}, Color: "#2563EB", Order: 30},
			{Code: string(types.OpSucceeded), Labels: map[string]string{"en": "Succeeded", "zh": "执行成功"}, Color: "#16A34A", Order: 40},
			{Code: string(types.OpFailed), Labels: map[string]string{"en": "Failed", "zh": "执行失败"}, Color: "#DC2626", Order: 50},
			{Code: string(types.OpDenied), Labels: map[string]string{"en": "Policy Denied", "zh": "策略拒绝"}, Color: "#B91C1C", Order: 60},
			{Code: string(types.OpRejected), Labels: map[string]string{"en": "Rejected", "zh": "审批拒绝"}, Color: "#DC2626", Order: 70},
			{Code: string(types.OpExpired), Labels: map[string]string{"en": "Expired", "zh": "审批超时"}, Color: "#9333EA", Order: 80},
			{Code: string(types.OpCancelled), Labels: map[string]string{"en": "Cancelled", "zh": "已撤回"}, Color: "#6B7280", Order: 90},
			{Code: string(types.OpTimedOut), Labels: map[string]string{"en": "Timed Out", "zh": "执行超时"}, Color: "#EA580C", Order: 100},
		},
		RiskLevels: []types.DisplayMetaItem{
			{Code: string(types.RiskSafeRead), Labels: map[string]string{"en": "Safe Read", "zh": "安全只读"}, Color: "#16A34A", Order: 10},
			{Code: string(types.RiskHighCostRead), Labels: map[string]string{"en": "High-Cost Read", "zh": "高危高耗读"}, Color: "#D97706", Order: 20},
			{Code: string(types.RiskWrite), Labels: map[string]string{"en": "Write (DML)", "zh": "写操作"}, Color: "#EA580C", Order: 30},
			{Code: string(types.RiskDDL), Labels: map[string]string{"en": "Schema (DDL)", "zh": "结构变更"}, Color: "#DC2626", Order: 40},
			{Code: string(types.RiskAdmin), Labels: map[string]string{"en": "Admin", "zh": "管理指令"}, Color: "#991B1B", Order: 50},
			{Code: string(types.RiskUnknown), Labels: map[string]string{"en": "Unknown (Fail-Closed)", "zh": "未知高危"}, Color: "#7C3AED", Order: 60},
		},
		Engines:           engineItems,
		ApprovalProviders: approvalItems,
	}, nil
}

func (s *Service) resolveNetworkProfile(ctx context.Context, npID string) *types.NetworkProfile {
	if npID == "" {
		return nil
	}
	nets, err := s.store.ListNetworkProfiles(ctx)
	if err != nil {
		return nil
	}
	for _, np := range nets {
		if np.ID == npID {
			npCopy := np
			return &npCopy
		}
	}
	return nil
}

func (s *Service) resolveCredentialProfile(ctx context.Context, credID string) *types.CredentialProfile {
	if credID == "" {
		return nil
	}
	creds, err := s.store.ListCredentialProfiles(ctx)
	if err != nil {
		return nil
	}
	for _, cp := range creds {
		if cp.ID == credID {
			cpCopy := cp
			return &cpCopy
		}
	}
	return nil
}

func (s *Service) openDriverConn(ctx context.Context, detail types.TargetDetail, credMode types.AccessLevel, preferReplica bool) (driver.Conn, error) {
	if detail.Instance == nil {
		return nil, fmt.Errorf("target %q references missing instance", detail.Target.Ref)
	}
	inst := *detail.Instance
	if s.IsServerMode() && (s.serverCfg == nil || !s.serverCfg.AllowSQLiteTargets) && classify.CanonicalEngine(inst.Engine) == "sqlite" {
		return nil, fmt.Errorf("sqlite targets are disabled in server mode")
	}
	effectiveNet := detail.NetworkProfile
	// Route read-only queries to replica instance if configured, resolving the replica's own NetworkProfile.
	if preferReplica && inst.Role == types.RolePrimary {
		allInsts, err := s.store.ListInstances(ctx)
		if err == nil {
			var replicas []types.Instance
			for _, candidate := range allInsts {
				if candidate.PrimaryInstanceID == inst.ID && candidate.Role == types.RoleReplica && strings.EqualFold(candidate.Engine, inst.Engine) {
					replicas = append(replicas, candidate)
				}
			}
			if len(replicas) > 0 {
				sort.Slice(replicas, func(i, j int) bool {
					if replicas[i].Name != replicas[j].Name {
						return replicas[i].Name < replicas[j].Name
					}
					return replicas[i].ID < replicas[j].ID
				})
				chosen := replicas[0]
				if chosen.NetworkProfileID != inst.NetworkProfileID {
					effectiveNet = s.resolveNetworkProfile(ctx, chosen.NetworkProfileID)
				}
				inst = chosen
			}
		}
	}

	drv, ok := s.drivers.Get(inst.Engine)
	if !ok {
		return nil, fmt.Errorf("no driver registered for engine %q", inst.Engine)
	}

	var chosenCred *types.CredentialProfile
	readOnly := credMode == types.AccessReadOnly
	if readOnly && detail.ROCredential != nil {
		chosenCred = detail.ROCredential
	} else if !readOnly && detail.RWCredential != nil {
		chosenCred = detail.RWCredential
	} else if detail.ROCredential != nil {
		chosenCred = detail.ROCredential
		readOnly = true
	} else if detail.RWCredential != nil {
		chosenCred = detail.RWCredential
	}

	var resolvedCred secrets.ResolvedSecret
	if chosenCred != nil {
		var err error
		resolvedCred, err = secrets.ResolveCredentialWithOptions(ctx, s.secrets, chosenCred, s.secretPolicy)
		if err != nil {
			return nil, err
		}
	}

	var bastionCred secrets.ResolvedSecret
	if effectiveNet != nil && effectiveNet.BastionCredentialID != "" {
		if cp := s.resolveCredentialProfile(ctx, effectiveNet.BastionCredentialID); cp != nil {
			var err error
			bastionCred, err = secrets.ResolveCredentialWithOptions(ctx, s.secrets, cp, s.secretPolicy)
			if err != nil {
				return nil, fmt.Errorf("resolve bastion credential: %w", err)
			}
		}
	}

	needsBridge := s.dialPolicy.EnforceEgressGuard || (effectiveNet != nil &&
		effectiveNet.Mode != "" &&
		effectiveNet.Mode != types.NetworkDirect)

	connCfg := driver.ConnectionConfig{
		Engine:          inst.Engine,
		Host:            inst.Host,
		Port:            inst.Port,
		DatabaseName:    detail.Target.DatabaseName,
		Params:          inst.Params,
		ReadOnly:        readOnly,
		Credential:      resolvedCred,
		NeedsDialBridge: needsBridge,
	}

	openFresh := func(openCtx context.Context) (driver.Conn, error) {
		var dialRes netdial.DialResult
		var err error
		if s.tunnels != nil {
			dialRes, err = s.tunnels.BuildContextWithPolicy(openCtx, effectiveNet, bastionCred, inst.TLSMode, inst.Host, s.dialPolicy)
		} else {
			dialRes, err = netdial.BuildContextWithPolicy(openCtx, effectiveNet, bastionCred, inst.TLSMode, inst.Host, s.dialPolicy)
		}
		if err != nil {
			return nil, err
		}
		cfgCopy := connCfg
		cfgCopy.DialContext = dialRes.DialContext
		cfgCopy.TLSMode = dialRes.TLSMode
		cfgCopy.TLSConfig = dialRes.TLSConfig
		cfgCopy.CloseHook = driver.CloseOnce(dialRes.Close)
		conn, openErr := drv.Open(openCtx, cfgCopy)
		if openErr != nil {
			_ = dialRes.Close()
			return nil, openErr
		}
		return conn, nil
	}

	if s.connPool == nil || !readOnly || driver.ShouldBypassPool(connCfg) || (drv.Metadata().Tier == "plugin" && needsBridge) {
		return openFresh(ctx)
	}

	netID, netHash := "", ""
	if effectiveNet != nil {
		netID = effectiveNet.ID
		netHash = effectiveNet.ID + "|" + string(effectiveNet.Mode) + "|" + effectiveNet.UpdatedAtUTC + "|" + effectiveNet.TLSMode
	}
	credID := ""
	var credKind types.CredentialKind
	if chosenCred != nil {
		credID = chosenCred.ID
		credKind = chosenCred.Kind
	}
	meta := driver.ConnPoolMeta{
		TargetID:         detail.Target.ID,
		InstanceID:       inst.ID,
		NetworkProfileID: netID,
		CredentialID:     credID,
		CredKind:         credKind,
		ReadOnly:         true,
	}
	meta.Key = driver.BuildConnPoolKey(meta, connCfg, netHash)
	return s.connPool.Acquire(ctx, meta, openFresh)
}

// PingTarget tests live connectivity for one resolved target.
func (s *Service) PingTarget(ctx context.Context, detail types.TargetDetail) types.PingResult {
	res := types.PingResult{
		TargetRef: detail.Target.Ref,
	}
	if detail.Instance != nil {
		res.InstanceID = detail.Instance.ID
		res.Engine = detail.Instance.Engine
		res.Role = string(detail.Instance.Role)
	}
	connCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	conn, err := s.openDriverConn(connCtx, detail, types.AccessReadOnly, false)
	if err != nil {
		msg := err.Error()
		if classify.CanonicalEngine(res.Engine) == "sqlite" && strings.Contains(strings.ToLower(msg), "unable to open database file") && detail.Instance != nil {
			dbPath := strings.TrimSpace(detail.Target.DatabaseName)
			if dbPath == "" {
				dbPath = strings.TrimSpace(detail.Instance.Host)
			}
			if dbPath != "" && dbPath != ":memory:" && !strings.HasPrefix(dbPath, "file:") {
				checkPath := dbPath
				if strings.HasPrefix(checkPath, "~/") {
					if home, hErr := os.UserHomeDir(); hErr == nil {
						checkPath = home + checkPath[1:]
					}
				}
				if _, statErr := os.Stat(checkPath); os.IsNotExist(statErr) {
					msg += fmt.Sprintf(" (SQLite file %q does not exist yet; read-only probes open with mode=ro and do not create empty files — create the file or run a write query in a yolo environment first)", dbPath)
				}
			}
		}
		res.Error = msg
		return res
	}
	defer func() { _ = conn.Close() }()

	pingOut, err := conn.Ping(connCtx)
	res.ServerVersion = pingOut.ServerVersion
	res.Dialect = pingOut.Dialect
	res.Capabilities = pingOut.Capabilities
	if res.Capabilities == nil {
		if dac, ok := conn.(driver.DialectAwareConn); ok {
			res.Capabilities = dac.Capabilities()
		}
	}
	if res.Dialect == "" && res.Capabilities != nil {
		res.Dialect = res.Capabilities.Dialect
	}
	res.LatencyMs = pingOut.LatencyMs
	if err != nil {
		res.Reachable = false
		res.Error = err.Error()
		return res
	}
	res.Reachable = pingOut.Reachable
	res.Error = pingOut.Error
	if !res.Reachable && strings.TrimSpace(res.Error) == "" {
		res.Error = "connectivity probe failed without a driver error message"
	}
	if res.Reachable && res.Capabilities != nil && detail.Instance != nil {
		_ = s.store.UpdateInstanceCapabilities(ctx, detail.Instance.ID, res.Capabilities)
	}
	return res
}

// PingTargets probes multiple targets concurrently while preserving input order.
func (s *Service) PingTargets(ctx context.Context, details []types.TargetDetail) []types.PingResult {
	results := make([]types.PingResult, len(details))
	if len(details) == 0 {
		return results
	}
	workers := 8
	if len(details) < workers {
		workers = len(details)
	}
	sem := make(chan struct{}, workers)
	var wg sync.WaitGroup
	for i, d := range details {
		wg.Add(1)
		go func(idx int, detail types.TargetDetail) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			results[idx] = s.PingTarget(ctx, detail)
		}(i, d)
	}
	wg.Wait()
	return results
}

func (s *Service) authorizeInstanceAction(ctx context.Context, inst types.Instance, credID string, action rbac.Action) (*types.CredentialProfile, error) {
	p := rbac.PrincipalFromContext(ctx)
	if s.IsServerMode() {
		st := strings.ToLower(strings.TrimSpace(inst.ScopeType))
		if st == "" || st == "global" {
			if !rbac.IsPlatformAdmin(p) {
				return nil, fmt.Errorf("forbidden: action %s on global instance requires platform_admin", action)
			}
		} else {
			if err := rbac.Authorize(p, action, s.scopeForScopedResource(ctx, inst.ScopeType, inst.ScopeID)); err != nil {
				return nil, err
			}
		}
	}
	var cp *types.CredentialProfile
	if strings.TrimSpace(credID) != "" {
		cp = s.resolveCredentialProfile(ctx, credID)
		if cp == nil {
			return nil, fmt.Errorf("%w: credential profile %q not found", store.ErrNotFound, credID)
		}
		if s.IsServerMode() {
			cst := strings.ToLower(strings.TrimSpace(cp.ScopeType))
			if cst != "" && cst != "global" {
				if err := rbac.Authorize(p, rbac.ActionCatalogRead, s.scopeForScopedResource(ctx, cp.ScopeType, cp.ScopeID)); err != nil {
					return nil, err
				}
			}
		}
	}
	return cp, nil
}

// PingInstance tests an instance directly and discovers databases on it.
func (s *Service) PingInstance(ctx context.Context, instanceID, credID, dbName string) (types.PingResult, error) {
	inst, err := s.store.GetInstance(ctx, instanceID)
	if err != nil {
		return types.PingResult{}, err
	}
	cp, err := s.authorizeInstanceAction(ctx, inst, credID, rbac.ActionDBTest)
	if err != nil {
		return types.PingResult{}, err
	}
	detail := types.TargetDetail{
		Target:         types.Target{Ref: inst.Name, DatabaseName: dbName, ROCredentialID: credID},
		Instance:       &inst,
		NetworkProfile: s.resolveNetworkProfile(ctx, inst.NetworkProfileID),
		ROCredential:   cp,
	}
	return s.PingTarget(ctx, detail), nil
}

// DiscoverInstance enumerates logical databases/schemas on an instance.
func (s *Service) DiscoverInstance(ctx context.Context, instanceID, credID, dbName string) ([]string, error) {
	inst, err := s.store.GetInstance(ctx, instanceID)
	if err != nil {
		return nil, err
	}
	cp, err := s.authorizeInstanceAction(ctx, inst, credID, rbac.ActionInstanceDiscover)
	if err != nil {
		return nil, err
	}
	detail := types.TargetDetail{
		Target:         types.Target{Ref: inst.Name, DatabaseName: dbName, ROCredentialID: credID},
		Instance:       &inst,
		NetworkProfile: s.resolveNetworkProfile(ctx, inst.NetworkProfileID),
		ROCredential:   cp,
	}
	connCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	conn, err := s.openDriverConn(connCtx, detail, types.AccessReadOnly, false)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()
	dbs, err := conn.ListDatabases(connCtx)
	if err == nil {
		_ = s.store.RecordAuditEvent(ctx, s.effectiveActor(ctx, ""), "instance.discover", inst.ID, "", map[string]any{
			"instance": inst.Name,
			"count":    len(dbs),
		})
	}
	return dbs, err
}

// InspectSchema lists tables/collections/key prefixes or describes one object on a target using read-only credentials.
func (s *Service) InspectSchema(ctx context.Context, targetRefOrAlias, workspaceCWD, table, search string, limit int, gitRemotes ...string) (any, error) {
	p := rbac.PrincipalFromContext(ctx)
	detail, err := s.ResolveTarget(ctx, targetRefOrAlias, workspaceCWD, gitRemotes...)
	if err != nil {
		return nil, err
	}
	if s.IsServerMode() {
		if authErr := rbac.Authorize(p, rbac.ActionDBSchema, scopeForTarget(detail)); authErr != nil {
			return nil, &TargetLookupError{
				Code:    types.ErrCodeForbidden,
				Message: authErr.Error(),
			}
		}
	}
	if detail.Target.Status == types.TargetDisabled || detail.Target.Status == types.TargetMaintenance {
		return nil, &TargetLookupError{
			Code:    types.ErrCodeTargetMaintenance,
			Message: fmt.Sprintf("Target %q is currently %s", detail.Target.Ref, detail.Target.Status),
		}
	}
	if !detail.EffectivePolicy.AllowSafeRead {
		return nil, &TargetLookupError{
			Code:    types.ErrCodePolicyDenied,
			Message: fmt.Sprintf("Target %q disallows safe read inspection", detail.Target.Ref),
		}
	}
	timeoutSec := detail.EffectivePolicy.ExecTimeoutSec
	if timeoutSec <= 0 {
		timeoutSec = 15
	}
	schemaCtx, cancel := context.WithTimeout(ctx, time.Duration(timeoutSec)*time.Second)
	defer cancel()

	conn, err := s.openDriverConn(schemaCtx, detail, types.AccessReadOnly, true)
	if err != nil {
		return nil, &TargetLookupError{
			Code:    types.ErrCodeDriverError,
			Message: err.Error(),
		}
	}
	defer func() { _ = conn.Close() }()

	si, ok := conn.(driver.SchemaInspector)
	if !ok {
		eng := ""
		if detail.Instance != nil {
			eng = detail.Instance.Engine
		}
		return nil, &TargetLookupError{
			Code:    types.ErrCodeDriverError,
			Message: fmt.Sprintf("driver for engine %q does not support db schema introspection; run a read-only query with exec", eng),
		}
	}

	if strings.TrimSpace(table) == "" {
		res, err := driver.ExecuteWithCancelGuard(schemaCtx, conn, func(cctx context.Context) (*types.SchemaListResult, error) {
			return si.ListTables(cctx, driver.SchemaListOpts{Search: search, Limit: limit})
		})
		if err != nil {
			return nil, &TargetLookupError{
				Code:    types.ErrCodeDriverError,
				Message: err.Error(),
			}
		}
		actor := s.effectiveActor(ctx, "")
		res.TargetRef = detail.Target.Ref
		_ = s.store.RecordAuditEvent(ctx, actor, "schema.list", detail.Target.ID, "", map[string]any{
			"target_ref": detail.Target.Ref,
			"search":     search,
			"returned":   res.ReturnedCount,
		})
		return res, nil
	}

	tblSchema, err := driver.ExecuteWithCancelGuard(schemaCtx, conn, func(cctx context.Context) (*types.TableSchema, error) {
		return si.DescribeTable(cctx, table)
	})
	if err != nil {
		return nil, &TargetLookupError{
			Code:    types.ErrCodeDriverError,
			Message: err.Error(),
		}
	}
	actor := s.effectiveActor(ctx, "")
	tblSchema.TargetRef = detail.Target.Ref
	_ = s.store.RecordAuditEvent(ctx, actor, "schema.describe", detail.Target.ID, "", map[string]any{
		"target_ref": detail.Target.Ref,
		"table":      tblSchema.Name,
	})
	return tblSchema, nil
}

// Execute runs the full dry-run / preflight / policy / approval / driver execution pipeline.
func (s *Service) Execute(ctx context.Context, req types.ExecRequest) (types.ExecResponse, error) {
	p := rbac.PrincipalFromContext(ctx)
	detail, err := s.ResolveTarget(ctx, req.TargetRefOrAlias, req.WorkspaceCWD, req.WorkspaceGitRemotes...)
	if err != nil {
		return types.ExecResponse{}, err
	}
	scope := scopeForTarget(detail)
	if s.IsServerMode() {
		if authErr := rbac.Authorize(p, rbac.ActionDBExecute, scope); authErr != nil {
			return types.ExecResponse{}, &TargetLookupError{
				Code:    types.ErrCodeForbidden,
				Message: authErr.Error(),
			}
		}
	}
	if detail.Instance == nil {
		return types.ExecResponse{}, fmt.Errorf("target %q has no bound instance", detail.Target.Ref)
	}
	engine := detail.Instance.Engine
	drv, ok := s.drivers.Get(engine)
	if !ok {
		return types.ExecResponse{}, fmt.Errorf("driver %q not registered", engine)
	}

	cls, err := drv.Classify(ctx, req.Query)
	if err != nil {
		cls = classify.Classify(engine, req.Query)
	}
	eff := detail.EffectivePolicy
	if s.IsServerMode() && rbac.ShouldForceReadOnly(p, scope) {
		eff.RequireApprovalOnWrite = true
		eff.RequireApprovalOnDDL = true
		eff.RequireApprovalOnAdmin = true
		eff.RequireApprovalOnUnknown = true
	}

	// 1. Offline Dry-Run: strictly zero DB dial, zero approval, zero business mutation.
	if req.DryRun {
		eval := policy.EvaluateQuery(detail.Target, eff, cls, nil, req.Query)
		return buildExecResponseSkeleton(detail, cls, nil, eval, types.OpPending), nil
	}

	// 2. Remote Read-Only Preflight (non-mutating EXPLAIN, zero approval popup).
	var pf *types.PreflightReport
	var preflightConn driver.Conn
	var preflightOpenErr error
	closePreflightConn := func() {
		if preflightConn != nil {
			_ = preflightConn.Close()
			preflightConn = nil
		}
	}
	defer closePreflightConn()

	canPreflightWrite := !cls.IsReadOnly && cls.RiskLevel == types.RiskWrite && driver.CanPreflightSQL(cls) &&
		(!eff.ProdReadOnlyFreeze || eff.SafetyTier != types.SafetyTierStrict)
	needAutoPreflight := (cls.IsReadOnly && ((eff.SafetyTier != types.SafetyTierYOLO && cls.RiskLevel == types.RiskSafeRead) || policy.HasPreflightPatternRule(eff.PatternRules))) ||
		(canPreflightWrite && eff.SafetyTier != types.SafetyTierYOLO && eff.RequireApprovalOnWrite)
	if req.Preflight || needAutoPreflight {
		pfCtx, cancel := context.WithTimeout(ctx, time.Duration(minPositive(req.TimeoutSec, eff.ExecTimeoutSec))*time.Second)
		conn, openErr := s.openDriverConn(pfCtx, detail, types.AccessReadOnly, true)
		if openErr == nil {
			pf, _ = driver.ExecuteWithCancelGuard(pfCtx, conn, func(cctx context.Context) (*types.PreflightReport, error) {
				return conn.Preflight(cctx, req.Query, driver.PreflightOpts{})
			})
			if req.Preflight || !cls.IsReadOnly {
				_ = conn.Close()
			} else {
				preflightConn = conn
			}
		} else if req.Preflight {
			cancel()
			return types.ExecResponse{}, openErr
		} else if cls.IsReadOnly {
			preflightOpenErr = openErr
		}
		cancel()
	}

	eval := policy.EvaluateQuery(detail.Target, eff, cls, pf, req.Query)
	if s.IsServerMode() && rbac.ShouldForceReadOnly(p, scope) && !cls.IsReadOnly {
		eval.Decision = types.DecisionDeny
		eval.DenyCode = types.ErrCodeForbidden
		eval.DenyMessage = "Current token/role is restricted to read-only operations."
		eval.CredentialMode = types.AccessReadOnly
	}
	if req.Preflight {
		return buildExecResponseSkeleton(detail, cls, pf, eval, types.OpPending), nil
	}
	if eval.Decision != types.DecisionAllow {
		closePreflightConn()
	}

	globalCfg, cfgErr := s.store.GetGlobalSecurityConfig(ctx)
	requireReason := true
	if cfgErr == nil {
		requireReason = globalCfg.RequireReasonForApproval
	}
	if ((eval.Decision == types.DecisionRequireApproval && requireReason) || eval.RequireReason) && strings.TrimSpace(req.Reason) == "" {
		resp := buildExecResponseSkeleton(detail, cls, pf, eval, types.OpDenied)
		resp.ErrorCode = types.ErrCodeReasonRequired
		if eval.RequireReason && eval.Decision == types.DecisionAllow {
			resp.ErrorMessage = "A business reason (--reason) is required for scan-read queries on this target (scan_read_mode=reason_only)."
		} else {
			resp.ErrorMessage = "A business reason (--reason) is required when requesting human approval."
		}
		return resp, nil
	}
	redacted := req.Query
	if globalCfg.RedactAuditLiterals {
		redacted = audit.RedactQuery(req.Query)
	}
	actor := s.effectiveActor(ctx, req.Actor)
	ownerUID := p.ID
	if p.OwnerUserID != "" {
		ownerUID = p.OwnerUserID
	}

	sysID, sysSlug := detail.Target.OwnerSystemID, ""
	if detail.OwnerSystem != nil {
		sysSlug = detail.OwnerSystem.Slug
	}

	op := types.Operation{
		TargetID:          detail.Target.ID,
		TargetRef:         detail.Target.Ref,
		SystemID:          sysID,
		SystemSlug:        sysSlug,
		EnvironmentCode:   detail.Target.EnvironmentCode,
		Engine:            engine,
		Actor:             actor,
		PrincipalID:       p.ID,
		PrincipalKind:     p.Kind,
		OwnerUserID:       ownerUID,
		OwnerNodeID:       s.nodeID,
		LeaseExpiresAtUTC: time.Now().UTC().Add(45 * time.Second).Format(time.RFC3339Nano),
		Reason:            req.Reason,
		WorkspaceCWD:    req.WorkspaceCWD,
		QueryText:       req.Query,
		QueryRedacted:   redacted,
		RiskLevel:       cls.RiskLevel,
		Decision:        eval.Decision,
		TriggerReasons:  eval.TriggerReasons,
		MatchedRules:    eval.MatchedRules,
		Classification:  cls,
		Preflight:       pf,
		Status:          types.OpPending,
		CredentialMode:  eval.CredentialMode,
	}
	op, err = s.store.CreateOperation(ctx, op)
	if err != nil {
		return types.ExecResponse{}, err
	}

	// Hard deny branch.
	if eval.Decision == types.DecisionDeny {
		op.Status = types.OpDenied
		op.ErrorCode = eval.DenyCode
		op.ErrorMessage = eval.DenyMessage
		op.CompletedAtUTC = time.Now().UTC().Format(time.RFC3339Nano)
		op, _ = s.store.UpdateOperation(ctx, actor, "operation.denied", op)
		s.broadcast(Event{Type: "operation_updated", Data: op})
		resp := s.responseFromOperation(op, eval)
		return resp, nil
	}

	// Approval branch.
	if eval.Decision == types.DecisionRequireApproval {
		waitCh := s.registerOpWaiter(op.ID)
		providerName := eval.EffectivePolicy.ApprovalProvider
		if providerName == "" {
			providerName = eff.ApprovalProvider
		}
		app, appURL, subErr := s.approvals.Submit(ctx, providerName, op, detail, eff.ApprovalTimeoutSec)
		if subErr != nil {
			s.clearOpWaiter(op.ID)
			op.Status = types.OpFailed
			op.ErrorCode = types.ErrCodeInternalError
			op.ErrorMessage = "failed to submit approval: " + subErr.Error()
			op.CompletedAtUTC = time.Now().UTC().Format(time.RFC3339Nano)
			op, _ = s.store.UpdateOperation(ctx, actor, "operation.failed", op)
			return s.responseFromOperation(op, eval), nil
		}
		op.Status = types.OpWaitingApproval
		op.ApprovalID = app.ID
		op, _ = s.store.UpdateOperation(ctx, actor, "operation.waiting_approval", op)
		s.broadcast(Event{Type: "operation_updated", Data: op})

		// Spawn waiter to react when approval expires/resolves asynchronously.
		if !s.goBackground(func(context.Context) {
			s.driveApprovalLifecycle(op, detail, eval, app.ID, req.MaxRows, req.MaxBytes, req.TimeoutSec)
		}) {
			_, _ = s.approvals.Cancel(ctx, app.ID, "system")
			s.clearOpWaiter(op.ID)
			op.Status = types.OpCancelled
			op.ErrorCode = types.ErrCodeDaemonUnavailable
			op.ErrorMessage = "daemon is shutting down"
			op.CompletedAtUTC = time.Now().UTC().Format(time.RFC3339Nano)
			op, _ = s.store.UpdateOperation(ctx, actor, "operation.cancelled", op)
			return s.responseFromOperation(op, eval), nil
		}

		if !req.Wait {
			resp := s.responseFromOperation(op, eval)
			resp.ApprovalURL = appURL
			resp.ApprovalExpires = app.ExpiresAtUTC
			resp.ErrorCode = types.ErrCodeWaitingApproval
			resp.ErrorMessage = fmt.Sprintf("Execution requires human approval (%s).", strings.Join(eval.TriggerReasons, ", "))
			if len(eval.MatchedRules) > 0 {
				top := eval.MatchedRules[0]
				if top.ConfirmTitle != "" {
					resp.ErrorMessage = fmt.Sprintf("High-risk pattern matched [%s]: %s", top.ConfirmTitle, top.ConfirmMessage)
				}
			}
			return resp, nil
		}

		// Block synchronously until approval resolves + query finishes (or caller ctx cancels).
		select {
		case resp := <-waitCh:
			resp.ApprovalURL = appURL
			resp.ApprovalExpires = app.ExpiresAtUTC
			return resp, nil
		case <-ctx.Done():
			return types.ExecResponse{}, ctx.Err()
		}
	}

	// Direct allow (dev YOLO or prod safe read).
	reusedConn := preflightConn
	preflightConn = nil
	resp := s.runExecutionWithConn(ctx, op, detail, eval, req.MaxRows, req.MaxBytes, req.TimeoutSec, reusedConn, preflightOpenErr)
	return resp, nil
}

func (s *Service) driveApprovalLifecycle(op types.Operation, detail types.TargetDetail, eval types.PolicyEvaluation, approvalID string, reqMaxRows int, reqMaxBytes int64, reqTimeout int) {
	app, err := s.approvals.Wait(s.rootCtx, approvalID)
	if err != nil {
		// Daemon shutting down.
		s.notifyOpWaiter(op.ID, s.responseFromOperation(op, eval))
		return
	}
	switch app.Status {
	case types.ApprovalApproved:
		if s.IsServerMode() {
			claimed, claimErr := s.store.TryClaimWaitingOperation(s.rootCtx, op.ID, s.nodeID, 45*time.Second)
			if claimErr != nil || !claimed {
				return
			}
		}
		resp := s.runExecution(s.rootCtx, op, detail, eval, reqMaxRows, reqMaxBytes, reqTimeout)
		resp.Reviewer = app.Reviewer
		resp.ReviewerNote = app.ReviewerNote
		s.notifyOpWaiter(op.ID, resp)
	case types.ApprovalRejected:
		op.Status = types.OpRejected
		op.ErrorCode = types.ErrCodeApprovalRejected
		op.ErrorMessage = "Execution was rejected by human reviewer."
		op.Retryable = false
		op.CompletedAtUTC = time.Now().UTC().Format(time.RFC3339Nano)
		op, _ = s.store.UpdateOperation(s.rootCtx, app.Reviewer, "operation.rejected", op)
		s.broadcast(Event{Type: "operation_updated", Data: op})
		resp := s.responseFromOperation(op, eval)
		resp.Reviewer = app.Reviewer
		resp.ReviewerNote = app.ReviewerNote
		s.notifyOpWaiter(op.ID, resp)
	case types.ApprovalExpired:
		op.Status = types.OpExpired
		op.ErrorCode = types.ErrCodeApprovalTimeout
		op.ErrorMessage = "Approval timed out before a human responded."
		op.Retryable = true
		op.CompletedAtUTC = time.Now().UTC().Format(time.RFC3339Nano)
		op, _ = s.store.UpdateOperation(s.rootCtx, "system", "operation.expired", op)
		s.broadcast(Event{Type: "operation_updated", Data: op})
		s.notifyOpWaiter(op.ID, s.responseFromOperation(op, eval))
	case types.ApprovalCancelled:
		op.Status = types.OpCancelled
		op.ErrorCode = types.ErrCodePolicyDenied
		op.ErrorMessage = "Operation was cancelled."
		op.CompletedAtUTC = time.Now().UTC().Format(time.RFC3339Nano)
		op, _ = s.store.UpdateOperation(s.rootCtx, app.Reviewer, "operation.cancelled", op)
		s.broadcast(Event{Type: "operation_updated", Data: op})
		s.notifyOpWaiter(op.ID, s.responseFromOperation(op, eval))
	}
}

func (s *Service) runExecution(parentCtx context.Context, op types.Operation, detail types.TargetDetail, eval types.PolicyEvaluation, reqMaxRows int, reqMaxBytes int64, reqTimeout int) types.ExecResponse {
	return s.runExecutionWithConn(parentCtx, op, detail, eval, reqMaxRows, reqMaxBytes, reqTimeout, nil, nil)
}

func (s *Service) runExecutionWithConn(parentCtx context.Context, op types.Operation, detail types.TargetDetail, eval types.PolicyEvaluation, reqMaxRows int, reqMaxBytes int64, reqTimeout int, conn driver.Conn, preErr error) types.ExecResponse {
	eff := eval.EffectivePolicy
	timeoutSec := minPositive(reqTimeout, eff.ExecTimeoutSec)
	maxRows := minPositive(reqMaxRows, eff.MaxRows)
	maxBytes := minPositiveInt64(reqMaxBytes, eff.MaxBytes)

	op.Status = types.OpRunning
	op.OwnerNodeID = s.nodeID
	op.LeaseExpiresAtUTC = time.Now().UTC().Add(45 * time.Second).Format(time.RFC3339Nano)
	op, _ = s.store.UpdateOperation(parentCtx, op.Actor, "operation.running", op)
	s.broadcast(Event{Type: "operation_updated", Data: op})

	execCtx, cancel := context.WithTimeout(parentCtx, time.Duration(timeoutSec)*time.Second)
	s.setOpCancel(op.ID, cancel)
	stopLease := make(chan struct{})
	if s.IsServerMode() {
		s.goBackground(func(context.Context) {
			ticker := time.NewTicker(10 * time.Second)
			defer ticker.Stop()
			for {
				select {
				case <-stopLease:
					return
				case <-execCtx.Done():
					return
				case <-ticker.C:
					if cancelReq, _ := s.store.RenewOperationLease(execCtx, op.ID, s.nodeID, 45*time.Second); cancelReq {
						cancel()
						return
					}
				}
			}
		})
	}
	defer func() {
		close(stopLease)
		cancel()
		s.clearOpCancel(op.ID)
	}()

	err := preErr
	if conn == nil && err == nil {
		conn, err = s.openDriverConn(execCtx, detail, eval.CredentialMode, eval.PreferReplica)
	}
	if err != nil {
		op.Status = types.OpFailed
		op.ErrorCode = types.ErrCodeDriverError
		op.ErrorMessage = err.Error()
		op.Retryable = op.Classification.IsReadOnly
		op.CompletedAtUTC = time.Now().UTC().Format(time.RFC3339Nano)
		op, _ = s.store.UpdateOperation(context.Background(), op.Actor, "operation.failed", op)
		s.broadcast(Event{Type: "operation_updated", Data: op})
		return s.responseFromOperation(op, eval)
	}
	defer func() { _ = conn.Close() }()

	res, err := driver.ExecuteWithCancelGuard(execCtx, conn, func(cctx context.Context) (*types.ExecResult, error) {
		return conn.Execute(cctx, op.QueryText, driver.ExecOpts{
			MaxRows:  maxRows,
			MaxBytes: maxBytes,
		})
	})

	op.CompletedAtUTC = time.Now().UTC().Format(time.RFC3339Nano)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(execCtx.Err(), context.DeadlineExceeded) {
			op.Status = types.OpTimedOut
			op.ErrorCode = types.ErrCodeQueryTimeout
			op.ErrorMessage = fmt.Sprintf("Query exceeded %ds execution timeout.", timeoutSec)
			// Critical safety rule: never auto-replay uncertain writes after timeout.
			op.Retryable = op.Classification.IsReadOnly
		} else if errors.Is(execCtx.Err(), context.Canceled) {
			op.Status = types.OpCancelled
			op.ErrorCode = types.ErrCodeDriverError
			op.ErrorMessage = "Operation cancelled."
			op.Retryable = false
		} else {
			op.Status = types.OpFailed
			op.ErrorCode = types.ErrCodeDriverError
			op.ErrorMessage = err.Error()
			op.Retryable = false
		}
		op, _ = s.store.UpdateOperation(context.Background(), op.Actor, "operation."+string(op.Status), op)
		s.broadcast(Event{Type: "operation_updated", Data: op})
		return s.responseFromOperation(op, eval)
	}

	op.Status = types.OpSucceeded
	op.FetchedRows = res.FetchedRows
	op.ReturnedRows = res.ReturnedRows
	op.AffectedRows = res.AffectedRows
	op.Truncated = res.Truncated
	op.CutoffReason = res.CutoffReason
	op.LatencyMs = res.LatencyMs
	op.OwnerNodeID = ""
	op.LeaseExpiresAtUTC = ""
	op, _ = s.store.UpdateOperation(context.Background(), op.Actor, "operation.succeeded", op)
	_ = s.slots.PutResult(context.Background(), op.ID, res)
	s.broadcast(Event{Type: "operation_updated", Data: op})

	resp := s.responseFromOperation(op, eval)
	resp.Result = res
	return resp
}

// ResolveApproval approves or rejects a pending approval ticket from the Web UI.
func (s *Service) ResolveApproval(ctx context.Context, approvalID string, approve bool, reviewer, note, token string, trustedUISession bool) (types.ApprovalRequest, error) {
	p := rbac.PrincipalFromContext(ctx)
	reviewerUserID := ""
	if s.IsServerMode() {
		appCur, _, err := s.store.GetApproval(ctx, approvalID)
		if err != nil {
			return types.ApprovalRequest{}, err
		}
		sysID := ""
		if sys, sErr := s.store.ResolveSystem(ctx, appCur.SystemSlug); sErr == nil {
			sysID = sys.ID
		}
		forbidSelf := true
		if cfg, gErr := s.store.GetGlobalSecurityConfig(ctx); gErr == nil {
			forbidSelf = cfg.ForbidSelfApproval
		}
		if s.serverCfg != nil && s.serverCfg.Auth.ForbidSelfApproval != nil {
			forbidSelf = forbidSelf && *s.serverCfg.Auth.ForbidSelfApproval
		}
		opOwnerUserID := ""
		if forbidSelf && appCur.OperationID != "" {
			if op, opErr := s.store.GetOperation(ctx, appCur.OperationID); opErr == nil {
				opOwnerUserID = op.OwnerUserID
			}
		}
		if authErr := rbac.AuthorizeApprovalDecision(p, appCur, sysID, opOwnerUserID, forbidSelf); authErr != nil {
			return types.ApprovalRequest{}, authErr
		}
		reviewer = p.Subject
		reviewerUserID = p.ID
	}
	app, err := s.approvals.ResolveWithUser(ctx, approvalID, approve, reviewer, reviewerUserID, note, token, trustedUISession)
	if err != nil {
		return app, err
	}
	s.broadcast(Event{Type: "approval_resolved", Data: app})
	return app, nil
}

// GetOperationStatus retrieves operation state plus cached ResultRelay entry if available.
func (s *Service) GetOperationStatus(ctx context.Context, opID string) (types.ExecResponse, error) {
	op, err := s.store.GetOperation(ctx, opID)
	if err != nil {
		return types.ExecResponse{}, err
	}
	if s.IsServerMode() {
		p := rbac.PrincipalFromContext(ctx)
		if !rbac.CanViewOperation(p, op) {
			return types.ExecResponse{}, &TargetLookupError{
				Code:    types.ErrCodeForbidden,
				Message: "forbidden: operation is outside your authorized scope",
			}
		}
	}
	eval := types.PolicyEvaluation{
		Decision:       op.Decision,
		TriggerReasons: op.TriggerReasons,
		MatchedRules:   op.MatchedRules,
		CredentialMode: op.CredentialMode,
	}
	resp := s.responseFromOperation(op, eval)
	if res, ok, rErr := s.slots.GetResult(ctx, op.ID); rErr == nil && ok {
		resp.Result = res
	}
	if op.ApprovalID != "" {
		if app, _, err := s.store.GetApproval(ctx, op.ApprovalID); err == nil {
			resp.ApprovalExpires = app.ExpiresAtUTC
			resp.Reviewer = app.Reviewer
			resp.ReviewerNote = app.ReviewerNote
			resp.ApprovalURL = app.ExternalTicketURL
		}
	}
	return resp, nil
}

// CancelOperation cancels a waiting approval or an actively running execution (locally or across nodes).
func (s *Service) CancelOperation(ctx context.Context, opID, actor string) (types.ExecResponse, error) {
	op, err := s.store.GetOperation(ctx, opID)
	if err != nil {
		return types.ExecResponse{}, err
	}
	if s.IsServerMode() {
		p := rbac.PrincipalFromContext(ctx)
		if authErr := rbac.Authorize(p, rbac.ActionOperationCancel, rbac.ResourceScope{
			SystemID:        op.SystemID,
			SystemSlug:      op.SystemSlug,
			EnvironmentCode: op.EnvironmentCode,
			OwnerUserID:     op.OwnerUserID,
		}); authErr != nil {
			return types.ExecResponse{}, &TargetLookupError{
				Code:    types.ErrCodeForbidden,
				Message: authErr.Error(),
			}
		}
		actor = p.Subject
	}
	if op.ApprovalID != "" && op.Status == types.OpWaitingApproval {
		_, _ = s.approvals.Cancel(ctx, op.ApprovalID, actor)
		deadline := time.Now().Add(500 * time.Millisecond)
		for time.Now().Before(deadline) {
			cur, getErr := s.store.GetOperation(ctx, opID)
			if getErr == nil && cur.Status != types.OpWaitingApproval {
				break
			}
			time.Sleep(15 * time.Millisecond)
		}
	}
	if s.IsServerMode() && op.Status == types.OpRunning {
		_ = s.store.RequestOperationCancel(ctx, opID)
		if s.bus != nil {
			_ = s.bus.Publish(ctx, Event{Type: "operation_cancel", Data: map[string]string{"operation_id": opID}})
		}
	}
	s.opMu.Lock()
	cancelFn := s.opActive[opID]
	s.opMu.Unlock()
	if cancelFn != nil {
		cancelFn()
	}
	return s.GetOperationStatus(ctx, opID)
}

func (s *Service) registerOpWaiter(opID string) chan types.ExecResponse {
	ch := make(chan types.ExecResponse, 1)
	s.opMu.Lock()
	s.opWaiters[opID] = ch
	s.opMu.Unlock()
	return ch
}

func (s *Service) notifyOpWaiter(opID string, resp types.ExecResponse) {
	s.opMu.Lock()
	ch, ok := s.opWaiters[opID]
	if ok {
		delete(s.opWaiters, opID)
	}
	s.opMu.Unlock()
	if ok {
		select {
		case ch <- resp:
		default:
		}
		close(ch)
	}
}

func (s *Service) clearOpWaiter(opID string) {
	s.opMu.Lock()
	if ch, ok := s.opWaiters[opID]; ok {
		delete(s.opWaiters, opID)
		close(ch)
	}
	s.opMu.Unlock()
}

func (s *Service) setOpCancel(opID string, fn context.CancelFunc) {
	s.opMu.Lock()
	s.opActive[opID] = fn
	s.opMu.Unlock()
}

func (s *Service) clearOpCancel(opID string) {
	s.opMu.Lock()
	delete(s.opActive, opID)
	s.opMu.Unlock()
}

func (s *Service) responseFromOperation(op types.Operation, eval types.PolicyEvaluation) types.ExecResponse {
	return types.ExecResponse{
		OperationID:     op.ID,
		Status:          op.Status,
		TargetRef:       op.TargetRef,
		SystemSlug:      op.SystemSlug,
		EnvironmentCode: op.EnvironmentCode,
		Engine:          op.Engine,
		CredentialMode:  op.CredentialMode,
		Classification:  op.Classification,
		Preflight:       op.Preflight,
		Evaluation:      eval,
		ApprovalID:      op.ApprovalID,
		ErrorCode:       op.ErrorCode,
		ErrorMessage:    op.ErrorMessage,
		Retryable:       op.Retryable,
		CreatedAtUTC:    op.CreatedAtUTC,
		CompletedAtUTC:  op.CompletedAtUTC,
	}
}

func buildExecResponseSkeleton(detail types.TargetDetail, cls types.Classification, pf *types.PreflightReport, eval types.PolicyEvaluation, status types.OperationStatus) types.ExecResponse {
	sysSlug := ""
	if detail.OwnerSystem != nil {
		sysSlug = detail.OwnerSystem.Slug
	}
	eng := ""
	if detail.Instance != nil {
		eng = detail.Instance.Engine
	}
	return types.ExecResponse{
		Status:          status,
		TargetRef:       detail.Target.Ref,
		SystemSlug:      sysSlug,
		EnvironmentCode: detail.Target.EnvironmentCode,
		Engine:          eng,
		CredentialMode:  eval.CredentialMode,
		Classification:  cls,
		Preflight:       pf,
		Evaluation:      eval,
		ErrorCode:       eval.DenyCode,
		ErrorMessage:    eval.DenyMessage,
	}
}

// TestRiskPattern evaluates a query offline against active target/engine policy and optional draft pattern rule.
func (s *Service) TestRiskPattern(ctx context.Context, req types.PatternTestRequest) (types.PatternTestResult, error) {
	if strings.TrimSpace(req.Query) == "" {
		return types.PatternTestResult{}, fmt.Errorf("query is required")
	}
	if req.DraftRule != nil {
		draft := *req.DraftRule
		if draft.ScopeType == "" {
			draft.ScopeType = "global"
			draft.ScopeID = "global"
		}
		if err := policy.ValidateRiskPatternRule(draft); err != nil {
			return types.PatternTestResult{}, fmt.Errorf("invalid draft_rule: %w", err)
		}
	}

	var tgt types.Target
	var eff types.EffectivePolicy
	engine := strings.TrimSpace(req.Engine)
	if strings.TrimSpace(req.TargetID) != "" {
		detail, err := s.ResolveTarget(ctx, req.TargetID, "")
		if err != nil {
			return types.PatternTestResult{}, err
		}
		if s.IsServerMode() {
			if authErr := rbac.Authorize(rbac.PrincipalFromContext(ctx), rbac.ActionCatalogRead, scopeForTarget(detail)); authErr != nil {
				return types.PatternTestResult{}, authErr
			}
		}
		tgt = detail.Target
		eff = detail.EffectivePolicy
		if detail.Instance != nil {
			engine = detail.Instance.Engine
		}
	} else {
		if s.IsServerMode() {
			if authErr := rbac.Authorize(rbac.PrincipalFromContext(ctx), rbac.ActionCatalogRead, rbac.ResourceScope{}); authErr != nil {
				return types.PatternTestResult{}, authErr
			}
		}
		if engine == "" {
			engine = "postgres"
		}
		tier := req.SafetyTier
		if tier == "" {
			tier = types.SafetyTierGuarded
		}
		globalCfg, err := s.store.GetGlobalSecurityConfig(ctx)
		if err != nil {
			globalCfg = types.GlobalSecurityConfig{
				ExecTimeoutSec:          15,
				ApprovalTimeoutSec:      120,
				MaxRows:                 200,
				MaxBytes:                262144,
				ExplainMaxRows:           100000,
				DefaultApprovalProvider:  "local-web",
				RequireReasonForApproval: true,
			}
		}
		env := &types.Environment{Code: string(tier), SafetyTier: tier}
		tgt = types.Target{Ref: "sandbox/test", EnvironmentCode: env.Code, Status: types.TargetActive}
		eff = policy.ResolveEffectivePolicy(globalCfg, env, nil, tgt, nil)
		allRules, err := s.store.ListRiskPatternRules(ctx)
		if err == nil {
			eff.PatternRules = policy.ResolveEffectivePatternRules(env, nil, tgt, engine, classify.EngineFamily(engine), allRules)
		}
	}

	var cls types.Classification
	if drv, ok := s.drivers.Get(engine); ok {
		var err error
		cls, err = drv.Classify(ctx, req.Query)
		if err != nil {
			cls = classify.Classify(engine, req.Query)
		}
	} else {
		cls = classify.Classify(engine, req.Query)
	}

	var draftMatched *types.MatchedRule
	if req.DraftRule != nil {
		draft := *req.DraftRule
		if draft.ID == "" {
			draft.ID = "pat_draft"
		}
		draft.Enabled = true
		dm, _ := policy.MatchPatternRules([]types.RiskPatternRule{draft}, cls, req.SimulatedPreflight, req.Query)
		if len(dm) > 0 {
			dmCopy := dm[0]
			draftMatched = &dmCopy
		}
		eff.PatternRules = append([]types.RiskPatternRule{draft}, eff.PatternRules...)
	}

	eval := policy.EvaluateQuery(tgt, eff, cls, req.SimulatedPreflight, req.Query)
	_, qctx := policy.MatchPatternRules(nil, cls, req.SimulatedPreflight, req.Query)
	return types.PatternTestResult{
		Classification:  cls,
		Evaluation:      eval,
		MatchedRules:    eval.MatchedRules,
		DraftMatched:    draftMatched,
		NormalizedQuery: qctx.NormalizedNoLit,
		Extracted: types.PatternTestExtracted{
			Functions:      qctx.Functions,
			Tables:         qctx.Tables,
			Pragmas:        qctx.Pragmas,
			MongoOperators: qctx.MongoOperators,
		},
	}, nil
}

// WriteJSON helper ensures compact consistent serialization.
func WriteJSON(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}

func (s *Service) effectiveActor(ctx context.Context, reqActor string) string {
	p := rbac.PrincipalFromContext(ctx)
	if s.IsServerMode() {
		return p.Subject
	}
	if strings.TrimSpace(reqActor) != "" {
		return strings.TrimSpace(reqActor)
	}
	if p.Kind != types.PrincipalLocalOwner && p.Subject != "" {
		return p.Subject
	}
	return "agent-cli"
}

func scopeForTarget(d types.TargetDetail) rbac.ResourceScope {
	sysSlug := ""
	if d.OwnerSystem != nil {
		sysSlug = d.OwnerSystem.Slug
	}
	return rbac.ResourceScope{
		SystemID:        d.Target.OwnerSystemID,
		SystemSlug:      sysSlug,
		LinkedSystemIDs: d.Target.LinkedSystemIDs,
		EnvironmentCode: d.Target.EnvironmentCode,
	}
}

func minPositive(req, ceiling int) int {
	if req <= 0 || req > ceiling {
		return ceiling
	}
	return req
}

func minPositiveInt64(req, ceiling int64) int64 {
	if req <= 0 || req > ceiling {
		return ceiling
	}
	return req
}
