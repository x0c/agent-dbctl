package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/x0c/agent-dbctl/internal/approval"
	"github.com/x0c/agent-dbctl/internal/audit"
	"github.com/x0c/agent-dbctl/internal/classify"
	"github.com/x0c/agent-dbctl/internal/config"
	"github.com/x0c/agent-dbctl/internal/driver"
	"github.com/x0c/agent-dbctl/internal/driver/builtin"
	drvplugin "github.com/x0c/agent-dbctl/internal/driver/plugin"
	"github.com/x0c/agent-dbctl/internal/netdial"
	"github.com/x0c/agent-dbctl/internal/policy"
	"github.com/x0c/agent-dbctl/internal/secrets"
	"github.com/x0c/agent-dbctl/internal/store"
	"github.com/x0c/agent-dbctl/internal/types"
)

// Identity identifies the running daemon process so CLIs detect stale versions cleanly.
type Identity struct {
	Version    string `json:"version"`
	Commit     string `json:"commit"`
	PID        int    `json:"pid"`
	Session    string `json:"session"`
	ConfigHome string `json:"config_home"`
	WebURL     string `json:"web_url"`
	StartedAt  string `json:"started_at_utc"`
}

// Event is pushed over SSE to live Web Console subscribers.
type Event struct {
	Type string `json:"type"`
	Data any    `json:"data,omitempty"`
}

// Service owns all local daemon business orchestration.
type Service struct {
	paths     config.Paths
	store     *store.Store
	secrets   secrets.Store
	drivers   *driver.Registry
	plugins   *drvplugin.Manager
	approvals *approval.Manager
	localWeb  *approval.LocalWebProvider
	slots     *audit.ResultSlotStore
	identity  Identity

	rootCtx    context.Context
	cancelRoot context.CancelFunc
	wg         sync.WaitGroup

	opMu      sync.Mutex
	opWaiters map[string]chan types.ExecResponse
	opActive  map[string]context.CancelFunc

	sseMu   sync.Mutex
	sseSubs map[chan Event]struct{}
}

// NewService wires up Store, Secrets, Drivers, Plugins, Approvals, and ResultSlots.
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

	slots := audit.NewResultSlotStore(10 * time.Minute)
	appMgr := approval.NewManager(st)

	rootCtx, cancelRoot := context.WithCancel(context.Background())
	svc := &Service{
		paths:   paths,
		store:   st,
		secrets: sec,
		drivers: reg,
		plugins: pm,
		approvals: appMgr,
		slots:   slots,
		identity: Identity{
			Version:    version,
			Commit:     commit,
			PID:        os.Getpid(),
			Session:    paths.Session,
			ConfigHome: paths.ConfigHome,
			StartedAt:  time.Now().UTC().Format(time.RFC3339),
		},
		rootCtx:    rootCtx,
		cancelRoot: cancelRoot,
		opWaiters:  make(map[string]chan types.ExecResponse),
		opActive:   make(map[string]context.CancelFunc),
		sseSubs:    make(map[chan Event]struct{}),
	}

	lw := approval.NewLocalWebProvider(func(approvalID string) {
		svc.broadcast(Event{Type: "approval_created", Data: map[string]string{"approval_id": approvalID}})
	})
	svc.localWeb = lw
	appMgr.RegisterProvider(lw)

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

// Shutdown gracefully stops background workers, slots, approvals, plugins, and SQLite.
func (s *Service) Shutdown() {
	s.cancelRoot()
	s.approvals.Shutdown()
	s.wg.Wait()
	s.slots.Wait()
	s.plugins.Shutdown()
	_ = s.store.Close()
}

func (s *Service) subscribeSSE() chan Event {
	ch := make(chan Event, 32)
	s.sseMu.Lock()
	s.sseSubs[ch] = struct{}{}
	s.sseMu.Unlock()
	return ch
}

func (s *Service) unsubscribeSSE(ch chan Event) {
	s.sseMu.Lock()
	delete(s.sseSubs, ch)
	s.sseMu.Unlock()
	close(ch)
}

func (s *Service) broadcast(ev Event) {
	s.sseMu.Lock()
	defer s.sseMu.Unlock()
	for ch := range s.sseSubs {
		select {
		case ch <- ev:
		default:
		}
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
		Engines: engineItems,
		ApprovalProviders: []types.DisplayMetaItem{
			{Code: "local-web", Labels: map[string]string{"en": "Local Web Popup", "zh": "本机 Web 弹窗确认"}, Color: "#2563EB", Order: 10},
		},
	}, nil
}

func (s *Service) openDriverConn(ctx context.Context, detail types.TargetDetail, credMode types.AccessLevel, preferReplica bool) (driver.Conn, error) {
	if detail.Instance == nil {
		return nil, fmt.Errorf("target %q references missing instance", detail.Target.Ref)
	}
	inst := *detail.Instance
	// Route read-only queries to replica instance if configured.
	if preferReplica && inst.Role == types.RolePrimary {
		allInsts, err := s.store.ListInstances(ctx)
		if err == nil {
			for _, candidate := range allInsts {
				if candidate.PrimaryInstanceID == inst.ID && candidate.Role == types.RoleReplica {
					inst = candidate
					break
				}
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
		resolvedCred, err = secrets.ResolveCredential(ctx, s.secrets, chosenCred)
		if err != nil {
			return nil, err
		}
	}

	var bastionCred secrets.ResolvedSecret
	if detail.NetworkProfile != nil && detail.NetworkProfile.BastionCredentialID != "" {
		creds, err := s.store.ListCredentialProfiles(ctx)
		if err == nil {
			for _, cp := range creds {
				if cp.ID == detail.NetworkProfile.BastionCredentialID {
					bastionCred, err = secrets.ResolveCredential(ctx, s.secrets, &cp)
					if err != nil {
						return nil, fmt.Errorf("resolve bastion credential: %w", err)
					}
					break
				}
			}
		}
	}

	dialRes, err := netdial.Build(detail.NetworkProfile, bastionCred, inst.TLSMode, inst.Host)
	if err != nil {
		return nil, err
	}

	conn, err := drv.Open(ctx, driver.ConnectionConfig{
		Engine:       inst.Engine,
		Host:         inst.Host,
		Port:         inst.Port,
		DatabaseName: detail.Target.DatabaseName,
		Params:       inst.Params,
		ReadOnly:     readOnly,
		Credential:   resolvedCred,
		DialContext:  dialRes.DialContext,
		TLSConfig:    dialRes.TLSConfig,
		CloseHook:    dialRes.Close,
	})
	if err != nil {
		_ = dialRes.Close()
		return nil, err
	}
	return conn, nil
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
		res.Error = err.Error()
		return res
	}
	defer func() { _ = conn.Close() }()

	pingOut, err := conn.Ping(connCtx)
	res.ServerVersion = pingOut.ServerVersion
	res.LatencyMs = pingOut.LatencyMs
	if err != nil {
		res.Reachable = false
		res.Error = err.Error()
		return res
	}
	res.Reachable = pingOut.Reachable
	res.Error = pingOut.Error
	return res
}

// PingInstance tests an instance directly and discovers databases on it.
func (s *Service) PingInstance(ctx context.Context, instanceID, credID, dbName string) (types.PingResult, error) {
	inst, err := s.store.GetInstance(ctx, instanceID)
	if err != nil {
		return types.PingResult{}, err
	}
	detail := types.TargetDetail{
		Target:   types.Target{Ref: inst.Name, DatabaseName: dbName, ROCredentialID: credID},
		Instance: &inst,
	}
	if inst.NetworkProfileID != "" {
		nets, _ := s.store.ListNetworkProfiles(ctx)
		for _, np := range nets {
			if np.ID == inst.NetworkProfileID {
				npCopy := np
				detail.NetworkProfile = &npCopy
				break
			}
		}
	}
	if credID != "" {
		creds, _ := s.store.ListCredentialProfiles(ctx)
		for _, cp := range creds {
			if cp.ID == credID {
				cpCopy := cp
				detail.ROCredential = &cpCopy
				break
			}
		}
	}
	return s.PingTarget(ctx, detail), nil
}

// DiscoverInstance enumerates logical databases/schemas on an instance.
func (s *Service) DiscoverInstance(ctx context.Context, instanceID, credID, dbName string) ([]string, error) {
	inst, err := s.store.GetInstance(ctx, instanceID)
	if err != nil {
		return nil, err
	}
	detail := types.TargetDetail{
		Target:   types.Target{Ref: inst.Name, DatabaseName: dbName, ROCredentialID: credID},
		Instance: &inst,
	}
	if inst.NetworkProfileID != "" {
		nets, _ := s.store.ListNetworkProfiles(ctx)
		for _, np := range nets {
			if np.ID == inst.NetworkProfileID {
				npCopy := np
				detail.NetworkProfile = &npCopy
				break
			}
		}
	}
	if credID != "" {
		creds, _ := s.store.ListCredentialProfiles(ctx)
		for _, cp := range creds {
			if cp.ID == credID {
				cpCopy := cp
				detail.ROCredential = &cpCopy
				break
			}
		}
	}
	connCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	conn, err := s.openDriverConn(connCtx, detail, types.AccessReadOnly, false)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()
	return conn.ListDatabases(connCtx)
}

// Execute runs the full dry-run / preflight / policy / approval / driver execution pipeline.
func (s *Service) Execute(ctx context.Context, req types.ExecRequest) (types.ExecResponse, error) {
	detail, err := s.ResolveTarget(ctx, req.TargetRefOrAlias, req.WorkspaceCWD)
	if err != nil {
		return types.ExecResponse{}, err
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

	// 1. Offline Dry-Run: strictly zero DB dial, zero approval, zero business mutation.
	if req.DryRun {
		eval := policy.Evaluate(detail.Target, eff, cls, nil)
		return buildExecResponseSkeleton(detail, cls, nil, eval, types.OpPending), nil
	}

	// 2. Remote Read-Only Preflight (non-mutating EXPLAIN, zero approval popup).
	var pf *types.PreflightReport
	if req.Preflight || (eff.SafetyTier != types.SafetyTierYOLO && cls.IsReadOnly && cls.RiskLevel == types.RiskSafeRead) {
		pfCtx, cancel := context.WithTimeout(ctx, time.Duration(minPositive(req.TimeoutSec, eff.ExecTimeoutSec))*time.Second)
		conn, openErr := s.openDriverConn(pfCtx, detail, types.AccessReadOnly, true)
		if openErr == nil {
			pf, _ = driver.ExecuteWithCancelGuard(pfCtx, conn, func(cctx context.Context) (*types.PreflightReport, error) {
				return conn.Preflight(cctx, req.Query, driver.PreflightOpts{})
			})
			_ = conn.Close()
		} else if req.Preflight {
			cancel()
			return types.ExecResponse{}, openErr
		}
		cancel()
	}

	eval := policy.Evaluate(detail.Target, eff, cls, pf)
	if req.Preflight {
		return buildExecResponseSkeleton(detail, cls, pf, eval, types.OpPending), nil
	}

	globalCfg, _ := s.store.GetGlobalSecurityConfig(ctx)
	redacted := req.Query
	if globalCfg.RedactAuditLiterals {
		redacted = audit.RedactQuery(req.Query)
	}
	actor := req.Actor
	if actor == "" {
		actor = "agent-cli"
	}

	sysID, sysSlug := detail.Target.OwnerSystemID, ""
	if detail.OwnerSystem != nil {
		sysSlug = detail.OwnerSystem.Slug
	}

	op := types.Operation{
		TargetID:        detail.Target.ID,
		TargetRef:       detail.Target.Ref,
		SystemID:        sysID,
		SystemSlug:      sysSlug,
		EnvironmentCode: detail.Target.EnvironmentCode,
		Engine:          engine,
		Actor:           actor,
		Reason:          req.Reason,
		WorkspaceCWD:    req.WorkspaceCWD,
		QueryText:       req.Query,
		QueryRedacted:   redacted,
		RiskLevel:       cls.RiskLevel,
		Decision:        eval.Decision,
		TriggerReasons:  eval.TriggerReasons,
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
		app, appURL, subErr := s.approvals.Submit(ctx, eff.ApprovalProvider, op, detail, eff.ApprovalTimeoutSec)
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
		s.wg.Add(1)
		go func(opSnapshot types.Operation, targetDetail types.TargetDetail, evaluation types.PolicyEvaluation, approvalID string, maxR int, maxB int64, tSec int) {
			defer s.wg.Done()
			s.driveApprovalLifecycle(opSnapshot, targetDetail, evaluation, approvalID, maxR, maxB, tSec)
		}(op, detail, eval, app.ID, req.MaxRows, req.MaxBytes, req.TimeoutSec)

		if !req.Wait {
			resp := s.responseFromOperation(op, eval)
			resp.ApprovalURL = appURL
			resp.ApprovalExpires = app.ExpiresAtUTC
			resp.ErrorCode = types.ErrCodeWaitingApproval
			resp.ErrorMessage = fmt.Sprintf("Execution requires human approval (%s).", strings.Join(eval.TriggerReasons, ", "))
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
	resp := s.runExecution(ctx, op, detail, eval, req.MaxRows, req.MaxBytes, req.TimeoutSec)
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
	eff := eval.EffectivePolicy
	timeoutSec := minPositive(reqTimeout, eff.ExecTimeoutSec)
	maxRows := minPositive(reqMaxRows, eff.MaxRows)
	maxBytes := minPositiveInt64(reqMaxBytes, eff.MaxBytes)

	op.Status = types.OpRunning
	op, _ = s.store.UpdateOperation(parentCtx, op.Actor, "operation.running", op)
	s.broadcast(Event{Type: "operation_updated", Data: op})

	execCtx, cancel := context.WithTimeout(parentCtx, time.Duration(timeoutSec)*time.Second)
	s.setOpCancel(op.ID, cancel)
	defer func() {
		cancel()
		s.clearOpCancel(op.ID)
	}()

	conn, err := s.openDriverConn(execCtx, detail, eval.CredentialMode, eval.PreferReplica)
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
	op, _ = s.store.UpdateOperation(context.Background(), op.Actor, "operation.succeeded", op)
	s.slots.Put(op.ID, res)
	s.broadcast(Event{Type: "operation_updated", Data: op})

	resp := s.responseFromOperation(op, eval)
	resp.Result = res
	return resp
}

// ResolveApproval approves or rejects a pending approval ticket from the Web UI.
func (s *Service) ResolveApproval(ctx context.Context, approvalID string, approve bool, reviewer, note, token string, trustedUISession bool) (types.ApprovalRequest, error) {
	app, err := s.approvals.Resolve(ctx, approvalID, approve, reviewer, note, token, trustedUISession)
	if err != nil {
		return app, err
	}
	s.broadcast(Event{Type: "approval_resolved", Data: app})
	return app, nil
}

// GetOperationStatus retrieves operation state plus cached in-memory ResultSlot if available.
func (s *Service) GetOperationStatus(ctx context.Context, opID string) (types.ExecResponse, error) {
	op, err := s.store.GetOperation(ctx, opID)
	if err != nil {
		return types.ExecResponse{}, err
	}
	eval := types.PolicyEvaluation{
		Decision:       op.Decision,
		TriggerReasons: op.TriggerReasons,
		CredentialMode: op.CredentialMode,
	}
	resp := s.responseFromOperation(op, eval)
	if res, ok := s.slots.Get(op.ID); ok {
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

// CancelOperation cancels a waiting approval or an actively running execution.
func (s *Service) CancelOperation(ctx context.Context, opID, actor string) (types.ExecResponse, error) {
	op, err := s.store.GetOperation(ctx, opID)
	if err != nil {
		return types.ExecResponse{}, err
	}
	if op.ApprovalID != "" && op.Status == types.OpWaitingApproval {
		_, _ = s.approvals.Cancel(ctx, op.ApprovalID, actor)
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

// WriteJSON helper ensures compact consistent serialization.
func WriteJSON(v any) []byte {
	b, _ := json.Marshal(v)
	return b
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
