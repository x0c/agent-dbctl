package types

// EngineFamily groups heterogeneous engines by result/wire shape.
type EngineFamily string

const (
	FamilySQL      EngineFamily = "sql"
	FamilyDocument EngineFamily = "document"
	FamilyKV       EngineFamily = "kv"
	FamilyRaw      EngineFamily = "raw"
)

// DriverMetadata describes a built-in or external plugin driver.
type DriverMetadata struct {
	ID              string       `json:"id"`
	Engine          string       `json:"engine"`
	DisplayName     string       `json:"display_name"`
	Family          EngineFamily `json:"family"`
	Tier            string       `json:"tier"` // builtin | plugin
	Version         string       `json:"version"`
	HostAPIVersion  int          `json:"host_api_version,omitempty"`
	Capabilities    []string     `json:"capabilities"`
	Verified        bool         `json:"verified"`
	VerificationErr string       `json:"verification_error,omitempty"`
	Labels          map[string]string `json:"labels,omitempty"`
}

// StatementSummary records one statement inside a possibly multi-statement input.
type StatementSummary struct {
	StatementType string    `json:"statement_type"`
	RiskLevel     RiskLevel `json:"risk_level"`
	Flags         []string  `json:"flags,omitempty"`
	Snippet       string    `json:"snippet,omitempty"`
}

// Classification captures static engine-aware risk analysis.
type Classification struct {
	Engine         string             `json:"engine"`
	Family         EngineFamily       `json:"family"`
	RiskLevel      RiskLevel          `json:"risk_level"`
	IsReadOnly     bool               `json:"is_read_only"`
	StatementCount int                `json:"statement_count"`
	Statements     []StatementSummary `json:"statements,omitempty"`
	RiskFlags      []string           `json:"risk_flags,omitempty"`
	Summary        string             `json:"summary"`
}

// PreflightReport contains non-mutating EXPLAIN / planner analysis.
type PreflightReport struct {
	Supported      bool           `json:"supported"`
	Executed       bool           `json:"executed"` // always false for safe preflight
	FullScan       bool           `json:"full_scan"`
	EstimatedRows  int64          `json:"estimated_rows"`
	Format         string         `json:"format,omitempty"`
	PlanSummary    string         `json:"plan_summary,omitempty"`
	PlanRaw        any            `json:"plan_raw,omitempty"`
	Warnings       []string       `json:"warnings,omitempty"`
}

// Column describes a tabular result column.
type Column struct {
	Name     string `json:"name"`
	TypeName string `json:"type_name"`
}

// ExecResult holds bounded verbatim execution output.
type ExecResult struct {
	Family        EngineFamily   `json:"family"`
	Columns       []Column       `json:"columns,omitempty"`
	Rows          [][]any        `json:"rows,omitempty"`
	Documents     []any          `json:"documents,omitempty"`
	KVResult      any            `json:"kv_result,omitempty"`
	RawText       string         `json:"raw_text,omitempty"`
	AffectedRows  *int64         `json:"affected_rows,omitempty"`
	FetchedRows   int            `json:"fetched_rows"`
	ReturnedRows  int            `json:"returned_rows"`
	ReturnedBytes int64          `json:"returned_bytes"`
	Truncated     bool           `json:"truncated"`
	CutoffReason  string         `json:"cutoff_reason,omitempty"`
	Messages      []string       `json:"messages,omitempty"`
	LatencyMs     int64          `json:"latency_ms"`
}

// OperationStatus tracks the execution & approval lifecycle.
type OperationStatus string

const (
	OpPending         OperationStatus = "pending"
	OpWaitingApproval OperationStatus = "waiting_approval"
	OpRunning         OperationStatus = "running"
	OpSucceeded       OperationStatus = "succeeded"
	OpFailed          OperationStatus = "failed"
	OpDenied          OperationStatus = "denied"
	OpRejected        OperationStatus = "rejected"
	OpExpired         OperationStatus = "expired"
	OpCancelled       OperationStatus = "cancelled"
	OpTimedOut        OperationStatus = "timed_out"
)

// ExecRequest represents a CLI/API execution submission.
type ExecRequest struct {
	TargetRefOrAlias string `json:"target"`
	Query            string `json:"query"`
	Reason           string `json:"reason,omitempty"`
	Actor            string `json:"actor,omitempty"`
	WorkspaceCWD     string `json:"workspace_cwd,omitempty"`
	DryRun           bool   `json:"dry_run,omitempty"`
	Preflight        bool   `json:"preflight,omitempty"`
	MaxRows          int    `json:"max_rows,omitempty"`
	MaxBytes         int64  `json:"max_bytes,omitempty"`
	TimeoutSec       int    `json:"timeout_sec,omitempty"`
	Wait             bool   `json:"wait"`
}

// ExecResponse is returned to the CLI for exec and op status calls.
type ExecResponse struct {
	OperationID     string            `json:"operation_id"`
	Status          OperationStatus   `json:"status"`
	TargetRef       string            `json:"target_ref"`
	SystemSlug      string            `json:"system_slug"`
	EnvironmentCode string            `json:"environment_code"`
	Engine          string            `json:"engine"`
	CredentialMode  AccessLevel       `json:"credential_mode"`
	Classification  Classification    `json:"classification"`
	Preflight       *PreflightReport  `json:"preflight,omitempty"`
	Evaluation      PolicyEvaluation  `json:"evaluation"`
	ApprovalID      string            `json:"approval_id,omitempty"`
	ApprovalURL     string            `json:"approval_url,omitempty"`
	ApprovalExpires string            `json:"approval_expires_at_utc,omitempty"`
	Reviewer        string            `json:"reviewer,omitempty"`
	ReviewerNote    string            `json:"reviewer_note,omitempty"`
	Result          *ExecResult       `json:"result,omitempty"`
	ErrorCode       string            `json:"error_code,omitempty"`
	ErrorMessage    string            `json:"error_message,omitempty"`
	Retryable       bool              `json:"retryable"`
	CreatedAtUTC    string            `json:"created_at_utc"`
	CompletedAtUTC  string            `json:"completed_at_utc,omitempty"`
}

// Operation is the persisted WAL state of an execution request.
type Operation struct {
	ID              string            `json:"id"`
	TargetID        string            `json:"target_id"`
	TargetRef       string            `json:"target_ref"`
	SystemID        string            `json:"system_id"`
	SystemSlug      string            `json:"system_slug"`
	EnvironmentCode string            `json:"environment_code"`
	Engine          string            `json:"engine"`
	Actor           string            `json:"actor"`
	Reason          string            `json:"reason,omitempty"`
	WorkspaceCWD    string            `json:"workspace_cwd,omitempty"`
	QueryText       string            `json:"query_text"`
	QueryRedacted   string            `json:"query_redacted"`
	RiskLevel       RiskLevel         `json:"risk_level"`
	Decision        Decision          `json:"decision"`
	TriggerReasons  []string          `json:"trigger_reasons,omitempty"`
	Classification  Classification    `json:"classification"`
	Preflight       *PreflightReport  `json:"preflight,omitempty"`
	Status          OperationStatus   `json:"status"`
	CredentialMode  AccessLevel       `json:"credential_mode"`
	ApprovalID      string            `json:"approval_id,omitempty"`
	FetchedRows     int               `json:"fetched_rows"`
	ReturnedRows    int               `json:"returned_rows"`
	AffectedRows    *int64            `json:"affected_rows,omitempty"`
	Truncated       bool              `json:"truncated"`
	CutoffReason    string            `json:"cutoff_reason,omitempty"`
	LatencyMs       int64             `json:"latency_ms"`
	ErrorCode       string            `json:"error_code,omitempty"`
	ErrorMessage    string            `json:"error_message,omitempty"`
	Retryable       bool              `json:"retryable"`
	CreatedAtUTC    string            `json:"created_at_utc"`
	UpdatedAtUTC    string            `json:"updated_at_utc"`
	CompletedAtUTC  string            `json:"completed_at_utc,omitempty"`
}

// ApprovalStatus tracks human approval workflow state.
type ApprovalStatus string

const (
	ApprovalPending   ApprovalStatus = "pending"
	ApprovalApproved  ApprovalStatus = "approved"
	ApprovalRejected  ApprovalStatus = "rejected"
	ApprovalExpired   ApprovalStatus = "expired"
	ApprovalCancelled ApprovalStatus = "cancelled"
)

// ApprovalRequest represents a pending or resolved approval ticket.
type ApprovalRequest struct {
	ID                string           `json:"id"`
	OperationID       string           `json:"operation_id"`
	Provider          string           `json:"provider"`
	ExternalTicketID  string           `json:"external_ticket_id,omitempty"`
	ExternalTicketURL string           `json:"external_ticket_url,omitempty"`
	Status            ApprovalStatus   `json:"status"`
	TargetRef         string           `json:"target_ref"`
	SystemSlug        string           `json:"system_slug"`
	EnvironmentCode   string           `json:"environment_code"`
	Engine            string           `json:"engine"`
	Actor             string           `json:"actor"`
	Reason            string           `json:"reason,omitempty"`
	WorkspaceCWD      string           `json:"workspace_cwd,omitempty"`
	QueryText         string           `json:"query_text"`
	RiskLevel         RiskLevel        `json:"risk_level"`
	TriggerReasons    []string         `json:"trigger_reasons,omitempty"`
	Preflight         *PreflightReport `json:"preflight,omitempty"`
	Reviewer          string           `json:"reviewer,omitempty"`
	ReviewerNote      string           `json:"reviewer_note,omitempty"`
	CreatedAtUTC      string           `json:"created_at_utc"`
	ExpiresAtUTC      string           `json:"expires_at_utc"`
	ResolvedAtUTC     string           `json:"resolved_at_utc,omitempty"`
}

// AuditEntry is an immutable append-only record in the SHA-256 hash chain.
type AuditEntry struct {
	Seq          int64  `json:"seq"`
	ID           string `json:"id"`
	Actor        string `json:"actor"`
	Action       string `json:"action"`
	TargetID     string `json:"target_id"`
	OperationID  string `json:"operation_id,omitempty"`
	PayloadJSON  string `json:"payload_json"`
	PrevHash     string `json:"prev_hash"`
	EntryHash    string `json:"entry_hash"`
	CreatedAtUTC string `json:"created_at_utc"`
}

// AuditVerifyResult summarizes hash-chain integrity verification.
type AuditVerifyResult struct {
	Valid         bool   `json:"valid"`
	CheckedCount  int64  `json:"checked_count"`
	FirstBrokenAt int64  `json:"first_broken_seq,omitempty"`
	Reason        string `json:"reason,omitempty"`
	LastHash      string `json:"last_hash,omitempty"`
}

// DisplayMetaItem delivers server-owned enum labels & colors to clients.
type DisplayMetaItem struct {
	Code   string            `json:"code"`
	Labels map[string]string `json:"labels"`
	Color  string            `json:"color"`
	Order  int               `json:"order"`
}

// DisplayCatalog groups all server-driven metadata catalogs.
type DisplayCatalog struct {
	CatalogVersion    int               `json:"catalog_version"`
	Environments      []DisplayMetaItem `json:"environments"`
	OperationStatuses []DisplayMetaItem `json:"operation_statuses"`
	RiskLevels        []DisplayMetaItem `json:"risk_levels"`
	Engines           []DisplayMetaItem `json:"engines"`
	ApprovalProviders []DisplayMetaItem `json:"approval_providers"`
}

// PingResult reports database connectivity probe outcome.
type PingResult struct {
	TargetRef     string `json:"target_ref"`
	InstanceID    string `json:"instance_id"`
	Engine        string `json:"engine"`
	Role          string `json:"role"`
	Reachable     bool   `json:"reachable"`
	ServerVersion string `json:"server_version,omitempty"`
	LatencyMs     int64  `json:"latency_ms"`
	Error         string `json:"error,omitempty"`
}
