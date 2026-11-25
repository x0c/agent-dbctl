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
	TargetRefOrAlias    string   `json:"target"`
	Query               string   `json:"query"`
	Reason              string   `json:"reason,omitempty"`
	Actor               string   `json:"actor,omitempty"`
	WorkspaceCWD        string   `json:"workspace_cwd,omitempty"`
	WorkspaceGitRemotes []string `json:"workspace_git_remotes,omitempty"`
	DryRun              bool     `json:"dry_run,omitempty"`
	Preflight           bool     `json:"preflight,omitempty"`
	MaxRows             int      `json:"max_rows,omitempty"`
	MaxBytes            int64    `json:"max_bytes,omitempty"`
	TimeoutSec          int      `json:"timeout_sec,omitempty"`
	Wait                bool     `json:"wait"`
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
	Engine               string            `json:"engine"`
	Actor                string            `json:"actor"`
	PrincipalID          string            `json:"principal_id,omitempty"`
	PrincipalKind        PrincipalKind     `json:"principal_kind,omitempty"`
	OwnerUserID          string            `json:"owner_user_id,omitempty"`
	OwnerNodeID          string            `json:"owner_node_id,omitempty"`
	LeaseExpiresAtUTC    string            `json:"lease_expires_at_utc,omitempty"`
	CancelRequestedAtUTC string            `json:"cancel_requested_at_utc,omitempty"`
	Reason               string            `json:"reason,omitempty"`
	WorkspaceCWD    string            `json:"workspace_cwd,omitempty"`
	QueryText       string            `json:"query_text"`
	QueryRedacted   string            `json:"query_redacted"`
	RiskLevel       RiskLevel         `json:"risk_level"`
	Decision        Decision          `json:"decision"`
	TriggerReasons  []string          `json:"trigger_reasons,omitempty"`
	MatchedRules    []MatchedRule     `json:"matched_rules,omitempty"`
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
	PrincipalID       string           `json:"principal_id,omitempty"`
	Reason            string           `json:"reason,omitempty"`
	WorkspaceCWD      string           `json:"workspace_cwd,omitempty"`
	QueryText         string           `json:"query_text"`
	RiskLevel         RiskLevel        `json:"risk_level"`
	TriggerReasons    []string         `json:"trigger_reasons,omitempty"`
	MatchedRules      []MatchedRule    `json:"matched_rules,omitempty"`
	Preflight         *PreflightReport `json:"preflight,omitempty"`
	Reviewer          string           `json:"reviewer,omitempty"`
	ReviewerUserID    string           `json:"reviewer_user_id,omitempty"`
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

// ServerCapabilities describes negotiated dialect and feature flags detected from a live server.
type ServerCapabilities struct {
	Engine                   string `json:"engine"`
	Dialect                  string `json:"dialect"`
	ServerVersion            string `json:"server_version,omitempty"`
	MajorVersion             int    `json:"major_version,omitempty"`
	MinorVersion             int    `json:"minor_version,omitempty"`
	ExplainFormat            string `json:"explain_format,omitempty"`
	SupportsExplain          bool   `json:"supports_explain"`
	SupportsExplainJSON      bool   `json:"supports_explain_json"`
	SupportsReadOnlySession  bool   `json:"supports_read_only_session"`
	SupportsCancelQuery      bool   `json:"supports_cancel_query"`
	SupportsReturning        bool   `json:"supports_returning"`
	SupportsRESP3            bool   `json:"supports_resp3,omitempty"`
	ClusterMode              bool   `json:"cluster_mode,omitempty"`
	SupportsAuthorizedDBList bool   `json:"supports_authorized_db_list,omitempty"`
	DetectedAtUTC            string `json:"detected_at_utc,omitempty"`
}

// PingResult reports database connectivity probe outcome.
type PingResult struct {
	TargetRef     string              `json:"target_ref"`
	InstanceID    string              `json:"instance_id"`
	Engine        string              `json:"engine"`
	Dialect       string              `json:"dialect,omitempty"`
	Role          string              `json:"role"`
	Reachable     bool                `json:"reachable"`
	ServerVersion string              `json:"server_version,omitempty"`
	Capabilities  *ServerCapabilities `json:"capabilities,omitempty"`
	LatencyMs     int64               `json:"latency_ms"`
	Error         string              `json:"error,omitempty"`
}

// SchemaObjectSummary describes one table, view, collection, or Redis key-prefix pattern.
type SchemaObjectSummary struct {
	Schema        string `json:"schema,omitempty"`
	Name          string `json:"name"`
	Type          string `json:"type"`
	Engine        string `json:"engine,omitempty"`
	EstimatedRows *int64 `json:"estimated_rows,omitempty"`
	SampleCount   int    `json:"sample_count,omitempty"`
}

// SchemaListResult is returned by `db schema <ref>`.
type SchemaListResult struct {
	TargetRef     string                `json:"target_ref,omitempty"`
	Engine        string                `json:"engine"`
	Dialect       string                `json:"dialect,omitempty"`
	Database      string                `json:"database,omitempty"`
	Items         []SchemaObjectSummary `json:"items"`
	TotalCount    int                   `json:"total_count"`
	ReturnedCount int                   `json:"returned_count"`
	Truncated     bool                  `json:"truncated"`
	Notes         []string              `json:"notes,omitempty"`
}

// SchemaColumn describes a SQL column.
type SchemaColumn struct {
	Name       string `json:"name"`
	Type       string `json:"type"`
	Nullable   bool   `json:"nullable"`
	PrimaryKey bool   `json:"primary_key,omitempty"`
	Default    string `json:"default,omitempty"`
	Extra      string `json:"extra,omitempty"`
}

// SchemaIndex describes an index on a SQL table or MongoDB collection.
type SchemaIndex struct {
	Name    string   `json:"name"`
	Columns []string `json:"columns,omitempty"`
	Unique  bool     `json:"unique,omitempty"`
	Primary bool     `json:"primary,omitempty"`
}

// SchemaForeignKey describes a SQL foreign key constraint.
type SchemaForeignKey struct {
	Column           string `json:"column"`
	ReferencedTable  string `json:"referenced_table"`
	ReferencedColumn string `json:"referenced_column"`
}

// SchemaSampleField summarizes a field name and observed types in a document collection.
type SchemaSampleField struct {
	Name  string   `json:"name"`
	Types []string `json:"types"`
}

// RedisKeySample summarizes a sampled Redis/Valkey key.
type RedisKeySample struct {
	Key  string `json:"key"`
	Type string `json:"type"`
	TTL  int64  `json:"ttl_sec"`
}

// TableSchema describes one table, view, collection, or key pattern (`db schema <ref> <name>`).
type TableSchema struct {
	TargetRef    string              `json:"target_ref,omitempty"`
	Engine       string              `json:"engine"`
	Dialect      string              `json:"dialect,omitempty"`
	Database     string              `json:"database,omitempty"`
	Schema       string              `json:"schema,omitempty"`
	Name         string              `json:"name"`
	ObjectType   string              `json:"object_type"`
	Columns      []SchemaColumn      `json:"columns,omitempty"`
	Indexes      []SchemaIndex       `json:"indexes,omitempty"`
	ForeignKeys  []SchemaForeignKey  `json:"foreign_keys,omitempty"`
	SampleFields []SchemaSampleField `json:"sample_fields,omitempty"`
	KeySamples   []RedisKeySample    `json:"key_samples,omitempty"`
	Notes        []string            `json:"notes,omitempty"`
}

// ExecCompactOutcome is the lean default JSON payload for successful `exec` / `op status` / `op wait` calls.
type ExecCompactOutcome struct {
	OperationID     string           `json:"operation_id"`
	Status          OperationStatus  `json:"status"`
	TargetRef       string           `json:"target_ref"`
	EnvironmentCode string           `json:"environment_code"`
	Engine          string           `json:"engine"`
	CredentialMode  AccessLevel      `json:"credential_mode"`
	RiskLevel       RiskLevel        `json:"risk_level"`
	Family          EngineFamily     `json:"family,omitempty"`
	Columns         []Column         `json:"columns,omitempty"`
	Rows            [][]any          `json:"rows,omitempty"`
	Records         []map[string]any `json:"records,omitempty"`
	Documents       []any            `json:"documents,omitempty"`
	KVResult        any              `json:"kv_result,omitempty"`
	RawText         string           `json:"raw_text,omitempty"`
	AffectedRows    *int64           `json:"affected_rows,omitempty"`
	FetchedRows     int              `json:"fetched_rows"`
	ReturnedRows    int              `json:"returned_rows"`
	ReturnedBytes   int64            `json:"returned_bytes,omitempty"`
	Truncated       bool             `json:"truncated"`
	CutoffReason    string           `json:"cutoff_reason,omitempty"`
	Messages        []string         `json:"messages,omitempty"`
	LatencyMs       int64            `json:"latency_ms"`
	Reviewer        string           `json:"reviewer,omitempty"`
	ReviewerNote    string           `json:"reviewer_note,omitempty"`
}
