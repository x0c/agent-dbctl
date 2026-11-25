package types

// SafetyTier controls baseline environment strictness.
type SafetyTier string

const (
	SafetyTierYOLO    SafetyTier = "yolo"
	SafetyTierGuarded SafetyTier = "guarded"
	SafetyTierStrict  SafetyTier = "strict"
)

// NetworkMode defines how a driver reaches a database host.
type NetworkMode string

const (
	NetworkDirect    NetworkMode = "direct"
	NetworkSSHTunnel NetworkMode = "ssh_tunnel"
	NetworkSOCKS5    NetworkMode = "socks5"
	NetworkHTTPProxy NetworkMode = "http_proxy"
)

// CredentialKind specifies where runtime credentials are resolved from.
type CredentialKind string

const (
	CredKeychain     CredentialKind = "keychain"
	CredEnvRef       CredentialKind = "env_ref"
	CredExecProvider CredentialKind = "exec_provider"
)

// AccessLevel classifies credential privilege intent.
type AccessLevel string

const (
	AccessReadOnly  AccessLevel = "read_only"
	AccessReadWrite AccessLevel = "read_write"
)

// InstanceRole marks primary/replica topology role.
type InstanceRole string

const (
	RolePrimary    InstanceRole = "primary"
	RoleReplica    InstanceRole = "replica"
	RoleStandalone InstanceRole = "standalone"
)

// TargetStatus governs whether a target accepts queries.
type TargetStatus string

const (
	TargetActive      TargetStatus = "active"
	TargetMaintenance TargetStatus = "maintenance"
	TargetDisabled    TargetStatus = "disabled"
)

// System represents a logical business system owning and linking databases.
type System struct {
	ID              string   `json:"id" yaml:"id"`
	Slug            string   `json:"slug" yaml:"slug"`
	Name            string   `json:"name" yaml:"name"`
	Owner           string   `json:"owner" yaml:"owner"`
	Description     string   `json:"description" yaml:"description"`
	Tags            []string `json:"tags" yaml:"tags"`
	WorkspacePaths  []string `json:"workspace_paths" yaml:"workspace_paths"`
	GitRemotes      []string `json:"git_remotes" yaml:"git_remotes"`
	DefaultPolicyID string   `json:"default_policy_id,omitempty" yaml:"default_policy_id,omitempty"`
	CreatedAtUTC    string   `json:"created_at_utc" yaml:"created_at_utc,omitempty"`
	UpdatedAtUTC    string   `json:"updated_at_utc" yaml:"updated_at_utc,omitempty"`
}

// Environment defines an operational environment tier.
type Environment struct {
	Code            string            `json:"code" yaml:"code"`
	SafetyTier      SafetyTier        `json:"safety_tier" yaml:"safety_tier"`
	Labels          map[string]string `json:"labels" yaml:"labels"`
	Color           string            `json:"color" yaml:"color"`
	SortOrder       int               `json:"sort_order" yaml:"sort_order"`
	DefaultPolicyID string            `json:"default_policy_id,omitempty" yaml:"default_policy_id,omitempty"`
	CreatedAtUTC    string            `json:"created_at_utc" yaml:"created_at_utc,omitempty"`
	UpdatedAtUTC    string            `json:"updated_at_utc" yaml:"updated_at_utc,omitempty"`
}

// NetworkProfile defines reusable connectivity settings (direct, bastion, proxy, TLS).
type NetworkProfile struct {
	ID                  string      `json:"id" yaml:"id"`
	Name                string      `json:"name" yaml:"name"`
	Mode                NetworkMode `json:"mode" yaml:"mode"`
	ProxyURL            string      `json:"proxy_url,omitempty" yaml:"proxy_url,omitempty"`
	BastionHost         string      `json:"bastion_host,omitempty" yaml:"bastion_host,omitempty"`
	BastionPort         int         `json:"bastion_port,omitempty" yaml:"bastion_port,omitempty"`
	BastionUser         string      `json:"bastion_user,omitempty" yaml:"bastion_user,omitempty"`
	BastionCredentialID string      `json:"bastion_credential_id,omitempty" yaml:"bastion_credential_id,omitempty"`
	SSHStrictHostKey    bool        `json:"ssh_strict_host_key" yaml:"ssh_strict_host_key"`
	TLSMode             string      `json:"tls_mode,omitempty" yaml:"tls_mode,omitempty"`
	CreatedAtUTC        string      `json:"created_at_utc" yaml:"created_at_utc,omitempty"`
	UpdatedAtUTC        string      `json:"updated_at_utc" yaml:"updated_at_utc,omitempty"`
}

// CredentialProfile references secrets stored outside SQLite (Keychain, env, exec).
type CredentialProfile struct {
	ID           string         `json:"id" yaml:"id"`
	Name         string         `json:"name" yaml:"name"`
	Kind         CredentialKind `json:"kind" yaml:"kind"`
	AccessLevel  AccessLevel    `json:"access_level" yaml:"access_level"`
	Username     string         `json:"username,omitempty" yaml:"username,omitempty"`
	EnvVarName   string         `json:"env_var_name,omitempty" yaml:"env_var_name,omitempty"`
	ExecCommand  string         `json:"exec_command,omitempty" yaml:"exec_command,omitempty"`
	HasSecret    bool           `json:"has_secret" yaml:"-"`
	CreatedAtUTC string         `json:"created_at_utc" yaml:"created_at_utc,omitempty"`
	UpdatedAtUTC string         `json:"updated_at_utc" yaml:"updated_at_utc,omitempty"`
}

// Instance represents a physical or clustered database endpoint.
type Instance struct {
	ID                     string              `json:"id" yaml:"id"`
	Name                   string              `json:"name" yaml:"name"`
	Engine                 string              `json:"engine" yaml:"engine"`
	Host                   string              `json:"host" yaml:"host"`
	Port                   int                 `json:"port" yaml:"port"`
	Role                   InstanceRole        `json:"role" yaml:"role"`
	PrimaryInstanceID      string              `json:"primary_instance_id,omitempty" yaml:"primary_instance_id,omitempty"`
	NetworkProfileID       string              `json:"network_profile_id,omitempty" yaml:"network_profile_id,omitempty"`
	TLSMode                string              `json:"tls_mode,omitempty" yaml:"tls_mode,omitempty"`
	Params                 map[string]string   `json:"params,omitempty" yaml:"params,omitempty"`
	Capabilities           *ServerCapabilities `json:"capabilities,omitempty" yaml:"-"`
	CapabilitiesDetectedAt string              `json:"capabilities_detected_at_utc,omitempty" yaml:"-"`
	CreatedAtUTC           string              `json:"created_at_utc" yaml:"created_at_utc,omitempty"`
	UpdatedAtUTC           string              `json:"updated_at_utc" yaml:"updated_at_utc,omitempty"`
}

// Target represents a logical addressable database/keyspace bound to a system and environment.
type Target struct {
	ID               string       `json:"id" yaml:"id"`
	Ref              string       `json:"ref" yaml:"ref"`
	Alias            string       `json:"alias,omitempty" yaml:"alias,omitempty"`
	OwnerSystemID    string       `json:"owner_system_id" yaml:"owner_system_id"`
	LinkedSystemIDs  []string     `json:"linked_system_ids,omitempty" yaml:"linked_system_ids,omitempty"`
	EnvironmentCode  string       `json:"environment_code" yaml:"environment_code"`
	InstanceID       string       `json:"instance_id" yaml:"instance_id"`
	DatabaseName     string       `json:"database_name" yaml:"database_name"`
	ROCredentialID   string       `json:"ro_credential_id,omitempty" yaml:"ro_credential_id,omitempty"`
	RWCredentialID   string       `json:"rw_credential_id,omitempty" yaml:"rw_credential_id,omitempty"`
	PolicyOverrideID string       `json:"policy_override_id,omitempty" yaml:"policy_override_id,omitempty"`
	Status           TargetStatus `json:"status" yaml:"status"`
	Description      string       `json:"description,omitempty" yaml:"description,omitempty"`
	CreatedAtUTC     string       `json:"created_at_utc" yaml:"created_at_utc,omitempty"`
	UpdatedAtUTC     string       `json:"updated_at_utc" yaml:"updated_at_utc,omitempty"`
}

// TargetDetail is the resolved, secret-free view returned to CLI and Web UI.
type TargetDetail struct {
	Target          Target             `json:"target"`
	OwnerSystem     *System            `json:"owner_system,omitempty"`
	LinkedSystems   []System           `json:"linked_systems,omitempty"`
	Environment     *Environment       `json:"environment,omitempty"`
	Instance        *Instance          `json:"instance,omitempty"`
	NetworkProfile  *NetworkProfile    `json:"network_profile,omitempty"`
	ROCredential    *CredentialProfile `json:"ro_credential,omitempty"`
	RWCredential    *CredentialProfile `json:"rw_credential,omitempty"`
	EffectivePolicy EffectivePolicy    `json:"effective_policy"`
	WorkspaceMatch  bool               `json:"workspace_match"`
}

// TargetSummary is the compact agent-facing view returned by `db list` by default.
type TargetSummary struct {
	Ref             string       `json:"ref"`
	Alias           string       `json:"alias,omitempty"`
	System          string       `json:"system,omitempty"`
	Env             string       `json:"env"`
	SafetyTier      SafetyTier   `json:"safety_tier"`
	Engine          string       `json:"engine"`
	Database        string       `json:"database,omitempty"`
	Status          TargetStatus `json:"status"`
	Writable        bool         `json:"writable"`
	ScanReadMode    ScanReadMode `json:"scan_read_mode,omitempty"`
	MaxRows         int          `json:"max_rows"`
	ExecTimeoutSec  int          `json:"exec_timeout_sec"`
	WorkspaceMatch  bool         `json:"workspace_match,omitempty"`
	QuerySyntaxHint string       `json:"query_syntax_hint,omitempty"`
	Description     string       `json:"description,omitempty"`
}

// TargetShowSummary extends TargetSummary with non-secret connection & guardrail metadata for `db show`.
type TargetShowSummary struct {
	TargetSummary
	Endpoint            string   `json:"endpoint,omitempty"`
	NetworkMode         string   `json:"network_mode,omitempty"`
	TLSMode             string   `json:"tls_mode,omitempty"`
	HasROCredential     bool     `json:"has_ro_credential"`
	HasRWCredential     bool     `json:"has_rw_credential"`
	AllowMultiStatement bool     `json:"allow_multi_statement"`
	ExplainMaxRows      int64    `json:"explain_max_rows"`
	PatternRulesCount   int      `json:"pattern_rules_count"`
	Examples            []string `json:"examples,omitempty"`
}

// TopologyBundle is a secret-free export/import representation of enterprise catalog topology.
type TopologyBundle struct {
	SchemaVersion      int                   `json:"schema_version" yaml:"schema_version"`
	ExportedAtUTC      string                `json:"exported_at_utc" yaml:"exported_at_utc"`
	GlobalSecurity     *GlobalSecurityConfig `json:"global_security,omitempty" yaml:"global_security,omitempty"`
	Environments       []Environment         `json:"environments" yaml:"environments"`
	Systems            []System              `json:"systems" yaml:"systems"`
	NetworkProfiles    []NetworkProfile      `json:"network_profiles" yaml:"network_profiles"`
	CredentialProfiles []CredentialProfile   `json:"credential_profiles" yaml:"credential_profiles"`
	Instances          []Instance            `json:"instances" yaml:"instances"`
	Targets            []Target              `json:"targets" yaml:"targets"`
	Policies           []PolicyRuleSet       `json:"policies" yaml:"policies"`
	RiskPatternRules   []RiskPatternRule     `json:"risk_pattern_rules,omitempty" yaml:"risk_pattern_rules,omitempty"`
}

// MissingSecretInfo identifies a keychain credential lacking a stored secret alongside its Web setup URL.
type MissingSecretInfo struct {
	ID          string      `json:"id"`
	Name        string      `json:"name"`
	Username    string      `json:"username,omitempty"`
	AccessLevel AccessLevel `json:"access_level"`
	SetupURL    string      `json:"setup_url,omitempty"`
}

// ResourcePlanCounts summarizes planned or applied resource counts.
type ResourcePlanCounts struct {
	Created   int `json:"created"`
	Updated   int `json:"updated"`
	Unchanged int `json:"unchanged"`
}

// TopologyImportSummary reports per-entity counts for topology apply / dry-run.
type TopologyImportSummary struct {
	GlobalSecurityAction string             `json:"global_security_action,omitempty"`
	Environments         ResourcePlanCounts `json:"environments"`
	Systems              ResourcePlanCounts `json:"systems"`
	NetworkProfiles      ResourcePlanCounts `json:"network_profiles"`
	CredentialProfiles   ResourcePlanCounts `json:"credential_profiles"`
	Instances            ResourcePlanCounts `json:"instances"`
	Targets              ResourcePlanCounts `json:"targets"`
	Policies             ResourcePlanCounts `json:"policies"`
	RiskPatternRules     ResourcePlanCounts `json:"risk_pattern_rules"`
}

// TopologyImportResult summarizes a topology plan (--dry-run) or atomic import.
type TopologyImportResult struct {
	DryRun         bool                  `json:"dry_run"`
	Status         string                `json:"status"` // planned | applied | unchanged
	Summary        TopologyImportSummary `json:"summary"`
	MissingSecrets []MissingSecretInfo   `json:"missing_secrets,omitempty"`
}
