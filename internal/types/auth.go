package types

// ServerMode distinguishes standalone local execution from multi-user remote server mode.
type ServerMode string

const (
	ModeLocal  ServerMode = "local"
	ModeServer ServerMode = "server"
)

// PrincipalKind identifies whether a request comes from local owner, human browser session, or scoped agent token.
type PrincipalKind string

const (
	PrincipalLocalOwner PrincipalKind = "local_owner"
	PrincipalHuman      PrincipalKind = "human"
	PrincipalAgentToken PrincipalKind = "agent_token"
)

// Role enumerates platform and system-level RBAC roles.
type Role string

const (
	RolePlatformAdmin Role = "platform_admin"
	RoleSystemAdmin   Role = "system_admin"
	RoleApprover      Role = "approver"
	RoleDeveloper     Role = "developer"
	RoleViewer        Role = "viewer"
)

// ScopeType defines the resource boundary of a RoleBinding.
type ScopeType string

const (
	ScopeGlobal ScopeType = "global"
	ScopeSystem ScopeType = "system"
	ScopeEnv    ScopeType = "env"
)

// User represents a human identity authenticated via OIDC or built-in credentials.
type User struct {
	ID           string `json:"id"`
	Email        string `json:"email"`
	DisplayName  string `json:"display_name"`
	OIDCIssuer   string `json:"oidc_issuer,omitempty"`
	OIDCSubject  string `json:"oidc_subject,omitempty"`
	PasswordHash string `json:"-"`
	Status       string `json:"status"` // active | disabled
	CreatedAtUTC string `json:"created_at_utc"`
	UpdatedAtUTC string `json:"updated_at_utc"`
}

// RoleBinding assigns a Role to a User across global, system, or environment scopes.
type RoleBinding struct {
	ID           string    `json:"id"`
	UserID       string    `json:"user_id"`
	Role         Role      `json:"role"`
	ScopeType    ScopeType `json:"scope_type"`
	ScopeID      string    `json:"scope_id,omitempty"` // empty for global; system slug/id or env code otherwise
	CreatedBy    string    `json:"created_by"`
	CreatedAtUTC string    `json:"created_at_utc"`
}

// APIToken represents a revocable, scope-limited credential issued to CLI/coding agents.
type APIToken struct {
	ID             string   `json:"id"`
	UserID         string   `json:"user_id"`
	OwnerEmail     string   `json:"owner_email,omitempty"`
	Name           string   `json:"name"`
	TokenPrefix    string   `json:"token_prefix"`
	TokenHash      string   `json:"-"`
	RoleCeiling    Role     `json:"role_ceiling"`
	AllowedSystems []string `json:"allowed_systems,omitempty"`
	AllowedEnvs    []string `json:"allowed_envs,omitempty"`
	ReadOnlyForced bool     `json:"read_only_forced"`
	ExpiresAtUTC   string   `json:"expires_at_utc,omitempty"`
	LastUsedAtUTC  string   `json:"last_used_at_utc,omitempty"`
	RevokedAtUTC   string   `json:"revoked_at_utc,omitempty"`
	CreatedAtUTC   string   `json:"created_at_utc"`
}

// APITokenCreateResponse returns the created token record plus the one-time plaintext secret.
type APITokenCreateResponse struct {
	Token       APIToken `json:"token"`
	SecretToken string   `json:"secret_token"`
}

// WebSession persists an authenticated browser session and CSRF token hash across nodes/restarts.
type WebSession struct {
	IDHash        string `json:"-"`
	UserID        string `json:"user_id"`
	CSRFTokenHash string `json:"-"`
	ExpiresAtUTC  string `json:"expires_at_utc"`
	CreatedAtUTC  string `json:"created_at_utc"`
}

// Principal is the authenticated actor context attached to every RPC and Web request.
type Principal struct {
	Kind           PrincipalKind `json:"kind"`
	ID             string        `json:"id"`
	Subject        string        `json:"subject"` // canonical audit actor, e.g. user:alice@corp.com or agent:alice@corp.com:ci
	OwnerUserID    string        `json:"owner_user_id,omitempty"`
	Email          string        `json:"email,omitempty"`
	DisplayName    string        `json:"display_name,omitempty"`
	Roles          []RoleBinding `json:"roles,omitempty"`
	RoleCeiling    Role          `json:"role_ceiling,omitempty"`
	AllowedSystems []string      `json:"allowed_systems,omitempty"`
	AllowedEnvs    []string      `json:"allowed_envs,omitempty"`
	ReadOnlyForced bool          `json:"read_only_forced,omitempty"`
}

// AuthBootstrapUser summarizes the logged-in user and coarse UI capability flags for Web Console bootstrap.
type AuthBootstrapUser struct {
	ID              string        `json:"id"`
	Email           string        `json:"email"`
	DisplayName     string        `json:"display_name"`
	Roles           []RoleBinding `json:"roles,omitempty"`
	IsPlatformAdmin bool          `json:"is_platform_admin"`
	CanManageUsers  bool          `json:"can_manage_users"`
	CanEditSecurity bool          `json:"can_edit_security"`
}

// PublicAuthInfo is exposed prior to login in server mode without leaking catalog/config state.
type PublicAuthInfo struct {
	Mode          ServerMode `json:"mode"`
	Authenticated bool       `json:"authenticated"`
	AuthMethods   []string   `json:"auth_methods"`
	OIDCEnabled   bool       `json:"oidc_enabled"`
	LocalEnabled  bool       `json:"local_enabled"`
	Version       string     `json:"version"`
}

// OIDCAuthState persists ephemeral PKCE + return_to state for OIDC Authorization Code flows.
type OIDCAuthState struct {
	StateHash    string `json:"-"`
	Nonce        string `json:"-"`
	PKCEVerifier string `json:"-"`
	ReturnTo     string `json:"return_to"`
	ExpiresAtUTC string `json:"expires_at_utc"`
	CreatedAtUTC string `json:"created_at_utc"`
}

// EncryptedSecretRecord stores an envelope-encrypted credential secret in SQLite/PostgreSQL.
type EncryptedSecretRecord struct {
	Key          string `json:"key"`
	KeyVersion   int    `json:"key_version"`
	Nonce        []byte `json:"nonce"`
	Ciphertext   []byte `json:"ciphertext"`
	UpdatedAtUTC string `json:"updated_at_utc"`
}

// CLIDeviceCode persists pending/decided CLI browser login confirmation requests.
type CLIDeviceCode struct {
	DeviceCodeHash string `json:"-"`
	UserCode       string `json:"user_code"`
	Status         string `json:"status"` // pending | approved | rejected | consumed
	UserID         string `json:"user_id,omitempty"`
	ExpiresAtUTC   string `json:"expires_at_utc"`
	CreatedAtUTC   string `json:"created_at_utc"`
}

// DeviceCodeStartResponse starts interactive browser verification for `agent-dbctl login`.
type DeviceCodeStartResponse struct {
	Mode                    string `json:"mode"` // oidc | local
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete,omitempty"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval"`
}

// DeviceCodePollResponse returns CLI browser authorization poll status and minted token upon approval.
type DeviceCodePollResponse struct {
	Status      string `json:"status"` // pending | slow_down | approved | denied | expired | error
	AccessToken string `json:"access_token,omitempty"`
	Email       string `json:"email,omitempty"`
	Error       string `json:"error,omitempty"`
	ErrorDesc   string `json:"error_description,omitempty"`
}
