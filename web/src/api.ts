export interface DisplayMetaItem {
  code: string
  labels: Record<string, string>
  color: string
  order: number
}

export interface DisplayCatalog {
  catalog_version: number
  environments: DisplayMetaItem[]
  operation_statuses: DisplayMetaItem[]
  risk_levels: DisplayMetaItem[]
  engines: DisplayMetaItem[]
  approval_providers: DisplayMetaItem[]
}

export interface DaemonIdentity {
  version: string
  commit: string
  pid: number
  session: string
  config_home: string
  web_url: string
  started_at_utc: string
}

export interface GlobalSecurityConfig {
  exec_timeout_sec: number
  approval_timeout_sec: number
  max_rows: number
  max_bytes: number
  explain_max_rows: number
  prod_read_only_freeze: boolean
  block_multi_statement_in_prod: boolean
  default_approval_provider: string
  redact_audit_literals: boolean
  require_reason_for_approval: boolean
  updated_at_utc?: string
}

export type Role = 'platform_admin' | 'system_admin' | 'approver' | 'developer' | 'viewer'
export type ScopeType = 'global' | 'system' | 'env'

export interface RoleBinding {
  id: string
  user_id: string
  role: Role
  scope_type: ScopeType
  scope_id?: string
  created_at_utc?: string
  created_by?: string
}

export interface BootstrapUser {
  id: string
  email: string
  display_name: string
  roles: RoleBinding[]
  is_platform_admin: boolean
  can_manage_users: boolean
  can_edit_security: boolean
}

export interface PublicAuthInfo {
  mode: 'local' | 'server'
  authenticated: boolean
  auth_methods?: string[]
  oidc_enabled?: boolean
  local_enabled?: boolean
  version?: string
}

export interface UserRecord {
  id: string
  email: string
  display_name: string
  oidc_issuer?: string
  status: string
  last_login_at_utc?: string
  created_at_utc: string
}

export interface APITokenRecord {
  id: string
  user_id: string
  owner_email?: string
  name: string
  token_prefix: string
  role_ceiling: Role
  allowed_systems?: string[]
  allowed_envs?: string[]
  read_only_forced: boolean
  expires_at_utc?: string
  revoked_at_utc?: string
  last_used_at_utc?: string
  created_at_utc: string
}

export interface APITokenCreateResponse {
  token: APITokenRecord
  secret_token: string
}

export interface BootstrapPayload {
  mode?: 'local' | 'server'
  authenticated?: boolean
  auth_methods?: string[]
  oidc_enabled?: boolean
  local_enabled?: boolean
  identity: DaemonIdentity
  display_catalog: DisplayCatalog
  global_security: GlobalSecurityConfig
  pending_approval_count: number
  secret_backend: string
  ui_csrf_token?: string
  current_user?: BootstrapUser
}

export class AuthRequiredError extends Error {
  authInfo?: PublicAuthInfo
  constructor(message: string, authInfo?: PublicAuthInfo) {
    super(message)
    this.name = 'AuthRequiredError'
    this.authInfo = authInfo
  }
}

export interface DBAddRequest {
  dsn?: string
  engine?: string
  host?: string
  port?: number
  database?: string
  tls_mode?: string
  ref?: string
  alias?: string
  system?: string
  system_name?: string
  env?: string
  instance?: string
  network?: string
  user?: string
  cred_kind?: 'keychain' | 'env_ref' | 'exec_provider'
  access_level?: 'read_only' | 'read_write'
  ro_cred?: string
  rw_cred?: string
  env_var_name?: string
  exec_command?: string
  secret_value?: string
  secret_provided?: boolean
  status?: 'active' | 'maintenance' | 'disabled'
  description?: string
  test?: boolean
}

export interface DBAddResponse {
  status: string
  target: {
    ref: string
    alias?: string
    system?: string
    env: string
    engine: string
    database?: string
  }
  actions: Record<string, string>
  ping?: PingResult
  warnings?: string[]
}

export interface SystemRecord {
  id: string
  slug: string
  name: string
  owner: string
  description: string
  tags: string[]
  workspace_paths: string[]
  git_remotes: string[]
  default_policy_id?: string
  created_at_utc?: string
  updated_at_utc?: string
}

export interface EnvironmentRecord {
  code: string
  safety_tier: 'yolo' | 'guarded' | 'strict'
  labels: Record<string, string>
  color: string
  sort_order: number
  default_policy_id?: string
}

export interface NetworkProfileRecord {
  id: string
  name: string
  mode: 'direct' | 'ssh_tunnel' | 'socks5' | 'http_proxy'
  proxy_url?: string
  bastion_host?: string
  bastion_port?: number
  bastion_user?: string
  bastion_credential_id?: string
  ssh_strict_host_key: boolean
  tls_mode?: string
}

export interface CredentialProfileRecord {
  id: string
  name: string
  kind: 'keychain' | 'env_ref' | 'exec_provider'
  access_level: 'read_only' | 'read_write'
  username?: string
  env_var_name?: string
  exec_command?: string
  has_secret: boolean
  secret_value?: string
}

export interface ServerCapabilities {
  engine: string
  dialect: string
  server_version?: string
  major_version?: number
  minor_version?: number
  explain_format?: string
  supports_explain: boolean
  supports_explain_json: boolean
  supports_read_only_session: boolean
  supports_cancel_query: boolean
  supports_returning: boolean
  supports_resp3?: boolean
  cluster_mode?: boolean
  supports_authorized_db_list?: boolean
  detected_at_utc?: string
}

export interface InstanceRecord {
  id: string
  name: string
  engine: string
  host: string
  port: number
  role: 'primary' | 'replica' | 'standalone'
  primary_instance_id?: string
  network_profile_id?: string
  tls_mode?: string
  params?: Record<string, string>
  capabilities?: ServerCapabilities
  capabilities_detected_at_utc?: string
}

export interface EffectivePolicy {
  safety_tier: string
  allow_safe_read: boolean
  require_approval_on_high_cost_read: boolean
  require_approval_on_write: boolean
  require_approval_on_ddl: boolean
  require_approval_on_admin: boolean
  require_approval_on_unknown: boolean
  allow_multi_statement: boolean
  prod_read_only_freeze: boolean
  exec_timeout_sec: number
  approval_timeout_sec: number
  max_rows: number
  max_bytes: number
  explain_max_rows: number
  approval_provider: string
  pattern_rules?: RiskPatternRule[]
  sources: Record<string, string>
}

export interface TargetRecord {
  id: string
  ref: string
  alias?: string
  owner_system_id: string
  linked_system_ids?: string[]
  environment_code: string
  instance_id: string
  database_name: string
  ro_credential_id?: string
  rw_credential_id?: string
  policy_override_id?: string
  status: 'active' | 'maintenance' | 'disabled'
  description?: string
}

export interface TargetDetail {
  target: TargetRecord
  owner_system?: SystemRecord
  linked_systems?: SystemRecord[]
  environment?: EnvironmentRecord
  instance?: InstanceRecord
  network_profile?: NetworkProfileRecord
  ro_credential?: CredentialProfileRecord
  rw_credential?: CredentialProfileRecord
  effective_policy: EffectivePolicy
  workspace_match: boolean
}

export interface PolicyRuleSet {
  id: string
  name: string
  scope_type: 'env' | 'system' | 'target'
  scope_id: string
  allow_safe_read?: boolean | null
  require_approval_on_high_cost_read?: boolean | null
  require_approval_on_write?: boolean | null
  require_approval_on_ddl?: boolean | null
  require_approval_on_admin?: boolean | null
  require_approval_on_unknown?: boolean | null
  allow_multi_statement?: boolean | null
  exec_timeout_sec?: number | null
  approval_timeout_sec?: number | null
  max_rows?: number | null
  max_bytes?: number | null
  explain_max_rows?: number | null
  scan_read_mode?: 'allow' | 'reason_only' | 'require_approval' | ''
  approval_provider?: string
}

export interface PreflightReport {
  supported: boolean
  executed: boolean
  full_scan: boolean
  estimated_rows: number
  format?: string
  plan_summary?: string
  plan_raw?: unknown
  warnings?: string[]
}

export type PatternAction = 'elevate_high_cost' | 'require_approval' | 'deny'

export type PatternMatcherType =
  | 'function_call'
  | 'table_ref'
  | 'pragma_name'
  | 'command_arg'
  | 'json_path'
  | 'regex'
  | 'risk_flag'
  | 'preflight_metric'

export interface PatternCondition {
  all?: PatternCondition[]
  any?: PatternCondition[]
  not?: PatternCondition | null
  type?: PatternMatcherType
  values?: string[]
  pattern?: string
  target?: string
  case_sensitive?: boolean
  command?: string
  subcommand?: string
  arg_keyword?: string
  arg_equals?: string
  arg_greater_than?: number | null
  json_path?: string
  equals?: string
  metric?: string
  operator?: string
  threshold?: number | null
  bool_value?: boolean | null
}

export interface RiskPatternRule {
  id: string
  name: string
  description?: string
  scope_type: 'global' | 'env' | 'system' | 'target'
  scope_id: string
  enabled: boolean
  builtin_pack?: string
  engines?: string[]
  families?: string[]
  action: PatternAction
  confirm_title?: string
  confirm_message?: string
  approval_provider?: string
  condition: PatternCondition
  priority: number
  created_at_utc?: string
  updated_at_utc?: string
}

export interface MatchedRule {
  rule_id: string
  rule_name: string
  scope: string
  action: PatternAction
  matched_fragment?: string
  confirm_title?: string
  confirm_message?: string
  approval_provider?: string
}

export interface BuiltinRulePack {
  id: string
  name: string
  description: string
  engines: string[]
  rules: RiskPatternRule[]
}

export interface PatternTestRequest {
  target_id?: string
  engine?: string
  safety_tier?: 'yolo' | 'guarded' | 'strict'
  query: string
  draft_rule?: RiskPatternRule | null
  simulated_preflight?: Partial<PreflightReport> | null
}

export interface PatternTestResult {
  classification: {
    engine: string
    family: string
    risk_level: string
    is_read_only: boolean
    statement_count: number
    risk_flags?: string[]
    summary: string
  }
  evaluation: {
    decision: string
    trigger_reasons?: string[]
    matched_rules?: MatchedRule[]
    deny_code?: string
    deny_message?: string
  }
  matched_rules?: MatchedRule[]
  draft_matched?: MatchedRule | null
  normalized_query: string
  extracted: {
    functions?: string[]
    tables?: string[]
    pragmas?: string[]
    mongo_operators?: string[]
  }
}

export interface ApprovalRecord {
  id: string
  operation_id: string
  provider: string
  external_ticket_id?: string
  external_ticket_url?: string
  status: string
  target_ref: string
  system_slug: string
  environment_code: string
  engine: string
  actor: string
  reason?: string
  workspace_cwd?: string
  query_text: string
  risk_level: string
  trigger_reasons?: string[]
  matched_rules?: MatchedRule[]
  preflight?: PreflightReport
  reviewer?: string
  reviewer_note?: string
  created_at_utc: string
  expires_at_utc: string
  resolved_at_utc?: string
}

export interface OperationRecord {
  id: string
  target_id: string
  target_ref: string
  system_id: string
  system_slug: string
  environment_code: string
  engine: string
  actor: string
  reason?: string
  workspace_cwd?: string
  query_text: string
  query_redacted: string
  risk_level: string
  decision: string
  trigger_reasons?: string[]
  matched_rules?: MatchedRule[]
  preflight?: PreflightReport
  status: string
  credential_mode: string
  approval_id?: string
  fetched_rows: number
  returned_rows: number
  affected_rows?: number | null
  truncated: boolean
  cutoff_reason?: string
  latency_ms: number
  error_code?: string
  error_message?: string
  retryable: boolean
  created_at_utc: string
  completed_at_utc?: string
}

export interface AuditEntry {
  seq: number
  id: string
  actor: string
  action: string
  target_id: string
  operation_id?: string
  payload_json: string
  prev_hash: string
  entry_hash: string
  created_at_utc: string
}

export interface AuditVerifyResult {
  valid: boolean
  checked_count: number
  first_broken_seq?: number
  reason?: string
  last_hash?: string
}

export interface DriverMetadata {
  id: string
  engine: string
  display_name: string
  family: string
  tier: string
  version: string
  host_api_version?: number
  capabilities: string[]
  verified: boolean
  verification_error?: string
}

export interface DiscoveredPlugin {
  Manifest: {
    id: string
    engine: string
    display_name: string
    family: string
    version: string
    host_api_version: number
    binary: string
    sha256: string
  }
  Dir: string
  BinaryPath: string
  ActualSHA256: string
  Verified: boolean
  VerificationErr: string
}

export interface PingResult {
  target_ref: string
  instance_id: string
  engine: string
  dialect?: string
  role: string
  reachable: boolean
  server_version?: string
  capabilities?: ServerCapabilities
  latency_ms: number
  error?: string
}

let uiCSRFToken: string | null = null
let onAuthRequiredHandler: ((authInfo?: PublicAuthInfo) => void) | null = null
let sharedEventSource: EventSource | null = null
const eventListeners = new Map<string, Set<() => void>>()

export function setOnAuthRequired(fn: ((authInfo?: PublicAuthInfo) => void) | null): void {
  onAuthRequiredHandler = fn
}

export function closeEventStream(): void {
  if (sharedEventSource) {
    sharedEventSource.close()
    sharedEventSource = null
  }
}

function ensureEventSource(): EventSource {
  if (!sharedEventSource || sharedEventSource.readyState === EventSource.CLOSED) {
    sharedEventSource = new EventSource('/api/v1/events', { withCredentials: true })
    for (const eventName of eventListeners.keys()) {
      sharedEventSource.addEventListener(eventName, () => {
        const set = eventListeners.get(eventName)
        if (!set) return
        for (const cb of set) {
          cb()
        }
      })
    }
  }
  return sharedEventSource
}

function notifyAuthRequired(authInfo?: PublicAuthInfo) {
  uiCSRFToken = null
  closeEventStream()
  onAuthRequiredHandler?.(authInfo)
}

async function fetchBootstrap(): Promise<BootstrapPayload> {
  const resp = await fetch('/api/v1/bootstrap', { credentials: 'same-origin' })
  const text = await resp.text()
  let parsed: unknown = {}
  if (text) {
    try {
      parsed = JSON.parse(text)
    } catch {
      parsed = text
    }
  }
  if (resp.status === 401) {
    const info = (parsed as { auth_info?: PublicAuthInfo })?.auth_info
    notifyAuthRequired(info)
    throw new AuthRequiredError('Authentication required', info)
  }
  if (!resp.ok) {
    const errObj = parsed as { error?: string }
    throw new Error(errObj?.error || `HTTP ${resp.status}`)
  }
  const payload = parsed as BootstrapPayload
  if (payload.ui_csrf_token) {
    uiCSRFToken = payload.ui_csrf_token
  }
  return payload
}

async function ensureCSRFToken(forceRefresh = false): Promise<string> {
  if (!forceRefresh && uiCSRFToken) {
    return uiCSRFToken
  }
  const boot = await fetchBootstrap()
  return boot.ui_csrf_token ?? uiCSRFToken ?? ''
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const isMutation = Boolean(init?.method && init.method !== 'GET' && init.method !== 'HEAD')
  const send = async (csrfToken: string | null) => {
    const headers = new Headers(init?.headers)
    if (isMutation) {
      if (csrfToken) {
        headers.set('X-Agent-DBCTL-CSRF', csrfToken)
      }
      if (!headers.has('Content-Type') && typeof init?.body === 'string') {
        headers.set('Content-Type', 'application/json')
      }
    }
    return fetch(path, {
      ...init,
      credentials: 'same-origin',
      headers,
    })
  }

  let resp = await send(isMutation ? await ensureCSRFToken() : null)
  if (isMutation && resp.status === 403) {
    const refreshed = await ensureCSRFToken(true)
    if (refreshed) {
      resp = await send(refreshed)
    }
  }

  const text = await resp.text()
  let parsed: unknown = {}
  if (text) {
    try {
      parsed = JSON.parse(text)
    } catch {
      parsed = text
    }
  }
  if (resp.status === 401) {
    notifyAuthRequired()
    throw new AuthRequiredError('Authentication required')
  }
  if (!resp.ok) {
    const errObj = parsed as { error?: string }
    throw new Error(errObj?.error || `HTTP ${resp.status}`)
  }
  return parsed as T
}

export const api = {
  bootstrap: () => fetchBootstrap(),

  getAuthConfig: async (): Promise<PublicAuthInfo> => {
    const resp = await fetch('/api/v1/auth/config', { credentials: 'same-origin' })
    if (!resp.ok) {
      throw new Error(`HTTP ${resp.status}`)
    }
    return (await resp.json()) as PublicAuthInfo
  },

  loginLocal: async (email: string, password: string): Promise<void> => {
    const resp = await fetch('/api/v1/auth/login', {
      method: 'POST',
      credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password }),
    })
    const parsed = (await resp.json().catch(() => ({}))) as { error?: string; ui_csrf_token?: string }
    if (!resp.ok) {
      throw new Error(parsed.error || `HTTP ${resp.status}`)
    }
    if (parsed.ui_csrf_token) {
      uiCSRFToken = parsed.ui_csrf_token
    }
  },

  logout: async (): Promise<void> => {
    await fetch('/api/v1/auth/logout', { method: 'POST', credentials: 'same-origin' }).catch(() => undefined)
    uiCSRFToken = null
    closeEventStream()
  },

  subscribeEvents: (eventNames: string[], listener: () => void): (() => void) => {
    const attached = new Map<string, EventListener>()
    const es = ensureEventSource()
    for (const name of eventNames) {
      let set = eventListeners.get(name)
      if (!set) {
        set = new Set()
        eventListeners.set(name, set)
        const dispatch: EventListener = () => {
          const cur = eventListeners.get(name)
          if (!cur) return
          for (const fn of cur) {
            fn()
          }
        }
        attached.set(name, dispatch)
        es.addEventListener(name, dispatch)
      }
      set.add(listener)
    }
    return () => {
      for (const name of eventNames) {
        eventListeners.get(name)?.delete(listener)
      }
      void attached
    }
  },

  listUsers: () => request<{ users: UserRecord[]; role_bindings: RoleBinding[] }>('/api/v1/users'),
  createUser: (body: { email: string; display_name: string; password: string }) =>
    request<UserRecord>('/api/v1/users', { method: 'POST', body: JSON.stringify(body) }),
  updateUserStatus: (id: string, status: string) =>
    request<{ updated: boolean }>(`/api/v1/users/${encodeURIComponent(id)}/status`, {
      method: 'POST',
      body: JSON.stringify({ status }),
    }),
  upsertRoleBinding: (b: Partial<RoleBinding>) =>
    request<RoleBinding>('/api/v1/roles', { method: 'POST', body: JSON.stringify(b) }),
  deleteRoleBinding: (id: string) =>
    request<{ deleted: boolean }>(`/api/v1/roles/${encodeURIComponent(id)}`, { method: 'DELETE' }),

  listTokens: (all?: boolean) =>
    request<{ items: APITokenRecord[] }>(`/api/v1/tokens${all ? '?all=1' : ''}`),
  createToken: (body: {
    name: string
    role_ceiling: Role
    allowed_systems?: string[]
    allowed_envs?: string[]
    read_only_forced?: boolean
    ttl_seconds?: number
  }) => request<APITokenCreateResponse>('/api/v1/tokens', { method: 'POST', body: JSON.stringify(body) }),
  revokeToken: (id: string) =>
    request<{ revoked: boolean }>(`/api/v1/tokens/${encodeURIComponent(id)}`, { method: 'DELETE' }),

  listSystems: () => request<{ items: SystemRecord[] }>('/api/v1/systems'),
  saveSystem: (s: Partial<SystemRecord>) =>
    request<SystemRecord>('/api/v1/systems', { method: 'POST', body: JSON.stringify(s) }),
  deleteSystem: (id: string) => request<{ deleted: boolean }>(`/api/v1/systems/${id}`, { method: 'DELETE' }),

  listEnvironments: () => request<{ items: EnvironmentRecord[] }>('/api/v1/environments'),
  saveEnvironment: (e: EnvironmentRecord) =>
    request<EnvironmentRecord>('/api/v1/environments', { method: 'POST', body: JSON.stringify(e) }),
  deleteEnvironment: (code: string) =>
    request<{ deleted: boolean }>(`/api/v1/environments/${encodeURIComponent(code)}`, { method: 'DELETE' }),

  listNetworkProfiles: () => request<{ items: NetworkProfileRecord[] }>('/api/v1/network-profiles'),
  saveNetworkProfile: (n: Partial<NetworkProfileRecord>) =>
    request<NetworkProfileRecord>('/api/v1/network-profiles', { method: 'POST', body: JSON.stringify(n) }),
  deleteNetworkProfile: (id: string) =>
    request<{ deleted: boolean }>(`/api/v1/network-profiles/${id}`, { method: 'DELETE' }),

  listCredentials: () => request<{ items: CredentialProfileRecord[] }>('/api/v1/credentials'),
  saveCredential: (c: Partial<CredentialProfileRecord>) =>
    request<CredentialProfileRecord>('/api/v1/credentials', { method: 'POST', body: JSON.stringify(c) }),
  deleteCredential: (id: string) =>
    request<{ deleted: boolean }>(`/api/v1/credentials/${id}`, { method: 'DELETE' }),

  listInstances: () => request<{ items: InstanceRecord[] }>('/api/v1/instances'),
  saveInstance: (i: Partial<InstanceRecord>) =>
    request<InstanceRecord>('/api/v1/instances', { method: 'POST', body: JSON.stringify(i) }),
  deleteInstance: (id: string) =>
    request<{ deleted: boolean }>(`/api/v1/instances/${id}`, { method: 'DELETE' }),
  testInstance: (id: string, body: { credential_id?: string; database_name?: string }) =>
    request<PingResult>(`/api/v1/instances/${id}/test`, { method: 'POST', body: JSON.stringify(body) }),
  discoverInstance: (id: string, body: { credential_id?: string; database_name?: string }) =>
    request<{ databases: string[] }>(`/api/v1/instances/${id}/discover`, { method: 'POST', body: JSON.stringify(body) }),

  listTargets: () => request<{ items: TargetDetail[] }>('/api/v1/targets'),
  addDatabase: (req: DBAddRequest) =>
    request<DBAddResponse>('/api/v1/db/add', { method: 'POST', body: JSON.stringify(req) }),
  saveTarget: (t: Partial<TargetRecord>) =>
    request<TargetRecord>('/api/v1/targets', { method: 'POST', body: JSON.stringify(t) }),
  deleteTarget: (id: string) =>
    request<{ deleted: boolean }>(`/api/v1/targets/${id}`, { method: 'DELETE' }),
  testTarget: (id: string) => request<PingResult>(`/api/v1/targets/${id}/test`, { method: 'POST', body: '{}' }),
  testAllTargets: () => request<{ results: PingResult[] }>('/api/v1/targets/test-all', { method: 'POST', body: '{}' }),

  exportTopologyYAML: async () => {
    const resp = await fetch('/api/v1/topology?format=yaml', { credentials: 'same-origin' })
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`)
    return resp.text()
  },
  importTopology: (raw: string) =>
    request<{ imported: boolean }>('/api/v1/topology', {
      method: 'POST',
      headers: { 'Content-Type': 'text/plain' },
      body: raw,
    }),

  listPolicies: () => request<{ items: PolicyRuleSet[] }>('/api/v1/policies'),
  savePolicy: (p: Partial<PolicyRuleSet>) =>
    request<PolicyRuleSet>('/api/v1/policies', { method: 'POST', body: JSON.stringify(p) }),
  deletePolicy: (id: string) =>
    request<{ deleted: boolean }>(`/api/v1/policies/${id}`, { method: 'DELETE' }),

  getGlobalSecurity: () => request<GlobalSecurityConfig>('/api/v1/security/global'),
  saveGlobalSecurity: (cfg: GlobalSecurityConfig) =>
    request<GlobalSecurityConfig>('/api/v1/security/global', { method: 'PUT', body: JSON.stringify(cfg) }),

  listRiskPatterns: () =>
    request<{ items: RiskPatternRule[]; builtin_packs: BuiltinRulePack[] }>('/api/v1/risk-patterns'),
  saveRiskPattern: (rule: Partial<RiskPatternRule>) =>
    request<RiskPatternRule>('/api/v1/risk-patterns', { method: 'POST', body: JSON.stringify(rule) }),
  deleteRiskPattern: (id: string) =>
    request<{ deleted: boolean }>(`/api/v1/risk-patterns/${id}`, { method: 'DELETE' }),
  installRulePack: (packId: string, body: { scope_type: string; scope_id: string }) =>
    request<{ items: RiskPatternRule[] }>(`/api/v1/risk-patterns/packs/${packId}/install`, {
      method: 'POST',
      body: JSON.stringify(body),
    }),
  testRiskPattern: (req: PatternTestRequest) =>
    request<PatternTestResult>('/api/v1/risk-patterns/test', {
      method: 'POST',
      body: JSON.stringify(req),
    }),

  listApprovals: (status?: string) =>
    request<{ items: ApprovalRecord[] }>(`/api/v1/approvals${status ? `?status=${encodeURIComponent(status)}` : ''}`),
  approve: (id: string, body: { reviewer?: string; note?: string; token?: string }) =>
    request<ApprovalRecord>(`/api/v1/approvals/${id}/approve`, { method: 'POST', body: JSON.stringify(body) }),
  reject: (id: string, body: { reviewer?: string; note?: string; token?: string }) =>
    request<ApprovalRecord>(`/api/v1/approvals/${id}/reject`, { method: 'POST', body: JSON.stringify(body) }),

  listOperations: (params: Record<string, string>) => {
    const sp = new URLSearchParams()
    for (const [k, v] of Object.entries(params)) {
      if (v) sp.set(k, v)
    }
    const q = sp.toString()
    return request<{ items: OperationRecord[] }>(`/api/v1/operations${q ? `?${q}` : ''}`)
  },
  listAudit: (params: Record<string, string>) => {
    const sp = new URLSearchParams()
    for (const [k, v] of Object.entries(params)) {
      if (v) sp.set(k, v)
    }
    const q = sp.toString()
    return request<{ items: AuditEntry[] }>(`/api/v1/audit${q ? `?${q}` : ''}`)
  },
  verifyAuditChain: () => request<AuditVerifyResult>('/api/v1/audit/verify', { method: 'POST', body: '{}' }),

  listDrivers: () => request<{ drivers: DriverMetadata[]; plugins: DiscoveredPlugin[] }>('/api/v1/drivers'),
  reloadPlugins: () => request<{ plugins: DiscoveredPlugin[] }>('/api/v1/plugins/reload', { method: 'POST', body: '{}' }),
}
