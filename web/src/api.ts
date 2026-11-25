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
  updated_at_utc?: string
}

export interface BootstrapPayload {
  identity: DaemonIdentity
  display_catalog: DisplayCatalog
  global_security: GlobalSecurityConfig
  pending_approval_count: number
  secret_backend: string
}

export interface SystemRecord {
  id: string
  slug: string
  name: string
  owner: string
  description: string
  tags: string[]
  workspace_paths: string[]
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
  role: string
  reachable: boolean
  server_version?: string
  latency_ms: number
  error?: string
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const headers = new Headers(init?.headers)
  if (init?.method && init.method !== 'GET') {
    headers.set('X-Agent-DBCTL-UI', '1')
    if (!headers.has('Content-Type') && typeof init.body === 'string') {
      headers.set('Content-Type', 'application/json')
    }
  }
  const resp = await fetch(path, {
    ...init,
    credentials: 'same-origin',
    headers,
  })
  const text = await resp.text()
  let parsed: unknown = {}
  if (text) {
    try {
      parsed = JSON.parse(text)
    } catch {
      parsed = text
    }
  }
  if (!resp.ok) {
    const errObj = parsed as { error?: string }
    throw new Error(errObj?.error || `HTTP ${resp.status}`)
  }
  return parsed as T
}

export const api = {
  bootstrap: () => request<BootstrapPayload>('/api/v1/bootstrap'),

  listSystems: () => request<{ items: SystemRecord[] }>('/api/v1/systems'),
  saveSystem: (s: Partial<SystemRecord>) =>
    request<SystemRecord>('/api/v1/systems', { method: 'POST', body: JSON.stringify(s) }),
  deleteSystem: (id: string) => request<{ deleted: boolean }>(`/api/v1/systems/${id}`, { method: 'DELETE' }),

  listEnvironments: () => request<{ items: EnvironmentRecord[] }>('/api/v1/environments'),
  saveEnvironment: (e: EnvironmentRecord) =>
    request<EnvironmentRecord>('/api/v1/environments', { method: 'POST', body: JSON.stringify(e) }),

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
