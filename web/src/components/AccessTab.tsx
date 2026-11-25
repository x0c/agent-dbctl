import {
  Badge,
  Button,
  type ColumnDef,
  ConfirmAction,
  DataTable,
  FormDialog,
  FormField,
  Input,
  Notice,
  PageHeader,
  Panel,
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
  Switch,
  Tabs,
  TabsContent,
  TabsList,
  TabsTrigger,
  fmtDateTime,
  toast,
} from '@x0c/ui'
import { Check, Copy, KeyRound, Plus, RefreshCw, Shield, Trash2, UserPlus } from 'lucide-react'
import { useEffect, useState } from 'react'
import {
  api,
  type APITokenRecord,
  type BootstrapUser,
  type EnvironmentRecord,
  type Role,
  type RoleBinding,
  type ScopeType,
  type SystemRecord,
  type UserRecord,
} from '../api'
import { useI18n } from '../lib/i18n'

export function AccessTab({ currentUser }: { currentUser: BootstrapUser }) {
  const { t } = useI18n()
  const [subTab, setSubTab] = useState<'tokens' | 'users'>('tokens')
  const [tokens, setTokens] = useState<APITokenRecord[]>([])
  const [users, setUsers] = useState<UserRecord[]>([])
  const [bindings, setBindings] = useState<RoleBinding[]>([])
  const [systems, setSystems] = useState<SystemRecord[]>([])
  const [envs, setEnvs] = useState<EnvironmentRecord[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  // New Token Dialog
  const [tokOpen, setTokOpen] = useState(false)
  const [tokName, setTokName] = useState('')
  const [tokRole, setTokRole] = useState<Role>('developer')
  const [tokSystems, setTokSystems] = useState('')
  const [tokEnvs, setTokEnvs] = useState('')
  const [tokReadOnly, setTokReadOnly] = useState(false)
  const [tokTTLDays, setTokTTLDays] = useState('30')
  const [tokSaving, setTokSaving] = useState(false)
  const [createdSecret, setCreatedSecret] = useState<string | null>(null)
  const [copiedSecret, setCopiedSecret] = useState(false)

  // New User Dialog (platform_admin)
  const [userOpen, setUserOpen] = useState(false)
  const [userEmail, setUserEmail] = useState('')
  const [userName, setUserName] = useState('')
  const [userPassword, setUserPassword] = useState('')
  const [userSaving, setUserSaving] = useState(false)

  // New RoleBinding Dialog (platform_admin)
  const [roleOpen, setRoleOpen] = useState(false)
  const [roleUserId, setRoleUserId] = useState('')
  const [roleVal, setRoleVal] = useState<Role>('developer')
  const [roleScopeType, setRoleScopeType] = useState<ScopeType>('system')
  const [roleScopeId, setRoleScopeId] = useState('')
  const [roleSaving, setRoleSaving] = useState(false)

  const load = async () => {
    setLoading(true)
    setError(null)
    try {
      const tokRes = await api.listTokens(currentUser.is_platform_admin)
      setTokens(tokRes.items ?? [])
      if (currentUser.can_manage_users) {
        const [uRes, sRes, eRes] = await Promise.all([
          api.listUsers(),
          api.listSystems(),
          api.listEnvironments(),
        ])
        setUsers(uRes.users ?? [])
        setBindings(uRes.role_bindings ?? [])
        setSystems(sRes.items ?? [])
        setEnvs(eRes.items ?? [])
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : t('access.loadFailed'))
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    void load()
  }, [currentUser.id])

  const handleCreateToken = async () => {
    if (!tokName.trim()) return
    setTokSaving(true)
    try {
      const days = Math.max(1, Number(tokTTLDays) || 30)
      const res = await api.createToken({
        name: tokName.trim(),
        role_ceiling: tokRole,
        allowed_systems: tokSystems
          .split(',')
          .map((s) => s.trim())
          .filter(Boolean),
        allowed_envs: tokEnvs
          .split(',')
          .map((s) => s.trim())
          .filter(Boolean),
        read_only_forced: tokReadOnly,
        ttl_seconds: days * 86400,
      })
      setCreatedSecret(res.secret_token)
      setCopiedSecret(false)
      setTokOpen(false)
      setTokName('')
      setTokSystems('')
      setTokEnvs('')
      toast.success(t('access.tokenCreated'))
      await load()
    } catch (e) {
      toast.error(e instanceof Error ? e.message : t('common.saveFailed'))
    } finally {
      setTokSaving(false)
    }
  }

  const handleRevokeToken = async (id: string) => {
    try {
      await api.revokeToken(id)
      toast.success(t('access.tokenRevoked'))
      await load()
    } catch (e) {
      toast.error(e instanceof Error ? e.message : t('common.deleteFailed'))
    }
  }

  const handleCreateUser = async () => {
    if (!userEmail.trim() || !userPassword) return
    setUserSaving(true)
    try {
      await api.createUser({
        email: userEmail.trim(),
        display_name: userName.trim() || userEmail.trim(),
        password: userPassword,
      })
      setUserOpen(false)
      setUserEmail('')
      setUserName('')
      setUserPassword('')
      toast.success(t('common.saved'))
      await load()
    } catch (e) {
      toast.error(e instanceof Error ? e.message : t('common.saveFailed'))
    } finally {
      setUserSaving(false)
    }
  }

  const handleToggleUserStatus = async (u: UserRecord) => {
    const next = u.status === 'active' ? 'disabled' : 'active'
    try {
      await api.updateUserStatus(u.id, next)
      await load()
    } catch (e) {
      toast.error(e instanceof Error ? e.message : t('common.saveFailed'))
    }
  }

  const handleAddRoleBinding = async () => {
    if (!roleUserId) return
    if (roleScopeType !== 'global' && !roleScopeId.trim()) return
    setRoleSaving(true)
    try {
      await api.upsertRoleBinding({
        user_id: roleUserId,
        role: roleVal,
        scope_type: roleScopeType,
        scope_id: roleScopeType === 'global' ? '' : roleScopeId.trim(),
      })
      setRoleOpen(false)
      toast.success(t('common.saved'))
      await load()
    } catch (e) {
      toast.error(e instanceof Error ? e.message : t('common.saveFailed'))
    } finally {
      setRoleSaving(false)
    }
  }

  const handleDeleteRoleBinding = async (id: string) => {
    try {
      await api.deleteRoleBinding(id)
      await load()
    } catch (e) {
      toast.error(e instanceof Error ? e.message : t('common.deleteFailed'))
    }
  }

  const copySecret = async () => {
    if (!createdSecret) return
    try {
      await navigator.clipboard.writeText(createdSecret)
      setCopiedSecret(true)
    } catch {
      toast.error(t('access.copyFailed'))
    }
  }

  const tokenCols: ColumnDef<APITokenRecord, unknown>[] = [
    {
      accessorKey: 'name',
      header: t('access.col.name'),
      cell: ({ row }) => (
        <div>
          <div className="font-medium">{row.original.name}</div>
          {row.original.owner_email && (
            <div className="text-xs text-muted-foreground">{row.original.owner_email}</div>
          )}
        </div>
      ),
    },
    {
      accessorKey: 'token_prefix',
      header: t('access.col.prefix'),
      cell: ({ row }) => <span className="font-mono text-xs">{row.original.token_prefix}…</span>,
    },
    {
      accessorKey: 'role_ceiling',
      header: t('access.col.ceiling'),
      cell: ({ row }) => (
        <div className="flex items-center gap-1.5">
          {row.original.principal_kind === 'human' || !row.original.role_ceiling ? (
            <Badge variant="secondary">{t('access.cliSession')}</Badge>
          ) : (
            <Badge variant="outline">{row.original.role_ceiling}</Badge>
          )}
          {row.original.read_only_forced && <Badge variant="secondary">RO</Badge>}
        </div>
      ),
    },
    {
      id: 'scope',
      header: t('access.col.scope'),
      cell: ({ row }) => {
        const sys = row.original.allowed_systems?.join(', ') || '*'
        const env = row.original.allowed_envs?.join(', ') || '*'
        return (
          <span className="font-mono text-xs text-muted-foreground">
            {sys} / {env}
          </span>
        )
      },
    },
    {
      accessorKey: 'expires_at_utc',
      header: t('access.col.status'),
      cell: ({ row }) =>
        row.original.revoked_at_utc ? (
          <Badge variant="destructive">{t('access.revoked')}</Badge>
        ) : (
          <span className="text-xs text-muted-foreground">
            {row.original.expires_at_utc ? fmtDateTime(row.original.expires_at_utc) : '—'}
          </span>
        ),
    },
    {
      id: 'actions',
      header: '',
      cell: ({ row }) =>
        row.original.revoked_at_utc ? null : (
          <div className="flex justify-end">
            <ConfirmAction
              title={t('access.revokeTitle')}
              description={t('access.revokeDesc', { name: row.original.name })}
              confirmLabel={t('access.revoke')}
              cancelLabel={t('common.cancel')}
              destructive
              onConfirm={() => handleRevokeToken(row.original.id)}
              trigger={
                <Button variant="ghost" size="sm" className="h-8 gap-1 text-destructive">
                  <Trash2 className="size-3.5" />
                  <span>{t('access.revoke')}</span>
                </Button>
              }
            />
          </div>
        ),
    },
  ]

  const userCols: ColumnDef<UserRecord, unknown>[] = [
    {
      accessorKey: 'email',
      header: t('login.email'),
      cell: ({ row }) => (
        <div>
          <div className="font-medium">{row.original.display_name || row.original.email}</div>
          <div className="font-mono text-xs text-muted-foreground">{row.original.email}</div>
        </div>
      ),
    },
    {
      id: 'roles',
      header: t('access.col.roles'),
      cell: ({ row }) => {
        const userBindings = bindings.filter((b) => b.user_id === row.original.id)
        if (userBindings.length === 0) {
          return <span className="text-xs text-muted-foreground">—</span>
        }
        return (
          <div className="flex flex-wrap gap-1.5">
            {userBindings.map((b) => {
              const scopeLabel =
                b.scope_type === 'global'
                  ? 'global'
                  : b.scope_type === 'system'
                    ? systems.find((s) => s.id === b.scope_id)?.slug ?? b.scope_id
                    : b.scope_id
              return (
                <Badge key={b.id} variant="outline" className="gap-1">
                  <span>
                    {b.role} ({scopeLabel})
                  </span>
                  <button
                    type="button"
                    className="ml-0.5 text-muted-foreground hover:text-destructive"
                    onClick={() => void handleDeleteRoleBinding(b.id)}
                    aria-label={t('common.delete')}
                  >
                    ×
                  </button>
                </Badge>
              )
            })}
          </div>
        )
      },
    },
    {
      accessorKey: 'status',
      header: t('access.col.status'),
      cell: ({ row }) => (
        <Badge variant={row.original.status === 'active' ? 'secondary' : 'destructive'}>
          {row.original.status}
        </Badge>
      ),
    },
    {
      id: 'actions',
      header: '',
      cell: ({ row }) => (
        <div className="flex justify-end gap-2">
          <Button
            type="button"
            variant="outline"
            size="sm"
            className="h-8"
            onClick={() => {
              setRoleUserId(row.original.id)
              setRoleOpen(true)
            }}
          >
            <Shield className="mr-1.5 size-3.5" />
            {t('access.assignRole')}
          </Button>
          {row.original.id !== currentUser.id && (
            <Button
              type="button"
              variant="ghost"
              size="sm"
              className="h-8"
              onClick={() => void handleToggleUserStatus(row.original)}
            >
              {row.original.status === 'active' ? t('access.disable') : t('access.enable')}
            </Button>
          )}
        </div>
      ),
    },
  ]

  return (
    <div className="space-y-6">
      <PageHeader
        title={t('access.title')}
        actions={
          <div className="flex items-center gap-2">
            <Button variant="outline" size="sm" className="h-8 gap-1.5" onClick={() => void load()}>
              <RefreshCw className="size-3.5" />
              <span>{t('common.refresh')}</span>
            </Button>
            {currentUser.can_manage_users && (
              <Button variant="outline" size="sm" className="h-8 gap-1.5" onClick={() => setUserOpen(true)}>
                <UserPlus className="size-3.5" />
                <span>{t('access.newUser')}</span>
              </Button>
            )}
            <Button size="sm" className="h-8 gap-1.5" onClick={() => setTokOpen(true)}>
              <Plus className="size-3.5" />
              <span>{t('access.newToken')}</span>
            </Button>
          </div>
        }
      />

      {error && <Notice tone="error">{error}</Notice>}

      {createdSecret && (
        <Panel className="border-amber-500/40 bg-amber-500/5 p-4 space-y-2">
          <div className="flex items-center justify-between gap-4">
            <div className="flex items-center gap-2 text-sm font-medium">
              <KeyRound className="size-4 text-amber-500" />
              <span>{t('access.secretOnceNotice')}</span>
            </div>
            <div className="flex items-center gap-2">
              <Button type="button" size="sm" variant="outline" className="h-8 gap-1.5" onClick={() => void copySecret()}>
                {copiedSecret ? <Check className="size-3.5" /> : <Copy className="size-3.5" />}
                <span>{copiedSecret ? t('access.copied') : t('access.copy')}</span>
              </Button>
              <Button type="button" size="sm" variant="ghost" className="h-8" onClick={() => setCreatedSecret(null)}>
                {t('common.cancel')}
              </Button>
            </div>
          </div>
          <code className="block break-all rounded border border-border bg-muted px-3 py-2 font-mono text-xs">
            {createdSecret}
          </code>
        </Panel>
      )}

      <Tabs value={subTab} onValueChange={(v) => setSubTab(v as 'tokens' | 'users')}>
        <TabsList>
          <TabsTrigger value="tokens">{t('access.tabs.tokens', { count: tokens.length })}</TabsTrigger>
          {currentUser.can_manage_users && (
            <TabsTrigger value="users">{t('access.tabs.users', { count: users.length })}</TabsTrigger>
          )}
        </TabsList>

        <TabsContent value="tokens" className="pt-4">
          <DataTable
            columns={tokenCols}
            data={tokens}
            loading={loading}
            emptyLabel={t('access.emptyTokens')}
          />
        </TabsContent>

        {currentUser.can_manage_users && (
          <TabsContent value="users" className="pt-4">
            <DataTable
              columns={userCols}
              data={users}
              loading={loading}
              emptyLabel={t('access.emptyUsers')}
            />
          </TabsContent>
        )}
      </Tabs>

      <FormDialog
        open={tokOpen}
        onOpenChange={setTokOpen}
        title={t('access.newToken')}
        submitLabel={t('common.save')}
        cancelLabel={t('common.cancel')}
        pending={tokSaving}
        onSubmit={() => void handleCreateToken()}
      >
        <div className="space-y-4">
          <FormField label={t('access.col.name')}>
            <Input value={tokName} onChange={(e) => setTokName(e.target.value)} placeholder="ci-agent" />
          </FormField>
          <FormField label={t('access.col.ceiling')}>
            <Select value={tokRole} onValueChange={(v) => setTokRole(v as Role)}>
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="viewer">viewer</SelectItem>
                <SelectItem value="developer">developer</SelectItem>
                <SelectItem value="system_admin">system_admin</SelectItem>
              </SelectContent>
            </Select>
          </FormField>
          <FormField label={t('access.allowedSystems')}>
            <Input value={tokSystems} onChange={(e) => setTokSystems(e.target.value)} placeholder="orders, billing" />
          </FormField>
          <FormField label={t('access.allowedEnvs')}>
            <Input value={tokEnvs} onChange={(e) => setTokEnvs(e.target.value)} placeholder="dev, staging" />
          </FormField>
          <FormField label={t('access.ttlDays')}>
            <Input type="number" min={1} value={tokTTLDays} onChange={(e) => setTokTTLDays(e.target.value)} />
          </FormField>
          <div className="flex items-center justify-between pt-1">
            <span className="text-sm">{t('access.readOnlyForced')}</span>
            <Switch checked={tokReadOnly} onCheckedChange={setTokReadOnly} />
          </div>
        </div>
      </FormDialog>

      <FormDialog
        open={userOpen}
        onOpenChange={setUserOpen}
        title={t('access.newUser')}
        submitLabel={t('common.save')}
        cancelLabel={t('common.cancel')}
        pending={userSaving}
        onSubmit={() => void handleCreateUser()}
      >
        <div className="space-y-4">
          <FormField label={t('login.email')}>
            <Input type="email" value={userEmail} onChange={(e) => setUserEmail(e.target.value)} />
          </FormField>
          <FormField label={t('access.displayName')}>
            <Input value={userName} onChange={(e) => setUserName(e.target.value)} />
          </FormField>
          <FormField label={t('login.password')}>
            <Input type="password" value={userPassword} onChange={(e) => setUserPassword(e.target.value)} />
          </FormField>
        </div>
      </FormDialog>

      <FormDialog
        open={roleOpen}
        onOpenChange={setRoleOpen}
        title={t('access.assignRole')}
        submitLabel={t('common.save')}
        cancelLabel={t('common.cancel')}
        pending={roleSaving}
        onSubmit={() => void handleAddRoleBinding()}
      >
        <div className="space-y-4">
          <FormField label={t('access.role')}>
            <Select value={roleVal} onValueChange={(v) => setRoleVal(v as Role)}>
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="viewer">viewer</SelectItem>
                <SelectItem value="developer">developer</SelectItem>
                <SelectItem value="approver">approver</SelectItem>
                <SelectItem value="system_admin">system_admin</SelectItem>
                <SelectItem value="platform_admin">platform_admin</SelectItem>
              </SelectContent>
            </Select>
          </FormField>
          <FormField label={t('access.scopeType')}>
            <Select value={roleScopeType} onValueChange={(v) => setRoleScopeType(v as ScopeType)}>
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="global">global</SelectItem>
                <SelectItem value="system">system</SelectItem>
                <SelectItem value="env">env</SelectItem>
              </SelectContent>
            </Select>
          </FormField>
          {roleScopeType === 'system' && (
            <FormField label={t('access.scopeId')}>
              <Select value={roleScopeId} onValueChange={setRoleScopeId}>
                <SelectTrigger>
                  <SelectValue placeholder={t('access.selectSystem')} />
                </SelectTrigger>
                <SelectContent>
                  {systems.map((s) => (
                    <SelectItem key={s.id} value={s.id}>
                      {s.name} ({s.slug})
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </FormField>
          )}
          {roleScopeType === 'env' && (
            <FormField label={t('access.scopeId')}>
              <Select value={roleScopeId} onValueChange={setRoleScopeId}>
                <SelectTrigger>
                  <SelectValue placeholder={t('access.selectEnv')} />
                </SelectTrigger>
                <SelectContent>
                  {envs.map((e) => (
                    <SelectItem key={e.code} value={e.code}>
                      {e.code} ({e.safety_tier})
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </FormField>
          )}
        </div>
      </FormDialog>
    </div>
  )
}
