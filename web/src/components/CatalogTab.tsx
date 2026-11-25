import {
  Badge,
  Button,
  type ColumnDef,
  ConfirmAction,
  DataTable,
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
  FilterSelect,
  FormDialog,
  FormField,
  Input,
  LoadingButton,
  Notice,
  PageHeader,
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
  Sheet,
  SheetBody,
  SheetContent,
  SheetHeader,
  SheetTitle,
  StatusDot,
  Switch,
  Tabs,
  TabsContent,
  TabsList,
  TabsTrigger,
  Textarea,
  toast,
} from '@x0c/ui'
import {
  ChevronDown,
  ChevronRight,
  Download,
  FolderGit2,
  GitBranch,
  KeyRound,
  Layers,
  Network,
  Plus,
  RefreshCw,
  Search,
  Server,
  Upload,
  Wifi,
} from 'lucide-react'
import { useEffect, useMemo, useRef, useState } from 'react'
import {
  api,
  type BootstrapUser,
  type CredentialProfileRecord,
  type DisplayCatalog,
  type EnvironmentRecord,
  type InstanceRecord,
  type NetworkProfileRecord,
  type PingResult,
  type SystemRecord,
  type TargetDetail,
  type TargetRecord,
} from '../api'
import { resolveDisplayItem } from '../lib/catalog'
import { useI18n } from '../lib/i18n'
import { MetaBadge } from './MetaBadge'

export type CatalogSubTab = 'targets' | 'systems' | 'instances' | 'networks' | 'credentials'
type PrimaryTab = 'targets' | 'systems'
type ResourceKind = 'instances' | 'networks' | 'credentials'
type DialogKind = 'add-db' | 'targets' | 'systems' | 'instances' | 'networks' | 'credentials' | 'topology'

const ALL_SYSTEMS = '__all__'

const DEFAULT_ENGINE_PORTS: Record<string, number> = {
  postgres: 5432,
  opengauss: 5432,
  gaussdb: 5432,
  gaussdb_dws: 8000,
  vastbase: 5432,
  mogdb: 5432,
  gbase8c: 5432,
  kingbase: 54321,
  kingbase8: 54321,
  kingbasees: 54321,
  highgo: 5866,
  uxdb: 52025,
  opentenbase: 11000,
  kwdb: 26257,
  dameng: 5236,
  dm: 5236,
  dm8: 5236,
  tdengine: 6041,
  mysql: 3306,
  tidb: 4000,
  oceanbase: 2883,
  oceanbase_mysql: 2883,
  polardb: 3306,
  tdsql: 3306,
  goldendb: 3306,
  greatsql: 3306,
  gbase: 5258,
  gbase8a: 5258,
  doris: 9030,
  selectdb: 9030,
  starrocks: 9030,
  mongodb: 27017,
  redis: 6379,
  clickhouse: 9000,
  mssql: 1433,
  oracle: 1521,
  elasticsearch: 9200,
  easysearch: 9200,
  sqlite: 0,
}

export function CatalogTab({
  catalog,
  currentUser,
  onRefreshBootstrap,
  initialSubTab = 'targets',
  deepLinkCredential = null,
}: {
  catalog: DisplayCatalog
  currentUser?: BootstrapUser
  onRefreshBootstrap: () => Promise<void>
  initialSubTab?: CatalogSubTab
  deepLinkCredential?: string | null
}) {
  const { locale, t } = useI18n()
  const [subTab, setSubTab] = useState<PrimaryTab>(initialSubTab === 'systems' ? 'systems' : 'targets')
  const [resourceSheet, setResourceSheet] = useState<ResourceKind | null>(
    !deepLinkCredential && (initialSubTab === 'instances' || initialSubTab === 'networks' || initialSubTab === 'credentials')
      ? initialSubTab
      : null,
  )
  const handledDeepLinkRef = useRef<string | null>(null)
  const [systemFilter, setSystemFilter] = useState<string>(ALL_SYSTEMS)
  const [searchQuery, setSearchQuery] = useState<string>('')
  const [systems, setSystems] = useState<SystemRecord[]>([])
  const [envs, setEnvs] = useState<EnvironmentRecord[]>([])
  const [networks, setNetworks] = useState<NetworkProfileRecord[]>([])
  const [credentials, setCredentials] = useState<CredentialProfileRecord[]>([])
  const [instances, setInstances] = useState<InstanceRecord[]>([])
  const [targets, setTargets] = useState<TargetDetail[]>([])
  const [pingByTargetRef, setPingByTargetRef] = useState<Record<string, PingResult>>({})
  const [testingAll, setTestingAll] = useState(false)
  const [testingTargetId, setTestingTargetId] = useState<string | null>(null)
  const [testingInstanceId, setTestingInstanceId] = useState<string | null>(null)
  const [multilineSecret, setMultilineSecret] = useState(false)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  const [dialog, setDialog] = useState<DialogKind | null>(null)
  const [saving, setSaving] = useState(false)
  const [formError, setFormError] = useState<string | null>(null)

  const [addMode, setAddMode] = useState<'fields' | 'uri'>('fields')
  const [showAddAdvanced, setShowAddAdvanced] = useState(false)
  const [addForm, setAddForm] = useState({
    dsn: '',
    engine: 'postgres',
    host: '127.0.0.1',
    port: 5432,
    database: '',
    user: '',
    secret_value: '',
    systemChoice: '__new__',
    newSystemSlug: '',
    env: 'dev',
    alias: '',
    ref: '',
    network: '',
    existingCred: '',
    access_level: 'read_only' as 'read_only' | 'read_write',
    testOnSave: false,
  })
  const [sysForm, setSysForm] = useState({ id: '', slug: '', name: '', owner: '', description: '', tags: '', workspace_paths: '', git_remotes: '' })
  const [netForm, setNetForm] = useState<Partial<NetworkProfileRecord>>({
    id: '',
    name: '',
    mode: 'direct',
    proxy_url: '',
    bastion_host: '',
    bastion_port: 22,
    bastion_user: '',
    bastion_credential_id: '',
    ssh_strict_host_key: true,
    tls_mode: 'prefer',
  })
  const [credForm, setCredForm] = useState<Partial<CredentialProfileRecord>>({
    id: '',
    name: '',
    kind: 'keychain',
    access_level: 'read_only',
    username: '',
    env_var_name: '',
    exec_command: '',
    secret_value: '',
  })
  const [instForm, setInstForm] = useState<Partial<InstanceRecord>>({
    id: '',
    name: '',
    engine: 'postgres',
    host: '127.0.0.1',
    port: 5432,
    role: 'standalone',
    primary_instance_id: '',
    network_profile_id: '',
    tls_mode: 'prefer',
  })
  const [targetForm, setTargetForm] = useState<Partial<TargetRecord>>({
    id: '',
    ref: '',
    alias: '',
    owner_system_id: '',
    linked_system_ids: [],
    environment_code: 'dev',
    instance_id: '',
    database_name: '',
    ro_credential_id: '',
    rw_credential_id: '',
    status: 'active',
    description: '',
  })

  const [discoverSheet, setDiscoverSheet] = useState<{
    instance: InstanceRecord
    credentialId: string
    databases: string[]
    loading: boolean
    error: string | null
  } | null>(null)
  const [topologyText, setTopologyText] = useState('')

  const loadAll = async () => {
    setLoading(true)
    setError(null)
    try {
      const [sRes, eRes, nRes, cRes, iRes, tRes] = await Promise.all([
        api.listSystems(),
        api.listEnvironments(),
        api.listNetworkProfiles(),
        api.listCredentials(),
        api.listInstances(),
        api.listTargets(),
      ])
      setSystems(sRes.items ?? [])
      setEnvs(eRes.items ?? [])
      setNetworks(nRes.items ?? [])
      setCredentials(cRes.items ?? [])
      setInstances(iRes.items ?? [])
      setTargets(tRes.items ?? [])
    } catch (e) {
      setError(e instanceof Error ? e.message : t('catalog.loadFailed'))
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    void loadAll()
  }, [])

  useEffect(() => {
    return api.subscribeEvents(['catalog_updated'], () => {
      void loadAll()
    })
  }, [])

  useEffect(() => {
    if (!deepLinkCredential || handledDeepLinkRef.current === deepLinkCredential) {
      return
    }
    const found = credentials.find(
      (c) => c.id === deepLinkCredential || c.name.toLowerCase() === deepLinkCredential.toLowerCase(),
    )
    if (!found) {
      return
    }
    handledDeepLinkRef.current = deepLinkCredential
    setCredForm({ ...found, secret_value: '' })
    setMultilineSecret(false)
    setFormError(null)
    setDialog('credentials')
  }, [deepLinkCredential, credentials])

  const filteredTargets = useMemo(() => {
    const q = searchQuery.trim().toLowerCase()
    return targets.filter((d) => {
      if (
        systemFilter !== ALL_SYSTEMS &&
        d.target.owner_system_id !== systemFilter &&
        !(d.target.linked_system_ids ?? []).includes(systemFilter)
      ) {
        return false
      }
      if (!q) return true
      const hay = `${d.target.ref} ${d.target.alias ?? ''} ${d.target.database_name} ${d.instance?.host ?? ''} ${d.owner_system?.slug ?? ''}`.toLowerCase()
      return hay.includes(q)
    })
  }, [targets, systemFilter, searchQuery])

  const defaultTargetForInstance = (instId: string): TargetRecord | undefined =>
    targets.find((t) => t.target.instance_id === instId && (t.target.ro_credential_id || t.target.rw_credential_id))?.target

  const defaultCredForInstance = (instId: string): string => {
    const t = defaultTargetForInstance(instId)
    return t?.ro_credential_id || t?.rw_credential_id || ''
  }

  const runTestAll = async () => {
    setTestingAll(true)
    try {
      const res = await api.testAllTargets()
      const next: Record<string, PingResult> = {}
      let okCount = 0
      for (const r of res.results ?? []) {
        next[r.target_ref] = r
        if (r.reachable) okCount++
      }
      setPingByTargetRef((prev) => ({ ...prev, ...next }))
      const total = (res.results ?? []).length
      if (okCount === total) toast.success(t('catalog.allReachable', { total }))
      else toast.info(t('catalog.partialReachable', { ok: okCount, total }))
    } catch (e) {
      toast.error(e instanceof Error ? e.message : t('catalog.batchTestFailed'))
    } finally {
      setTestingAll(false)
    }
  }

  const runDiscover = async (inst: InstanceRecord, credId: string) => {
    const defTgt = targets.find((t) => t.target.instance_id === inst.id && (t.target.ro_credential_id === credId || t.target.rw_credential_id === credId))
    const dbName = defTgt?.target.database_name || ''
    setDiscoverSheet({ instance: inst, credentialId: credId, databases: [], loading: true, error: null })
    try {
      const res = await api.discoverInstance(inst.id, {
        ...(credId ? { credential_id: credId } : {}),
        ...(dbName ? { database_name: dbName } : {}),
      })
      setDiscoverSheet({
        instance: inst,
        credentialId: credId,
        databases: res.databases ?? [],
        loading: false,
        error: null,
      })
    } catch (e) {
      setDiscoverSheet({
        instance: inst,
        credentialId: credId,
        databases: [],
        loading: false,
        error: e instanceof Error ? e.message : t('catalog.discoveryFailed'),
      })
    }
  }

  const defaultResourceScope = (): { scope_type: 'global' | 'system'; scope_id: string } => {
    if (currentUser && !currentUser.is_platform_admin && systems.length > 0) {
      const sysId = systemFilter !== ALL_SYSTEMS ? systemFilter : systems[0].id
      return { scope_type: 'system', scope_id: sysId }
    }
    return { scope_type: 'global', scope_id: 'global' }
  }

  const renderScopeFields = (
    scopeType: 'global' | 'system' | undefined,
    scopeId: string | undefined,
    onChange: (next: { scope_type: 'global' | 'system'; scope_id: string }) => void,
  ) => {
    const curType = scopeType === 'system' ? 'system' : 'global'
    return (
      <div className="grid grid-cols-2 gap-3">
        <FormField label={t('policies.field.scopeType')}>
          <Select
            value={curType}
            onValueChange={(v) => {
              const st = v === 'system' ? 'system' : 'global'
              onChange({
                scope_type: st,
                scope_id: st === 'global' ? 'global' : (systemFilter !== ALL_SYSTEMS ? systemFilter : systems[0]?.id ?? ''),
              })
            }}
          >
            <SelectTrigger><SelectValue /></SelectTrigger>
            <SelectContent>
              <SelectItem value="global">global</SelectItem>
              <SelectItem value="system" disabled={systems.length === 0}>system</SelectItem>
            </SelectContent>
          </Select>
        </FormField>
        <FormField label={t('policies.field.scopeTarget')}>
          {curType === 'global' ? (
            <Input value="global" disabled />
          ) : (
            <Select
              value={scopeId || '__pick__'}
              onValueChange={(v) => onChange({ scope_type: 'system', scope_id: v === '__pick__' ? '' : v })}
            >
              <SelectTrigger><SelectValue placeholder={t('policies.field.selectScope')} /></SelectTrigger>
              <SelectContent>
                <SelectItem value="__pick__" disabled>{t('policies.field.selectScope')}</SelectItem>
                {systems.map((s) => (
                  <SelectItem key={s.id} value={s.id}>{s.slug}</SelectItem>
                ))}
              </SelectContent>
            </Select>
          )}
        </FormField>
      </div>
    )
  }

  const openResourceCreate = (kind: ResourceKind) => {
    setFormError(null)
    const defScope = defaultResourceScope()
    if (kind === 'networks') {
      setNetForm({ id: '', name: '', ...defScope, mode: 'direct', proxy_url: '', bastion_host: '', bastion_port: 22, bastion_user: '', bastion_credential_id: '', ssh_strict_host_key: true, tls_mode: 'prefer' })
    } else if (kind === 'credentials') {
      setMultilineSecret(false)
      setCredForm({ id: '', name: '', ...defScope, kind: 'keychain', access_level: 'read_only', username: '', env_var_name: '', exec_command: '', secret_value: '' })
    } else {
      setInstForm({ id: '', name: '', ...defScope, engine: 'postgres', host: '127.0.0.1', port: 5432, role: 'standalone', primary_instance_id: '', network_profile_id: '', tls_mode: 'prefer' })
    }
    setDialog(kind)
  }

  const openCreate = () => {
    setFormError(null)
    if (subTab === 'systems') {
      setSysForm({ id: '', slug: '', name: '', owner: '', description: '', tags: '', workspace_paths: '', git_remotes: '' })
      setDialog('systems')
      return
    }
    const defSys = systemFilter !== ALL_SYSTEMS ? systemFilter : (systems[0]?.id ?? '__new__')
    setAddMode('fields')
    setShowAddAdvanced(false)
    setAddForm({
      dsn: '',
      engine: 'postgres',
      host: '127.0.0.1',
      port: 5432,
      database: '',
      user: '',
      secret_value: '',
      systemChoice: defSys,
      newSystemSlug: '',
      env: envs[0]?.code ?? 'dev',
      alias: '',
      ref: '',
      network: '',
      existingCred: '',
      access_level: 'read_only',
      testOnSave: false,
    })
    setDialog('add-db')
  }

  const handleSave = async () => {
    setSaving(true)
    setFormError(null)
    try {
      if (dialog === 'add-db') {
        const systemSlug = addForm.systemChoice === '__new__' ? addForm.newSystemSlug.trim() : addForm.systemChoice
        const isSQLite = addMode === 'fields' && addForm.engine === 'sqlite'
        const res = await api.addDatabase({
          ...(addMode === 'uri'
            ? { dsn: addForm.dsn.trim() }
            : {
                engine: addForm.engine,
                host: addForm.host.trim(),
                port: isSQLite ? 0 : addForm.port,
                database: addForm.database.trim(),
                ...(isSQLite
                  ? {}
                  : {
                      user: addForm.user.trim(),
                      secret_value: addForm.secret_value,
                      secret_provided: addForm.secret_value !== '',
                    }),
              }),
          system: systemSlug || undefined,
          env: addForm.env,
          alias: addForm.alias.trim() || undefined,
          ref: addForm.ref.trim() || undefined,
          network: addForm.network || undefined,
          ...(addForm.existingCred
            ? addForm.access_level === 'read_write'
              ? { rw_cred: addForm.existingCred }
              : { ro_cred: addForm.existingCred }
            : { access_level: addForm.access_level }),
          test: addForm.testOnSave,
        })
        setDialog(null)
        if (res.ping) {
          if (res.ping.reachable) {
            toast.success(t('catalog.reachableToast', { ms: res.ping.latency_ms, ver: res.ping.server_version || '?' }))
          } else {
            toast.error(res.ping.error || t('catalog.unreachable'))
          }
        } else {
          toast.success(t('common.saved'))
        }
        await loadAll()
        return
      }
      if (dialog === 'systems') {
        await api.saveSystem({
          id: sysForm.id || undefined,
          slug: sysForm.slug.trim(),
          name: sysForm.name.trim(),
          owner: sysForm.owner.trim(),
          description: sysForm.description.trim(),
          tags: sysForm.tags.split(',').map((s) => s.trim()).filter(Boolean),
          workspace_paths: sysForm.workspace_paths.split('\n').map((s) => s.trim()).filter(Boolean),
          git_remotes: sysForm.git_remotes.split('\n').map((s) => s.trim()).filter(Boolean),
        })
      } else if (dialog === 'networks') {
        await api.saveNetworkProfile(netForm)
      } else if (dialog === 'credentials') {
        await api.saveCredential(credForm)
      } else if (dialog === 'instances') {
        await api.saveInstance(instForm)
      } else if (dialog === 'targets') {
        await api.saveTarget(targetForm)
      } else if (dialog === 'topology') {
        await api.importTopology(topologyText)
        await onRefreshBootstrap()
      }
      setDialog(null)
      toast.success(t('common.saved'))
      await loadAll()
    } catch (e) {
      setFormError(e instanceof Error ? e.message : t('common.saveFailed'))
    } finally {
      setSaving(false)
    }
  }

  const targetColumns: ColumnDef<TargetDetail, unknown>[] = [
    {
      accessorKey: 'target.ref',
      header: t('catalog.col.target'),
      cell: ({ row }) => (
        <div className="flex max-w-[250px] items-center gap-1.5" title={row.original.target.database_name}>
          <span className="truncate font-mono text-xs font-semibold">{row.original.target.ref}</span>
          {row.original.target.alias && (
            <Badge variant="outline" className="shrink-0 font-mono text-[11px]">{row.original.target.alias}</Badge>
          )}
        </div>
      ),
    },
    {
      id: 'system',
      header: t('catalog.col.system'),
      cell: ({ row }) => (
        <span className="block max-w-[110px] truncate font-mono text-xs">
          {row.original.owner_system?.slug ?? row.original.target.owner_system_id}
          {(row.original.linked_systems?.length ?? 0) > 0 && ` (+${row.original.linked_systems?.length})`}
        </span>
      ),
    },
    {
      id: 'env',
      header: t('catalog.col.env'),
      cell: ({ row }) => <MetaBadge items={catalog.environments} code={row.original.target.environment_code} />,
    },
    {
      id: 'engine',
      header: t('catalog.col.engine'),
      cell: ({ row }) =>
        row.original.instance ? <MetaBadge items={catalog.engines} code={row.original.instance.engine} /> : '—',
    },
    {
      id: 'health',
      header: t('catalog.col.status'),
      cell: ({ row }) => {
        const p = pingByTargetRef[row.original.target.ref]
        if (!p) {
          return <span className="font-mono text-xs text-muted-foreground">{row.original.target.status}</span>
        }
        return p.reachable ? (
          <StatusDot tone="success">
            <span className="font-mono text-xs" title={p.server_version || ''}>
              {p.latency_ms}ms
            </span>
          </StatusDot>
        ) : (
          <StatusDot tone="danger">
            <span className="max-w-[240px] truncate font-mono text-xs text-red-700" title={p.error || t('catalog.unreachable')}>
              {p.error ? `${t('catalog.unreachable')}: ${p.error}` : t('catalog.unreachable')}
            </span>
          </StatusDot>
        )
      },
    },
    {
      id: 'actions',
      header: '',
      cell: ({ row }) => (
        <div className="flex justify-end gap-1.5">
          <LoadingButton
            size="sm"
            variant="outline"
            pending={testingTargetId === row.original.target.id}
            onClick={async () => {
              setTestingTargetId(row.original.target.id)
              try {
                const res = await api.testTarget(row.original.target.id)
                setPingByTargetRef((prev) => ({ ...prev, [row.original.target.ref]: res }))
                if (res.reachable) {
                  toast.success(t('catalog.reachableToast', { ms: res.latency_ms, ver: res.server_version || '?' }))
                } else {
                  toast.error(res.error || t('catalog.unreachable'))
                }
              } catch (e) {
                toast.error(e instanceof Error ? e.message : t('catalog.pingFailed'))
              } finally {
                setTestingTargetId(null)
              }
            }}
          >
            <Wifi className="size-3.5" />
            {t('catalog.test')}
          </LoadingButton>
          <Button
            size="sm"
            variant="outline"
            onClick={() => {
              setFormError(null)
              setTargetForm({ ...row.original.target })
              setDialog('targets')
            }}
          >
            {t('common.edit')}
          </Button>
          <ConfirmAction
            trigger={<Button size="sm" variant="ghost">{t('common.delete')}</Button>}
            title={t('catalog.deleteTargetTitle', { ref: row.original.target.ref })}
            description={t('catalog.deleteTargetDesc')}
            confirmLabel={t('common.delete')}
            cancelLabel={t('common.cancel')}
            destructive
            onConfirm={async () => {
              await api.deleteTarget(row.original.target.id)
              toast.success(t('catalog.targetDeleted'))
              await loadAll()
            }}
          />
        </div>
      ),
    },
  ]

  const systemColumns: ColumnDef<SystemRecord, unknown>[] = [
    {
      accessorKey: 'slug',
      header: t('catalog.col.slug'),
      cell: ({ row }) => <span className="font-mono text-xs font-semibold">{row.original.slug}</span>,
    },
    { accessorKey: 'name', header: t('catalog.col.name') },
    {
      accessorKey: 'owner',
      header: t('catalog.col.owner'),
      cell: ({ row }) => <span className="text-xs text-muted-foreground">{row.original.owner || '—'}</span>,
    },
    {
      id: 'workspaces',
      header: t('catalog.col.workspaces'),
      cell: ({ row }) => (
        <span
          className="inline-flex items-center gap-1 font-mono text-xs text-muted-foreground"
          title={(row.original.workspace_paths ?? []).join('\n')}
        >
          <FolderGit2 className="size-3.5" />
          {row.original.workspace_paths?.length ?? 0}
        </span>
      ),
    },
    {
      id: 'git_remotes',
      header: t('catalog.col.gitRemotes'),
      cell: ({ row }) => (
        <span
          className="inline-flex items-center gap-1 font-mono text-xs text-muted-foreground"
          title={(row.original.git_remotes ?? []).join('\n')}
        >
          <GitBranch className="size-3.5" />
          {row.original.git_remotes?.length ?? 0}
        </span>
      ),
    },
    {
      id: 'actions',
      header: '',
      cell: ({ row }) => (
        <div className="flex justify-end gap-1.5">
          <Button
            size="sm"
            variant="outline"
            onClick={() => {
              setFormError(null)
              setSysForm({
                id: row.original.id,
                slug: row.original.slug,
                name: row.original.name,
                owner: row.original.owner,
                description: row.original.description,
                tags: (row.original.tags ?? []).join(', '),
                workspace_paths: (row.original.workspace_paths ?? []).join('\n'),
                git_remotes: (row.original.git_remotes ?? []).join('\n'),
              })
              setDialog('systems')
            }}
          >
            {t('common.edit')}
          </Button>
          <ConfirmAction
            trigger={<Button size="sm" variant="ghost">{t('common.delete')}</Button>}
            title={t('catalog.deleteSystemTitle', { slug: row.original.slug })}
            description={t('catalog.deleteSystemDesc')}
            confirmLabel={t('common.delete')}
            cancelLabel={t('common.cancel')}
            destructive
            onConfirm={async () => {
              try {
                await api.deleteSystem(row.original.id)
                toast.success(t('catalog.systemDeleted'))
                await loadAll()
              } catch (e) {
                toast.error(e instanceof Error ? e.message : t('common.deleteFailed'))
              }
            }}
          />
        </div>
      ),
    },
  ]

  const instanceColumns: ColumnDef<InstanceRecord, unknown>[] = [
    {
      accessorKey: 'name',
      header: t('catalog.col.instance'),
      cell: ({ row }) => (
        <span className="block max-w-[150px] truncate font-mono text-xs font-semibold" title={row.original.name}>
          {row.original.name}
        </span>
      ),
    },
    {
      accessorKey: 'engine',
      header: t('catalog.col.engine'),
      cell: ({ row }) => <MetaBadge items={catalog.engines} code={row.original.engine} />,
    },
    {
      id: 'endpoint',
      header: t('catalog.col.endpoint'),
      cell: ({ row }) => {
        const isSQLite = row.original.engine === 'sqlite'
        const raw = isSQLite
          ? row.original.host
          : `${row.original.host}:${row.original.port || DEFAULT_ENGINE_PORTS[row.original.engine] || 'default'}`
        const display = isSQLite ? raw.replace(/^\/Users\/[^/]+/, '~') : raw
        return (
          <span className="block max-w-[230px] truncate font-mono text-xs text-muted-foreground" title={raw}>
            {display}
          </span>
        )
      },
    },
    {
      accessorKey: 'role',
      header: t('catalog.col.role'),
      cell: ({ row }) => <Badge variant="outline" className="font-mono text-[11px]">{row.original.role}</Badge>,
    },
    {
      id: 'actions',
      header: '',
      cell: ({ row }) => (
        <div className="flex justify-end gap-1.5">
          <LoadingButton
            size="sm"
            variant="outline"
            pending={testingInstanceId === row.original.id}
            onClick={async () => {
              setTestingInstanceId(row.original.id)
              try {
                const credId = defaultCredForInstance(row.original.id)
                const res = await api.testInstance(row.original.id, credId ? { credential_id: credId } : {})
                if (res.reachable) {
                  toast.success(t('catalog.reachableToast', { ms: res.latency_ms, ver: res.server_version || '?' }))
                } else {
                  toast.error(res.error || t('catalog.unreachable'))
                }
              } catch (e) {
                toast.error(e instanceof Error ? e.message : t('catalog.pingFailed'))
              } finally {
                setTestingInstanceId(null)
              }
            }}
          >
            <Wifi className="size-3.5" />
            {t('catalog.test')}
          </LoadingButton>
          <Button
            size="sm"
            variant="outline"
            onClick={() => void runDiscover(row.original, defaultCredForInstance(row.original.id))}
          >
            <Search className="size-3.5" />
            {t('catalog.discover')}
          </Button>
          <Button
            size="sm"
            variant="outline"
            onClick={() => {
              setFormError(null)
              setInstForm({ ...row.original })
              setDialog('instances')
            }}
          >
            {t('common.edit')}
          </Button>
          <ConfirmAction
            trigger={<Button size="sm" variant="ghost">{t('common.delete')}</Button>}
            title={t('catalog.deleteInstanceTitle', { name: row.original.name })}
            confirmLabel={t('common.delete')}
            cancelLabel={t('common.cancel')}
            destructive
            onConfirm={async () => {
              try {
                await api.deleteInstance(row.original.id)
                toast.success(t('catalog.instanceDeleted'))
                await loadAll()
              } catch (e) {
                toast.error(e instanceof Error ? e.message : t('common.deleteFailed'))
              }
            }}
          />
        </div>
      ),
    },
  ]

  const netColumns: ColumnDef<NetworkProfileRecord, unknown>[] = [
    { accessorKey: 'name', header: t('catalog.col.name'), cell: ({ row }) => <span className="font-mono text-xs font-semibold">{row.original.name}</span> },
    { accessorKey: 'mode', header: t('catalog.col.mode'), cell: ({ row }) => <Badge variant="outline" className="font-mono text-[11px]">{row.original.mode}</Badge> },
    { id: 'detail', header: t('catalog.col.endpoint'), cell: ({ row }) => <span className="font-mono text-xs text-muted-foreground">{row.original.bastion_host || row.original.proxy_url || t('catalog.direct')}</span> },
    {
      id: 'actions',
      header: '',
      cell: ({ row }) => (
        <div className="flex justify-end gap-1.5">
          <Button size="sm" variant="outline" onClick={() => { setFormError(null); setNetForm({ ...row.original }); setDialog('networks') }}>{t('common.edit')}</Button>
          <ConfirmAction trigger={<Button size="sm" variant="ghost">{t('common.delete')}</Button>} title={t('catalog.deleteItemTitle', { name: row.original.name })} confirmLabel={t('common.delete')} cancelLabel={t('common.cancel')} destructive onConfirm={async () => { await api.deleteNetworkProfile(row.original.id); await loadAll() }} />
        </div>
      ),
    },
  ]

  const credColumns: ColumnDef<CredentialProfileRecord, unknown>[] = [
    { accessorKey: 'name', header: t('catalog.col.name'), cell: ({ row }) => <span className="font-mono text-xs font-semibold">{row.original.name}</span> },
    { accessorKey: 'kind', header: t('catalog.col.backend'), cell: ({ row }) => <Badge variant="outline" className="font-mono text-[11px]">{row.original.kind}</Badge> },
    { accessorKey: 'access_level', header: t('catalog.col.access'), cell: ({ row }) => <Badge variant="outline" className="font-mono text-[11px]">{row.original.access_level}</Badge> },
    { id: 'state', header: t('catalog.col.secret'), cell: ({ row }) => <span className="text-xs">{row.original.has_secret ? t('catalog.secretConfigured') : t('catalog.secretMissing')}</span> },
    {
      id: 'actions',
      header: '',
      cell: ({ row }) => (
        <div className="flex justify-end gap-1.5">
          <Button size="sm" variant="outline" onClick={() => { setFormError(null); setMultilineSecret(false); setCredForm({ ...row.original, secret_value: '' }); setDialog('credentials') }}>{t('common.edit')}</Button>
          <ConfirmAction trigger={<Button size="sm" variant="ghost">{t('common.delete')}</Button>} title={t('catalog.deleteItemTitle', { name: row.original.name })} confirmLabel={t('common.delete')} cancelLabel={t('common.cancel')} destructive onConfirm={async () => { await api.deleteCredential(row.original.id); await loadAll() }} />
        </div>
      ),
    },
  ]

  return (
    <div className="space-y-5">
      <PageHeader
        title={t('catalog.title')}
        actions={
          <div className="flex flex-wrap items-center gap-2">
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button variant="outline" size="sm">
                  <Layers className="size-3.5" />
                  {t('catalog.resources')}
                  <ChevronDown className="size-3.5 opacity-60" />
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent align="end">
                <DropdownMenuItem onClick={() => setResourceSheet('instances')}>
                  <Server className="size-3.5" />
                  {t('catalog.resources.instances', { count: instances.length })}
                </DropdownMenuItem>
                <DropdownMenuItem onClick={() => setResourceSheet('networks')}>
                  <Network className="size-3.5" />
                  {t('catalog.resources.networks', { count: networks.length })}
                </DropdownMenuItem>
                <DropdownMenuItem onClick={() => setResourceSheet('credentials')}>
                  <KeyRound className="size-3.5" />
                  {t('catalog.resources.credentials', { count: credentials.length })}
                </DropdownMenuItem>
              </DropdownMenuContent>
            </DropdownMenu>
            <Button
              variant="outline"
              size="sm"
              onClick={async () => {
                try {
                  const yamlText = await api.exportTopologyYAML()
                  setTopologyText(yamlText)
                  setFormError(null)
                  setDialog('topology')
                } catch (e) {
                  toast.error(e instanceof Error ? e.message : t('catalog.exportFailed'))
                }
              }}
            >
              <Download className="size-3.5" />
              {t('catalog.topologyYaml')}
            </Button>
            <Button variant="outline" size="sm" onClick={() => void loadAll()} disabled={loading}>
              <RefreshCw className={loading ? 'animate-spin' : undefined} />
              {t('common.refresh')}
            </Button>
            <Button size="sm" onClick={openCreate}>
              <Plus />
              {t('common.new')}
            </Button>
          </div>
        }
      />

      {error && <Notice tone="error">{error}</Notice>}

      <Tabs value={subTab} onValueChange={(v) => setSubTab(v as PrimaryTab)}>
        <TabsList>
          <TabsTrigger value="targets">{t('catalog.tabs.targets', { count: filteredTargets.length })}</TabsTrigger>
          <TabsTrigger value="systems">{t('catalog.tabs.systems', { count: systems.length })}</TabsTrigger>
        </TabsList>

        <TabsContent value="targets">
          <DataTable
            columns={targetColumns}
            data={filteredTargets}
            loading={loading}
            manualFiltering
            searchValue={searchQuery}
            onSearchChange={setSearchQuery}
            searchPlaceholder={t('catalog.searchPlaceholder')}
            searchClearLabel={t('common.clearSearch')}
            searchInputClassName="sm:w-72"
            emptyLabel={t('catalog.empty.targets')}
            toolbarLeft={
              <>
                <FilterSelect
                  value={systemFilter}
                  onValueChange={setSystemFilter}
                  placeholder={t('catalog.filterSystem')}
                  options={[
                    { value: ALL_SYSTEMS, label: t('catalog.allSystems', { count: systems.length }) },
                    ...systems.map((s) => ({ value: s.id, label: `${s.name} (${s.slug})` })),
                  ]}
                />
                {(searchQuery.trim() !== '' || systemFilter !== ALL_SYSTEMS) && (
                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={() => {
                      setSearchQuery('')
                      setSystemFilter(ALL_SYSTEMS)
                    }}
                  >
                    {t('common.reset')}
                  </Button>
                )}
              </>
            }
            toolbarRight={
              <LoadingButton
                variant="outline"
                size="sm"
                pending={testingAll}
                disabled={targets.length === 0}
                onClick={() => void runTestAll()}
              >
                <Wifi className="size-3.5" />
                {t('catalog.testAll')}
              </LoadingButton>
            }
          />
        </TabsContent>
        <TabsContent value="systems">
          <DataTable
            columns={systemColumns}
            data={systems}
            loading={loading}
            searchPlaceholder={t('common.search')}
            emptyLabel={t('catalog.empty.systems')}
          />
        </TabsContent>
      </Tabs>

      <FormDialog
        open={dialog === 'add-db'}
        onOpenChange={(o) => !o && setDialog(null)}
        title={t('catalog.dialog.addDb')}
        submitLabel={t('common.save')}
        cancelLabel={t('common.cancel')}
        error={formError}
        pending={saving}
        onSubmit={handleSave}
      >
        <div className="grid grid-cols-2 gap-1 rounded-md border border-border bg-muted/40 p-1">
          <Button
            type="button"
            size="sm"
            variant={addMode === 'fields' ? 'default' : 'ghost'}
            className="h-7 text-xs"
            onClick={() => setAddMode('fields')}
          >
            {t('catalog.addDb.modeFields')}
          </Button>
          <Button
            type="button"
            size="sm"
            variant={addMode === 'uri' ? 'default' : 'ghost'}
            className="h-7 text-xs"
            onClick={() => setAddMode('uri')}
          >
            {t('catalog.addDb.modeUri')}
          </Button>
        </div>

        {addMode === 'uri' ? (
          <div className="grid gap-3 sm:grid-cols-[1fr_160px]">
            <FormField label={t('catalog.addDb.dsn')}>
              <Input
                value={addForm.dsn}
                onChange={(e) => setAddForm((p) => ({ ...p, dsn: e.target.value }))}
                placeholder={t('catalog.addDb.dsnPh')}
                className="font-mono text-xs"
              />
            </FormField>
            <FormField label={t('catalog.field.environment')}>
              <Select value={addForm.env} onValueChange={(v) => setAddForm((p) => ({ ...p, env: v }))}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>
                  {envs.map((e) => (
                    <SelectItem key={e.code} value={e.code}>
                      {resolveDisplayItem(catalog.environments, e.code, locale).label} ({e.safety_tier})
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </FormField>
          </div>
        ) : (
          <>
            <div className="grid grid-cols-2 gap-3">
              <FormField label={t('catalog.field.engine')}>
                <Select
                  value={addForm.engine}
                  onValueChange={(v) =>
                    setAddForm((p) => {
                      const prevDef = DEFAULT_ENGINE_PORTS[p.engine] ?? 0
                      const nextDef = DEFAULT_ENGINE_PORTS[v] ?? 0
                      const keepCustomPort = p.port && p.port !== prevDef && v !== 'sqlite'
                      return {
                        ...p,
                        engine: v,
                        port: v === 'sqlite' ? 0 : keepCustomPort ? p.port : nextDef,
                        host: v === 'sqlite' && p.host === '127.0.0.1' ? '' : p.host,
                      }
                    })
                  }
                >
                  <SelectTrigger><SelectValue /></SelectTrigger>
                  <SelectContent>
                    {catalog.engines.map((e) => (
                      <SelectItem key={e.code} value={e.code}>
                        {resolveDisplayItem(catalog.engines, e.code, locale).label}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </FormField>
              <FormField label={t('catalog.field.environment')}>
                <Select value={addForm.env} onValueChange={(v) => setAddForm((p) => ({ ...p, env: v }))}>
                  <SelectTrigger><SelectValue /></SelectTrigger>
                  <SelectContent>
                    {envs.map((e) => (
                      <SelectItem key={e.code} value={e.code}>
                        {resolveDisplayItem(catalog.environments, e.code, locale).label} ({e.safety_tier})
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </FormField>
            </div>
            {addForm.engine === 'sqlite' ? (
              <FormField label={t('catalog.field.sqlitePath')}>
                <Input
                  value={addForm.host}
                  onChange={(e) => setAddForm((p) => ({ ...p, host: e.target.value, port: 0 }))}
                  placeholder="~/.config/app/data.db"
                />
              </FormField>
            ) : (
              <>
                <div className="grid grid-cols-[1fr_110px] gap-3">
                  <FormField label={t('catalog.field.host')}>
                    <Input value={addForm.host} onChange={(e) => setAddForm((p) => ({ ...p, host: e.target.value }))} />
                  </FormField>
                  <FormField label={t('catalog.field.port')}>
                    <Input
                      type="number"
                      value={addForm.port}
                      onChange={(e) => setAddForm((p) => ({ ...p, port: Number(e.target.value) }))}
                    />
                  </FormField>
                </div>
                <FormField label={t('catalog.field.databaseName')}>
                  <Input
                    value={addForm.database}
                    onChange={(e) => setAddForm((p) => ({ ...p, database: e.target.value }))}
                    placeholder="orders"
                  />
                </FormField>
                {!addForm.existingCred && (
                  <div className="grid grid-cols-2 gap-3">
                    <FormField label={t('catalog.field.username')}>
                      <Input value={addForm.user} onChange={(e) => setAddForm((p) => ({ ...p, user: e.target.value }))} />
                    </FormField>
                    <FormField label={t('catalog.addDb.password')}>
                      <Input
                        type="password"
                        value={addForm.secret_value}
                        onChange={(e) => setAddForm((p) => ({ ...p, secret_value: e.target.value }))}
                        placeholder={t('catalog.addDb.passwordPh')}
                      />
                    </FormField>
                  </div>
                )}
              </>
            )}
          </>
        )}

        <div className={addForm.systemChoice === '__new__' ? 'grid grid-cols-2 gap-3' : undefined}>
          <FormField label={t('catalog.field.ownerSystem')}>
            <Select value={addForm.systemChoice} onValueChange={(v) => setAddForm((p) => ({ ...p, systemChoice: v }))}>
              <SelectTrigger><SelectValue /></SelectTrigger>
              <SelectContent>
                {systems.map((s) => (
                  <SelectItem key={s.id} value={s.id}>{s.name} ({s.slug})</SelectItem>
                ))}
                <SelectItem value="__new__">{t('catalog.addDb.newSystem')}</SelectItem>
              </SelectContent>
            </Select>
          </FormField>
          {addForm.systemChoice === '__new__' && (
            <FormField label={t('catalog.addDb.systemSlug')}>
              <Input
                value={addForm.newSystemSlug}
                onChange={(e) => setAddForm((p) => ({ ...p, newSystemSlug: e.target.value }))}
                placeholder="order-core"
              />
            </FormField>
          )}
        </div>

        <button
          type="button"
          className="flex items-center gap-1.5 text-xs font-medium text-muted-foreground hover:text-foreground"
          onClick={() => setShowAddAdvanced((v) => !v)}
        >
          {showAddAdvanced ? <ChevronDown className="size-3.5" /> : <ChevronRight className="size-3.5" />}
          {t('catalog.addDb.advanced')}
        </button>

        {showAddAdvanced && (
          <div className="space-y-3 rounded-md border border-border p-3">
            <div className="grid grid-cols-2 gap-3">
              <FormField label={t('catalog.field.alias')}>
                <Input
                  value={addForm.alias}
                  onChange={(e) => setAddForm((p) => ({ ...p, alias: e.target.value }))}
                  placeholder="prod-orders"
                />
              </FormField>
              <FormField label={t('catalog.field.ref')}>
                <Input
                  value={addForm.ref}
                  onChange={(e) => setAddForm((p) => ({ ...p, ref: e.target.value }))}
                  placeholder={t('catalog.addDb.refPh')}
                />
              </FormField>
            </div>
            <div className="grid grid-cols-2 gap-3">
              <FormField label={t('catalog.field.networkProfile')}>
                <Select
                  value={addForm.network || '__direct'}
                  onValueChange={(v) => setAddForm((p) => ({ ...p, network: v === '__direct' ? '' : v }))}
                >
                  <SelectTrigger><SelectValue /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="__direct">{t('catalog.field.directDefault')}</SelectItem>
                    {networks.map((n) => (
                      <SelectItem key={n.id} value={n.id}>{n.name} ({n.mode})</SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </FormField>
              <FormField label={t('catalog.field.accessLevel')}>
                <Select
                  value={addForm.access_level}
                  onValueChange={(v) => setAddForm((p) => ({ ...p, access_level: v as 'read_only' | 'read_write' }))}
                >
                  <SelectTrigger><SelectValue /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="read_only">read_only</SelectItem>
                    <SelectItem value="read_write">read_write</SelectItem>
                  </SelectContent>
                </Select>
              </FormField>
            </div>
            {credentials.length > 0 && (
              <FormField label={t('catalog.addDb.reuseCred')}>
                <Select
                  value={addForm.existingCred || '__auto'}
                  onValueChange={(v) => setAddForm((p) => ({ ...p, existingCred: v === '__auto' ? '' : v }))}
                >
                  <SelectTrigger><SelectValue /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="__auto">{t('catalog.addDb.autoCred')}</SelectItem>
                    {credentials.map((c) => (
                      <SelectItem key={c.id} value={c.id}>{c.name} ({c.access_level})</SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </FormField>
            )}
            <label className="flex items-center justify-between text-sm">
              <span>{t('catalog.addDb.testOnSave')}</span>
              <Switch
                checked={addForm.testOnSave}
                onCheckedChange={(c) => setAddForm((p) => ({ ...p, testOnSave: c }))}
              />
            </label>
          </div>
        )}
      </FormDialog>

      <FormDialog
        open={dialog === 'systems'}
        onOpenChange={(o) => !o && setDialog(null)}
        title={sysForm.id ? t('catalog.dialog.editSystem') : t('catalog.dialog.newSystem')}
        submitLabel={t('common.save')}
        cancelLabel={t('common.cancel')}
        error={formError}
        pending={saving}
        onSubmit={handleSave}
      >
        <FormField label={t('catalog.field.slug')}>
          <Input value={sysForm.slug} onChange={(e) => setSysForm((p) => ({ ...p, slug: e.target.value }))} placeholder="order-core" />
        </FormField>
        <FormField label={t('catalog.field.name')}>
          <Input value={sysForm.name} onChange={(e) => setSysForm((p) => ({ ...p, name: e.target.value }))} placeholder="Order Core" />
        </FormField>
        <FormField label={t('catalog.field.owner')}>
          <Input value={sysForm.owner} onChange={(e) => setSysForm((p) => ({ ...p, owner: e.target.value }))} placeholder="commerce-platform" />
        </FormField>
        <FormField label={t('catalog.field.description')}>
          <Input value={sysForm.description} onChange={(e) => setSysForm((p) => ({ ...p, description: e.target.value }))} />
        </FormField>
        <FormField label={t('catalog.field.tags')}>
          <Input value={sysForm.tags} onChange={(e) => setSysForm((p) => ({ ...p, tags: e.target.value }))} placeholder="core, payments" />
        </FormField>
        <FormField label={t('catalog.field.workspaces')}>
          <Textarea rows={3} value={sysForm.workspace_paths} onChange={(e) => setSysForm((p) => ({ ...p, workspace_paths: e.target.value }))} placeholder="~/Codes/order-core" />
        </FormField>
        <FormField label={t('catalog.field.gitRemotes')}>
          <Textarea rows={2} value={sysForm.git_remotes} onChange={(e) => setSysForm((p) => ({ ...p, git_remotes: e.target.value }))} placeholder="github.com/org/order-core" />
        </FormField>
      </FormDialog>

      <FormDialog
        open={dialog === 'instances'}
        onOpenChange={(o) => !o && setDialog(null)}
        title={instForm.id ? t('catalog.dialog.editInstance') : t('catalog.dialog.newInstance')}
        submitLabel={t('common.save')}
        cancelLabel={t('common.cancel')}
        error={formError}
        pending={saving}
        onSubmit={handleSave}
      >
        <FormField label={t('catalog.field.name')}>
          <Input value={instForm.name ?? ''} onChange={(e) => setInstForm((p) => ({ ...p, name: e.target.value }))} placeholder="rds-order-prod-01" />
        </FormField>
        {renderScopeFields(instForm.scope_type, instForm.scope_id, (sc) => setInstForm((p) => ({ ...p, ...sc })))}
        <div className="grid grid-cols-2 gap-3">
          <FormField label={t('catalog.field.engine')}>
            <Select
              value={instForm.engine ?? 'postgres'}
              onValueChange={(v) =>
                setInstForm((p) => {
                  const prevDef = DEFAULT_ENGINE_PORTS[p.engine ?? 'postgres'] ?? 0
                  const nextDef = DEFAULT_ENGINE_PORTS[v] ?? 0
                  const keepCustomPort = p.port && p.port !== prevDef && v !== 'sqlite'
                  return {
                    ...p,
                    engine: v,
                    port: v === 'sqlite' ? 0 : keepCustomPort ? p.port : nextDef,
                    host: v === 'sqlite' && p.host === '127.0.0.1' ? '' : p.host,
                  }
                })
              }
            >
              <SelectTrigger><SelectValue /></SelectTrigger>
              <SelectContent>
                {instForm.engine && !catalog.engines.some((e) => e.code === instForm.engine) && (
                  <SelectItem value={instForm.engine}>{instForm.engine}</SelectItem>
                )}
                {catalog.engines.map((e) => (
                  <SelectItem key={e.code} value={e.code}>
                    {resolveDisplayItem(catalog.engines, e.code, locale).label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </FormField>
          <FormField label={t('catalog.field.role')}>
            <Select
              value={instForm.role ?? 'standalone'}
              onValueChange={(v) =>
                setInstForm((p) => ({
                  ...p,
                  role: v as InstanceRecord['role'],
                  primary_instance_id: v === 'replica' ? (p.primary_instance_id ?? '') : '',
                }))
              }
            >
              <SelectTrigger><SelectValue /></SelectTrigger>
              <SelectContent>
                <SelectItem value="standalone">standalone</SelectItem>
                <SelectItem value="primary">primary</SelectItem>
                <SelectItem value="replica">replica</SelectItem>
              </SelectContent>
            </Select>
          </FormField>
        </div>
        {instForm.role === 'replica' && (
          <FormField label={t('catalog.field.primaryInstance')}>
            <Select
              value={instForm.primary_instance_id || '__none'}
              onValueChange={(v) => setInstForm((p) => ({ ...p, primary_instance_id: v === '__none' ? '' : v }))}
            >
              <SelectTrigger><SelectValue placeholder={t('catalog.field.selectPrimary')} /></SelectTrigger>
              <SelectContent>
                <SelectItem value="__none">{t('common.none')}</SelectItem>
                {instances
                  .filter((candidate) => candidate.id !== instForm.id && candidate.role === 'primary')
                  .map((candidate) => (
                    <SelectItem key={candidate.id} value={candidate.id}>
                      {candidate.name} ({candidate.engine})
                    </SelectItem>
                  ))}
              </SelectContent>
            </Select>
          </FormField>
        )}
        {instForm.engine === 'sqlite' ? (
          <FormField label={t('catalog.field.sqlitePath')}>
            <Input
              value={instForm.host ?? ''}
              onChange={(e) => setInstForm((p) => ({ ...p, host: e.target.value, port: 0 }))}
              placeholder="~/.config/app/data.db"
            />
          </FormField>
        ) : (
          <>
            <div className="grid grid-cols-[1fr_110px] gap-3">
              <FormField label={t('catalog.field.host')}>
                <Input value={instForm.host ?? ''} onChange={(e) => setInstForm((p) => ({ ...p, host: e.target.value }))} />
              </FormField>
              <FormField label={t('catalog.field.port')}>
                <Input type="number" value={instForm.port ?? 0} onChange={(e) => setInstForm((p) => ({ ...p, port: Number(e.target.value) }))} />
              </FormField>
            </div>
            <div className="grid grid-cols-2 gap-3">
              <FormField label={t('catalog.field.networkProfile')}>
                <Select value={instForm.network_profile_id || '__direct'} onValueChange={(v) => setInstForm((p) => ({ ...p, network_profile_id: v === '__direct' ? '' : v }))}>
                  <SelectTrigger><SelectValue /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="__direct">{t('catalog.field.directDefault')}</SelectItem>
                    {networks.map((n) => (
                      <SelectItem key={n.id} value={n.id}>{n.name} ({n.mode})</SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </FormField>
              <FormField label={t('catalog.field.tlsMode')}>
                <Select value={instForm.tls_mode || 'prefer'} onValueChange={(v) => setInstForm((p) => ({ ...p, tls_mode: v }))}>
                  <SelectTrigger><SelectValue /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="prefer">prefer</SelectItem>
                    <SelectItem value="disable">disable</SelectItem>
                    <SelectItem value="require">require</SelectItem>
                    <SelectItem value="verify-ca">verify-ca</SelectItem>
                    <SelectItem value="verify-full">verify-full</SelectItem>
                  </SelectContent>
                </Select>
              </FormField>
            </div>
          </>
        )}
      </FormDialog>

      <FormDialog
        open={dialog === 'targets'}
        onOpenChange={(o) => !o && setDialog(null)}
        title={targetForm.id ? t('catalog.dialog.editTarget') : t('catalog.dialog.newTarget')}
        submitLabel={t('common.save')}
        cancelLabel={t('common.cancel')}
        error={formError}
        pending={saving}
        onSubmit={handleSave}
      >
        <div className="grid grid-cols-2 gap-3">
          <FormField label={t('catalog.field.ref')}>
            <Input value={targetForm.ref ?? ''} onChange={(e) => setTargetForm((p) => ({ ...p, ref: e.target.value }))} placeholder="order-core/prod/orders" />
          </FormField>
          <FormField label={t('catalog.field.alias')}>
            <Input value={targetForm.alias ?? ''} onChange={(e) => setTargetForm((p) => ({ ...p, alias: e.target.value }))} placeholder="prod-orders" />
          </FormField>
        </div>
        <div className="grid grid-cols-2 gap-3">
          <FormField label={t('catalog.field.ownerSystem')}>
            <Select
              value={targetForm.owner_system_id ?? ''}
              onValueChange={(v) =>
                setTargetForm((p) => ({
                  ...p,
                  owner_system_id: v,
                  linked_system_ids: (p.linked_system_ids ?? []).filter((id) => id !== v),
                }))
              }
            >
              <SelectTrigger><SelectValue placeholder={t('catalog.field.selectSystem')} /></SelectTrigger>
              <SelectContent>
                {systems.map((s) => (
                  <SelectItem key={s.id} value={s.id}>{s.name} ({s.slug})</SelectItem>
                ))}
              </SelectContent>
            </Select>
          </FormField>
          <FormField label={t('catalog.field.environment')}>
            <Select value={targetForm.environment_code ?? 'dev'} onValueChange={(v) => setTargetForm((p) => ({ ...p, environment_code: v }))}>
              <SelectTrigger><SelectValue /></SelectTrigger>
              <SelectContent>
                {envs.map((e) => (
                  <SelectItem key={e.code} value={e.code}>
                    {resolveDisplayItem(catalog.environments, e.code, locale).label} ({e.safety_tier})
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </FormField>
        </div>
        {systems.some((s) => s.id !== targetForm.owner_system_id) && (
          <FormField label={t('catalog.field.linkedSystems')}>
            <div className="flex flex-wrap gap-1.5">
              {systems
                .filter((s) => s.id !== targetForm.owner_system_id)
                .map((s) => {
                  const active = (targetForm.linked_system_ids ?? []).includes(s.id)
                  return (
                    <Button
                      key={s.id}
                      type="button"
                      size="sm"
                      variant={active ? 'default' : 'outline'}
                      className="h-7 px-2 font-mono text-xs"
                      onClick={() =>
                        setTargetForm((p) => {
                          const cur = p.linked_system_ids ?? []
                          const next = cur.includes(s.id) ? cur.filter((id) => id !== s.id) : [...cur, s.id]
                          return { ...p, linked_system_ids: next }
                        })
                      }
                    >
                      {s.slug}
                    </Button>
                  )
                })}
            </div>
          </FormField>
        )}
        <div className="grid grid-cols-2 gap-3">
          <FormField label={t('catalog.field.instance')}>
            <Select value={targetForm.instance_id ?? ''} onValueChange={(v) => setTargetForm((p) => ({ ...p, instance_id: v }))}>
              <SelectTrigger><SelectValue placeholder={t('catalog.field.selectInstance')} /></SelectTrigger>
              <SelectContent>
                {instances.map((i) => (
                  <SelectItem key={i.id} value={i.id}>{i.name} ({i.engine})</SelectItem>
                ))}
              </SelectContent>
            </Select>
          </FormField>
          <FormField label={t('catalog.field.databaseName')}>
            <Input value={targetForm.database_name ?? ''} onChange={(e) => setTargetForm((p) => ({ ...p, database_name: e.target.value }))} />
          </FormField>
        </div>
        <div className="grid grid-cols-2 gap-3">
          <FormField label={t('catalog.field.roCredential')}>
            <Select value={targetForm.ro_credential_id || '__none'} onValueChange={(v) => setTargetForm((p) => ({ ...p, ro_credential_id: v === '__none' ? '' : v }))}>
              <SelectTrigger><SelectValue /></SelectTrigger>
              <SelectContent>
                <SelectItem value="__none">{t('common.none')}</SelectItem>
                {credentials.map((c) => (
                  <SelectItem key={c.id} value={c.id}>{c.name} ({c.access_level})</SelectItem>
                ))}
              </SelectContent>
            </Select>
          </FormField>
          <FormField label={t('catalog.field.rwCredential')}>
            <Select value={targetForm.rw_credential_id || '__none'} onValueChange={(v) => setTargetForm((p) => ({ ...p, rw_credential_id: v === '__none' ? '' : v }))}>
              <SelectTrigger><SelectValue /></SelectTrigger>
              <SelectContent>
                <SelectItem value="__none">{t('common.none')}</SelectItem>
                {credentials.map((c) => (
                  <SelectItem key={c.id} value={c.id}>{c.name} ({c.access_level})</SelectItem>
                ))}
              </SelectContent>
            </Select>
          </FormField>
        </div>
        <FormField label={t('catalog.field.status')}>
          <Select value={targetForm.status ?? 'active'} onValueChange={(v) => setTargetForm((p) => ({ ...p, status: v as TargetRecord['status'] }))}>
            <SelectTrigger><SelectValue /></SelectTrigger>
            <SelectContent>
              <SelectItem value="active">{t('catalog.status.active')}</SelectItem>
              <SelectItem value="maintenance">{t('catalog.status.maintenance')}</SelectItem>
              <SelectItem value="disabled">{t('catalog.status.disabled')}</SelectItem>
            </SelectContent>
          </Select>
        </FormField>
      </FormDialog>

      <FormDialog
        open={dialog === 'networks'}
        onOpenChange={(o) => !o && setDialog(null)}
        title={netForm.id ? t('catalog.dialog.editNetwork') : t('catalog.dialog.newNetwork')}
        submitLabel={t('common.save')}
        cancelLabel={t('common.cancel')}
        error={formError}
        pending={saving}
        onSubmit={handleSave}
      >
        <FormField label={t('catalog.field.name')}>
          <Input value={netForm.name ?? ''} onChange={(e) => setNetForm((p) => ({ ...p, name: e.target.value }))} />
        </FormField>
        {renderScopeFields(netForm.scope_type, netForm.scope_id, (sc) => setNetForm((p) => ({ ...p, ...sc })))}
        <FormField label={t('catalog.field.mode')}>
          <Select value={netForm.mode ?? 'direct'} onValueChange={(v) => setNetForm((p) => ({ ...p, mode: v as NetworkProfileRecord['mode'] }))}>
            <SelectTrigger><SelectValue /></SelectTrigger>
            <SelectContent>
              <SelectItem value="direct">direct</SelectItem>
              <SelectItem value="ssh_tunnel">ssh_tunnel</SelectItem>
              <SelectItem value="socks5">socks5</SelectItem>
              <SelectItem value="http_proxy">http_proxy</SelectItem>
            </SelectContent>
          </Select>
        </FormField>
        {netForm.mode === 'ssh_tunnel' && (
          <>
            <div className="grid grid-cols-[1fr_100px] gap-3">
              <FormField label={t('catalog.field.bastionHost')}><Input value={netForm.bastion_host ?? ''} onChange={(e) => setNetForm((p) => ({ ...p, bastion_host: e.target.value }))} /></FormField>
              <FormField label={t('catalog.field.port')}><Input type="number" value={netForm.bastion_port ?? 22} onChange={(e) => setNetForm((p) => ({ ...p, bastion_port: Number(e.target.value) }))} /></FormField>
            </div>
            <FormField label={t('catalog.field.bastionUser')}><Input value={netForm.bastion_user ?? ''} onChange={(e) => setNetForm((p) => ({ ...p, bastion_user: e.target.value }))} /></FormField>
            <FormField label={t('catalog.field.bastionCred')}>
              <Select value={netForm.bastion_credential_id || '__none'} onValueChange={(v) => setNetForm((p) => ({ ...p, bastion_credential_id: v === '__none' ? '' : v }))}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="__none">{t('catalog.field.noneSshAgent')}</SelectItem>
                  {credentials.map((c) => <SelectItem key={c.id} value={c.id}>{c.name}</SelectItem>)}
                </SelectContent>
              </Select>
            </FormField>
            <div className="flex items-center justify-between">
              <span className="text-sm">{t('catalog.field.strictHostKey')}</span>
              <Switch checked={Boolean(netForm.ssh_strict_host_key)} onCheckedChange={(c) => setNetForm((p) => ({ ...p, ssh_strict_host_key: c }))} />
            </div>
          </>
        )}
        {(netForm.mode === 'socks5' || netForm.mode === 'http_proxy') && (
          <FormField label={t('catalog.field.proxyUrl')}><Input value={netForm.proxy_url ?? ''} onChange={(e) => setNetForm((p) => ({ ...p, proxy_url: e.target.value }))} placeholder="socks5://127.0.0.1:1080" /></FormField>
        )}
      </FormDialog>

      <FormDialog
        open={dialog === 'credentials'}
        onOpenChange={(o) => !o && setDialog(null)}
        title={credForm.id ? t('catalog.dialog.editCredential') : t('catalog.dialog.newCredential')}
        submitLabel={t('common.save')}
        cancelLabel={t('common.cancel')}
        error={formError}
        pending={saving}
        onSubmit={handleSave}
      >
        <FormField label={t('catalog.field.name')}>
          <Input value={credForm.name ?? ''} onChange={(e) => setCredForm((p) => ({ ...p, name: e.target.value }))} />
        </FormField>
        {renderScopeFields(credForm.scope_type, credForm.scope_id, (sc) => setCredForm((p) => ({ ...p, ...sc })))}
        <div className="grid grid-cols-2 gap-3">
          <FormField label={t('catalog.field.kind')}>
            <Select value={credForm.kind ?? 'keychain'} onValueChange={(v) => setCredForm((p) => ({ ...p, kind: v as CredentialProfileRecord['kind'] }))}>
              <SelectTrigger><SelectValue /></SelectTrigger>
              <SelectContent>
                <SelectItem value="keychain">keychain</SelectItem>
                <SelectItem value="env_ref">env_ref</SelectItem>
                <SelectItem value="exec_provider">exec_provider</SelectItem>
              </SelectContent>
            </Select>
          </FormField>
          <FormField label={t('catalog.field.accessLevel')}>
            <Select value={credForm.access_level ?? 'read_only'} onValueChange={(v) => setCredForm((p) => ({ ...p, access_level: v as CredentialProfileRecord['access_level'] }))}>
              <SelectTrigger><SelectValue /></SelectTrigger>
              <SelectContent>
                <SelectItem value="read_only">read_only</SelectItem>
                <SelectItem value="read_write">read_write</SelectItem>
              </SelectContent>
            </Select>
          </FormField>
        </div>
        <FormField label={t('catalog.field.username')}>
          <Input value={credForm.username ?? ''} onChange={(e) => setCredForm((p) => ({ ...p, username: e.target.value }))} />
        </FormField>
        {credForm.kind === 'keychain' && (
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-xs font-medium text-muted-foreground">{t('catalog.field.secretHeader')}</span>
              <label className="flex cursor-pointer items-center gap-1.5 text-xs text-muted-foreground">
                <Switch checked={multilineSecret} onCheckedChange={setMultilineSecret} />
                <span>{t('catalog.field.multilineKey')}</span>
              </label>
            </div>
            {multilineSecret ? (
              <Textarea
                rows={5}
                className="font-mono text-xs"
                value={credForm.secret_value ?? ''}
                onChange={(e) => setCredForm((p) => ({ ...p, secret_value: e.target.value }))}
                placeholder={
                  credForm.id && credForm.has_secret
                    ? t('catalog.field.secretKeep')
                    : t('catalog.field.secretKeyPlaceholder')
                }
              />
            ) : (
              <Input
                type="password"
                autoFocus={Boolean(credForm.id && !credForm.has_secret)}
                value={credForm.secret_value ?? ''}
                onChange={(e) => setCredForm((p) => ({ ...p, secret_value: e.target.value }))}
                placeholder={
                  credForm.id && credForm.has_secret
                    ? t('catalog.field.secretKeep')
                    : t('catalog.field.secretPwdPlaceholder')
                }
              />
            )}
          </div>
        )}
        {credForm.kind === 'env_ref' && (
          <FormField label={t('catalog.field.envVarName')}>
            <Input value={credForm.env_var_name ?? ''} onChange={(e) => setCredForm((p) => ({ ...p, env_var_name: e.target.value }))} placeholder="PROD_DB_PASSWORD" />
          </FormField>
        )}
        {credForm.kind === 'exec_provider' && (
          <FormField label={t('catalog.field.execCmd')}>
            <Input value={credForm.exec_command ?? ''} onChange={(e) => setCredForm((p) => ({ ...p, exec_command: e.target.value }))} placeholder="op read op://prod/db/password" />
          </FormField>
        )}
      </FormDialog>

      <FormDialog
        open={dialog === 'topology'}
        onOpenChange={(o) => !o && setDialog(null)}
        title={t('catalog.dialog.topologyTitle')}
        submitLabel={t('catalog.dialog.topologySubmit')}
        cancelLabel={t('common.cancel')}
        error={formError}
        pending={saving}
        onSubmit={handleSave}
        maxWidthClassName="sm:max-w-[680px]"
      >
        <FormField label={t('catalog.field.topologyText')}>
          <Textarea rows={14} className="font-mono text-xs" value={topologyText} onChange={(e) => setTopologyText(e.target.value)} />
        </FormField>
        <div className="flex justify-start">
          <Button
            type="button"
            variant="outline"
            size="sm"
            onClick={() => {
              const blob = new Blob([topologyText], { type: 'application/yaml' })
              const url = URL.createObjectURL(blob)
              const a = document.createElement('a')
              a.href = url
              a.download = 'agent-dbctl-topology.yaml'
              a.click()
              URL.revokeObjectURL(url)
            }}
          >
            <Upload className="size-3.5" />
            {t('catalog.downloadYaml')}
          </Button>
        </div>
      </FormDialog>

      <Sheet open={Boolean(resourceSheet)} onOpenChange={(o) => !o && setResourceSheet(null)}>
        <SheetContent className="w-full sm:max-w-3xl">
          <SheetHeader>
            <SheetTitle>
              {resourceSheet === 'instances' && t('catalog.resources.instances', { count: instances.length })}
              {resourceSheet === 'networks' && t('catalog.resources.networks', { count: networks.length })}
              {resourceSheet === 'credentials' && t('catalog.resources.credentials', { count: credentials.length })}
            </SheetTitle>
          </SheetHeader>
          <SheetBody>
            {resourceSheet && (
              <>
                {resourceSheet === 'instances' && (
                  <DataTable
                    columns={instanceColumns}
                    data={instances}
                    searchPlaceholder={t('common.search')}
                    emptyLabel={t('catalog.empty.instances')}
                    toolbarRight={
                      <Button size="sm" onClick={() => openResourceCreate('instances')}>
                        <Plus className="size-3.5" />
                        {t('catalog.resources.newInstance')}
                      </Button>
                    }
                  />
                )}
                {resourceSheet === 'networks' && (
                  <DataTable
                    columns={netColumns}
                    data={networks}
                    searchPlaceholder={t('common.search')}
                    emptyLabel={t('catalog.empty.networks')}
                    toolbarRight={
                      <Button size="sm" onClick={() => openResourceCreate('networks')}>
                        <Plus className="size-3.5" />
                        {t('catalog.resources.newNetwork')}
                      </Button>
                    }
                  />
                )}
                {resourceSheet === 'credentials' && (
                  <DataTable
                    columns={credColumns}
                    data={credentials}
                    searchPlaceholder={t('common.search')}
                    emptyLabel={t('catalog.empty.credentials')}
                    toolbarRight={
                      <Button size="sm" onClick={() => openResourceCreate('credentials')}>
                        <Plus className="size-3.5" />
                        {t('catalog.resources.newCredential')}
                      </Button>
                    }
                  />
                )}
              </>
            )}
          </SheetBody>
        </SheetContent>
      </Sheet>

      <Sheet open={Boolean(discoverSheet)} onOpenChange={(o) => !o && setDiscoverSheet(null)}>
        <SheetContent>
          <SheetHeader>
            <SheetTitle>{t('catalog.discoverTitle', { name: discoverSheet?.instance.name ?? '' })}</SheetTitle>
          </SheetHeader>
          <SheetBody>
            {discoverSheet && (
              <div className="space-y-3">
                <div className="flex items-end gap-2">
                  <div className="flex-1">
                    <FormField label={t('catalog.field.credential')}>
                      <Select
                        value={discoverSheet.credentialId || '__none'}
                        onValueChange={(v) => {
                          const cid = v === '__none' ? '' : v
                          void runDiscover(discoverSheet.instance, cid)
                        }}
                      >
                        <SelectTrigger><SelectValue /></SelectTrigger>
                        <SelectContent>
                          <SelectItem value="__none">{t('common.none')}</SelectItem>
                          {credentials.map((c) => (
                            <SelectItem key={c.id} value={c.id}>{c.name} ({c.access_level})</SelectItem>
                          ))}
                        </SelectContent>
                      </Select>
                    </FormField>
                  </div>
                  <LoadingButton
                    size="sm"
                    variant="outline"
                    pending={discoverSheet.loading}
                    onClick={() => void runDiscover(discoverSheet.instance, discoverSheet.credentialId)}
                  >
                    <RefreshCw className="size-3.5" />
                    {t('catalog.scan')}
                  </LoadingButton>
                </div>

                {discoverSheet.error && <Notice tone="error">{discoverSheet.error}</Notice>}

                <div className="space-y-2">
                  {discoverSheet.databases.map((dbName) => (
                    <div key={dbName} className="flex items-center justify-between rounded-md border border-border px-3 py-2">
                      <span className="truncate font-mono text-xs">{dbName}</span>
                      <Button
                        size="sm"
                        variant="outline"
                        onClick={() => {
                          const inst = discoverSheet.instance
                          const defSys = systemFilter !== ALL_SYSTEMS ? systemFilter : (systems[0]?.id ?? '')
                          const sysSlug = systems.find((s) => s.id === defSys)?.slug ?? 'system'
                          setTargetForm({
                            id: '',
                            ref: `${sysSlug}/dev/${dbName.replace(/[^A-Za-z0-9_-]/g, '_')}`,
                            alias: '',
                            owner_system_id: defSys,
                            environment_code: envs[0]?.code ?? 'dev',
                            instance_id: inst.id,
                            database_name: dbName,
                            ro_credential_id: discoverSheet.credentialId || '',
                            status: 'active',
                          })
                          setDiscoverSheet(null)
                          setDialog('targets')
                        }}
                      >
                        {t('catalog.attach')}
                      </Button>
                    </div>
                  ))}
                  {!discoverSheet.loading && !discoverSheet.error && discoverSheet.databases.length === 0 && (
                    <div className="py-6 text-center text-xs text-muted-foreground">{t('catalog.noDiscovered')}</div>
                  )}
                </div>
              </div>
            )}
          </SheetBody>
        </SheetContent>
      </Sheet>
    </div>
  )
}
