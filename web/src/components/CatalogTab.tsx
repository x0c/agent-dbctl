import {
  Badge,
  Button,
  type ColumnDef,
  ConfirmAction,
  DataTable,
  FormDialog,
  FormField,
  Input,
  LoadingButton,
  Notice,
  PageHeader,
  Panel,
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
import { Download, FolderGit2, Plus, RefreshCw, Search, Upload, Wifi } from 'lucide-react'
import { useEffect, useMemo, useState } from 'react'
import {
  api,
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
import { MetaBadge } from './MetaBadge'

type SubTab = 'targets' | 'systems' | 'instances' | 'networks' | 'credentials' | 'environments'

const ALL_SYSTEMS = '__all__'

const DEFAULT_ENGINE_PORTS: Record<string, number> = {
  postgres: 5432,
  mysql: 3306,
  mongodb: 27017,
  redis: 6379,
  sqlite: 0,
}

export function CatalogTab({ catalog, onRefreshBootstrap }: { catalog: DisplayCatalog; onRefreshBootstrap: () => Promise<void> }) {
  const [subTab, setSubTab] = useState<SubTab>('targets')
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

  const [dialog, setDialog] = useState<SubTab | 'topology' | null>(null)
  const [saving, setSaving] = useState(false)
  const [formError, setFormError] = useState<string | null>(null)

  const [sysForm, setSysForm] = useState({ id: '', slug: '', name: '', owner: '', description: '', tags: '', workspace_paths: '' })
  const [envForm, setEnvForm] = useState<EnvironmentRecord>({
    code: '',
    safety_tier: 'guarded',
    labels: { en: '', zh: '' },
    color: '#D97706',
    sort_order: 25,
  })
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
      setError(e instanceof Error ? e.message : 'Failed to load catalog')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    void loadAll()
  }, [])

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
      if (okCount === total) toast.success(`All ${total} targets reachable`)
      else toast.info(`${okCount}/${total} targets reachable`)
    } catch (e) {
      toast.error(e instanceof Error ? e.message : 'Batch test failed')
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
        error: e instanceof Error ? e.message : 'Discovery failed',
      })
    }
  }

  const openCreate = () => {
    setFormError(null)
    if (subTab === 'systems') {
      setSysForm({ id: '', slug: '', name: '', owner: '', description: '', tags: '', workspace_paths: '' })
    } else if (subTab === 'environments') {
      setEnvForm({ code: '', safety_tier: 'guarded', labels: { en: '', zh: '' }, color: '#D97706', sort_order: 25 })
    } else if (subTab === 'networks') {
      setNetForm({ id: '', name: '', mode: 'direct', proxy_url: '', bastion_host: '', bastion_port: 22, bastion_user: '', bastion_credential_id: '', ssh_strict_host_key: true, tls_mode: 'prefer' })
    } else if (subTab === 'credentials') {
      setMultilineSecret(false)
      setCredForm({ id: '', name: '', kind: 'keychain', access_level: 'read_only', username: '', env_var_name: '', exec_command: '', secret_value: '' })
    } else if (subTab === 'instances') {
      setInstForm({ id: '', name: '', engine: 'postgres', host: '127.0.0.1', port: 5432, role: 'standalone', primary_instance_id: '', network_profile_id: '', tls_mode: 'prefer' })
    } else {
      const defSys = systemFilter !== ALL_SYSTEMS ? systemFilter : (systems[0]?.id ?? '')
      setTargetForm({
        id: '',
        ref: '',
        alias: '',
        owner_system_id: defSys,
        linked_system_ids: [],
        environment_code: envs[0]?.code ?? 'dev',
        instance_id: instances[0]?.id ?? '',
        database_name: '',
        ro_credential_id: '',
        rw_credential_id: '',
        status: 'active',
        description: '',
      })
    }
    setDialog(subTab)
  }

  const handleSave = async () => {
    setSaving(true)
    setFormError(null)
    try {
      if (dialog === 'systems') {
        await api.saveSystem({
          id: sysForm.id || undefined,
          slug: sysForm.slug.trim(),
          name: sysForm.name.trim(),
          owner: sysForm.owner.trim(),
          description: sysForm.description.trim(),
          tags: sysForm.tags.split(',').map((s) => s.trim()).filter(Boolean),
          workspace_paths: sysForm.workspace_paths.split('\n').map((s) => s.trim()).filter(Boolean),
        })
      } else if (dialog === 'environments') {
        await api.saveEnvironment(envForm)
        await onRefreshBootstrap()
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
      toast.success('Saved')
      await loadAll()
    } catch (e) {
      setFormError(e instanceof Error ? e.message : 'Save failed')
    } finally {
      setSaving(false)
    }
  }

  const targetColumns: ColumnDef<TargetDetail, unknown>[] = [
    {
      accessorKey: 'target.ref',
      header: 'Target',
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
      header: 'System',
      cell: ({ row }) => (
        <span className="block max-w-[110px] truncate font-mono text-xs">
          {row.original.owner_system?.slug ?? row.original.target.owner_system_id}
          {(row.original.linked_systems?.length ?? 0) > 0 && ` (+${row.original.linked_systems?.length})`}
        </span>
      ),
    },
    {
      id: 'env',
      header: 'Env',
      cell: ({ row }) => <MetaBadge items={catalog.environments} code={row.original.target.environment_code} />,
    },
    {
      id: 'engine',
      header: 'Engine',
      cell: ({ row }) =>
        row.original.instance ? <MetaBadge items={catalog.engines} code={row.original.instance.engine} /> : '—',
    },
    {
      id: 'health',
      header: 'Status',
      cell: ({ row }) => {
        const p = pingByTargetRef[row.original.target.ref]
        if (!p) {
          return <span className="font-mono text-xs text-muted-foreground">{row.original.target.status}</span>
        }
        return p.reachable ? (
          <StatusDot tone="success">
            <span className="font-mono text-xs" title={p.server_version || 'Reachable'}>
              {p.latency_ms}ms
            </span>
          </StatusDot>
        ) : (
          <StatusDot tone="danger">
            <span className="max-w-[110px] truncate font-mono text-xs text-red-700" title={p.error || 'Unreachable'}>
              Unreachable
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
                if (res.reachable) toast.success(`Reachable (${res.latency_ms}ms, v${res.server_version || '?'})`)
                else toast.error(res.error || 'Unreachable')
              } catch (e) {
                toast.error(e instanceof Error ? e.message : 'Ping failed')
              } finally {
                setTestingTargetId(null)
              }
            }}
          >
            <Wifi className="size-3.5" />
            Test
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
            Edit
          </Button>
          <ConfirmAction
            trigger={<Button size="sm" variant="ghost">Delete</Button>}
            title={`Delete ${row.original.target.ref}?`}
            description="Historical audit logs remain intact."
            confirmLabel="Delete"
            destructive
            onConfirm={async () => {
              await api.deleteTarget(row.original.target.id)
              toast.success('Target deleted')
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
      header: 'Slug',
      cell: ({ row }) => <span className="font-mono text-xs font-semibold">{row.original.slug}</span>,
    },
    { accessorKey: 'name', header: 'Name' },
    {
      accessorKey: 'owner',
      header: 'Owner',
      cell: ({ row }) => <span className="text-xs text-muted-foreground">{row.original.owner || '—'}</span>,
    },
    {
      id: 'workspaces',
      header: 'Workspaces',
      cell: ({ row }) => (
        <span className="inline-flex items-center gap-1 font-mono text-xs text-muted-foreground">
          <FolderGit2 className="size-3.5" />
          {row.original.workspace_paths?.length ?? 0}
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
              })
              setDialog('systems')
            }}
          >
            Edit
          </Button>
          <ConfirmAction
            trigger={<Button size="sm" variant="ghost">Delete</Button>}
            title={`Delete system ${row.original.slug}?`}
            description="Systems with attached targets cannot be deleted."
            confirmLabel="Delete"
            destructive
            onConfirm={async () => {
              try {
                await api.deleteSystem(row.original.id)
                toast.success('System deleted')
                await loadAll()
              } catch (e) {
                toast.error(e instanceof Error ? e.message : 'Delete failed')
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
      header: 'Instance',
      cell: ({ row }) => (
        <span className="block max-w-[150px] truncate font-mono text-xs font-semibold" title={row.original.name}>
          {row.original.name}
        </span>
      ),
    },
    {
      accessorKey: 'engine',
      header: 'Engine',
      cell: ({ row }) => <MetaBadge items={catalog.engines} code={row.original.engine} />,
    },
    {
      id: 'endpoint',
      header: 'Endpoint',
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
      header: 'Role',
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
                if (res.reachable) toast.success(`Reachable (${res.latency_ms}ms, v${res.server_version || '?'})`)
                else toast.error(res.error || 'Unreachable')
              } catch (e) {
                toast.error(e instanceof Error ? e.message : 'Ping failed')
              } finally {
                setTestingInstanceId(null)
              }
            }}
          >
            <Wifi className="size-3.5" />
            Test
          </LoadingButton>
          <Button
            size="sm"
            variant="outline"
            onClick={() => void runDiscover(row.original, defaultCredForInstance(row.original.id))}
          >
            <Search className="size-3.5" />
            Discover
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
            Edit
          </Button>
          <ConfirmAction
            trigger={<Button size="sm" variant="ghost">Delete</Button>}
            title={`Delete instance ${row.original.name}?`}
            confirmLabel="Delete"
            destructive
            onConfirm={async () => {
              try {
                await api.deleteInstance(row.original.id)
                toast.success('Instance deleted')
                await loadAll()
              } catch (e) {
                toast.error(e instanceof Error ? e.message : 'Delete failed')
              }
            }}
          />
        </div>
      ),
    },
  ]

  const netColumns: ColumnDef<NetworkProfileRecord, unknown>[] = [
    { accessorKey: 'name', header: 'Name', cell: ({ row }) => <span className="font-mono text-xs font-semibold">{row.original.name}</span> },
    { accessorKey: 'mode', header: 'Mode', cell: ({ row }) => <Badge variant="outline" className="font-mono text-[11px]">{row.original.mode}</Badge> },
    { id: 'detail', header: 'Endpoint', cell: ({ row }) => <span className="font-mono text-xs text-muted-foreground">{row.original.bastion_host || row.original.proxy_url || 'Direct'}</span> },
    {
      id: 'actions',
      header: '',
      cell: ({ row }) => (
        <div className="flex justify-end gap-1.5">
          <Button size="sm" variant="outline" onClick={() => { setFormError(null); setNetForm({ ...row.original }); setDialog('networks') }}>Edit</Button>
          <ConfirmAction trigger={<Button size="sm" variant="ghost">Delete</Button>} title={`Delete ${row.original.name}?`} confirmLabel="Delete" destructive onConfirm={async () => { await api.deleteNetworkProfile(row.original.id); await loadAll() }} />
        </div>
      ),
    },
  ]

  const credColumns: ColumnDef<CredentialProfileRecord, unknown>[] = [
    { accessorKey: 'name', header: 'Name', cell: ({ row }) => <span className="font-mono text-xs font-semibold">{row.original.name}</span> },
    { accessorKey: 'kind', header: 'Backend', cell: ({ row }) => <Badge variant="outline" className="font-mono text-[11px]">{row.original.kind}</Badge> },
    { accessorKey: 'access_level', header: 'Access', cell: ({ row }) => <Badge variant="outline" className="font-mono text-[11px]">{row.original.access_level}</Badge> },
    { id: 'state', header: 'Secret', cell: ({ row }) => <span className="text-xs">{row.original.has_secret ? 'Configured' : 'Missing'}</span> },
    {
      id: 'actions',
      header: '',
      cell: ({ row }) => (
        <div className="flex justify-end gap-1.5">
          <Button size="sm" variant="outline" onClick={() => { setFormError(null); setMultilineSecret(false); setCredForm({ ...row.original, secret_value: '' }); setDialog('credentials') }}>Edit</Button>
          <ConfirmAction trigger={<Button size="sm" variant="ghost">Delete</Button>} title={`Delete ${row.original.name}?`} confirmLabel="Delete" destructive onConfirm={async () => { await api.deleteCredential(row.original.id); await loadAll() }} />
        </div>
      ),
    },
  ]

  const envColumns: ColumnDef<EnvironmentRecord, unknown>[] = [
    { accessorKey: 'code', header: 'Code', cell: ({ row }) => <MetaBadge items={catalog.environments} code={row.original.code} /> },
    { accessorKey: 'safety_tier', header: 'Safety Tier', cell: ({ row }) => <Badge variant="outline" className="font-mono text-[11px]">{row.original.safety_tier}</Badge> },
    { accessorKey: 'sort_order', header: 'Order' },
    {
      id: 'actions',
      header: '',
      cell: ({ row }) => (
        <div className="flex justify-end">
          <Button size="sm" variant="outline" onClick={() => { setFormError(null); setEnvForm({ ...row.original }); setDialog('environments') }}>Edit</Button>
        </div>
      ),
    },
  ]

  return (
    <div className="space-y-5">
      <PageHeader
        title="Systems & Databases"
        actions={
          <div className="flex flex-wrap items-center gap-2">
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
                  toast.error(e instanceof Error ? e.message : 'Export failed')
                }
              }}
            >
              <Download className="size-3.5" />
              Topology YAML
            </Button>
            <Button variant="outline" size="sm" onClick={() => void loadAll()} disabled={loading}>
              <RefreshCw className={loading ? 'animate-spin' : undefined} />
              Refresh
            </Button>
            <Button size="sm" onClick={openCreate}>
              <Plus />
              New
            </Button>
          </div>
        }
      />

      {error && <Notice tone="error">{error}</Notice>}

      <Tabs value={subTab} onValueChange={(v) => setSubTab(v as SubTab)}>
        <TabsList>
          <TabsTrigger value="targets">Databases ({filteredTargets.length})</TabsTrigger>
          <TabsTrigger value="systems">Systems ({systems.length})</TabsTrigger>
          <TabsTrigger value="instances">Instances ({instances.length})</TabsTrigger>
          <TabsTrigger value="networks">Networks ({networks.length})</TabsTrigger>
          <TabsTrigger value="credentials">Credentials ({credentials.length})</TabsTrigger>
          <TabsTrigger value="environments">Environments ({envs.length})</TabsTrigger>
        </TabsList>

        <TabsContent value="targets">
          <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
            <div className="flex flex-wrap items-center gap-2">
              <div className="w-60">
                <Input
                  placeholder="Search ref, alias, database, host..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                />
              </div>
              <div className="w-56">
                <Select value={systemFilter} onValueChange={setSystemFilter}>
                  <SelectTrigger>
                    <SelectValue placeholder="Filter by system" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value={ALL_SYSTEMS}>All Systems ({systems.length})</SelectItem>
                    {systems.map((s) => (
                      <SelectItem key={s.id} value={s.id}>
                        {s.name} ({s.slug})
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
            </div>
            <LoadingButton
              variant="outline"
              size="sm"
              pending={testingAll}
              disabled={targets.length === 0}
              onClick={() => void runTestAll()}
            >
              <Wifi className="size-3.5" />
              Test All
            </LoadingButton>
          </div>
          <Panel flush>
            <DataTable columns={targetColumns} data={filteredTargets} emptyLabel="No database targets configured." />
          </Panel>
        </TabsContent>
        <TabsContent value="systems">
          <Panel flush>
            <DataTable columns={systemColumns} data={systems} emptyLabel="No systems configured." />
          </Panel>
        </TabsContent>
        <TabsContent value="instances">
          <Panel flush>
            <DataTable columns={instanceColumns} data={instances} emptyLabel="No instances configured." />
          </Panel>
        </TabsContent>
        <TabsContent value="networks">
          <Panel flush>
            <DataTable columns={netColumns} data={networks} emptyLabel="No network profiles configured." />
          </Panel>
        </TabsContent>
        <TabsContent value="credentials">
          <Panel flush>
            <DataTable columns={credColumns} data={credentials} emptyLabel="No credentials configured." />
          </Panel>
        </TabsContent>
        <TabsContent value="environments">
          <Panel flush>
            <DataTable columns={envColumns} data={envs} emptyLabel="No environments configured." />
          </Panel>
        </TabsContent>
      </Tabs>

      <FormDialog
        open={dialog === 'systems'}
        onOpenChange={(o) => !o && setDialog(null)}
        title={sysForm.id ? 'Edit System' : 'New System'}
        error={formError}
        pending={saving}
        onSubmit={handleSave}
      >
        <FormField label="Slug">
          <Input value={sysForm.slug} onChange={(e) => setSysForm((p) => ({ ...p, slug: e.target.value }))} placeholder="order-core" />
        </FormField>
        <FormField label="Name">
          <Input value={sysForm.name} onChange={(e) => setSysForm((p) => ({ ...p, name: e.target.value }))} placeholder="Order Core" />
        </FormField>
        <FormField label="Owner">
          <Input value={sysForm.owner} onChange={(e) => setSysForm((p) => ({ ...p, owner: e.target.value }))} placeholder="commerce-platform" />
        </FormField>
        <FormField label="Description">
          <Input value={sysForm.description} onChange={(e) => setSysForm((p) => ({ ...p, description: e.target.value }))} />
        </FormField>
        <FormField label="Tags (comma separated)">
          <Input value={sysForm.tags} onChange={(e) => setSysForm((p) => ({ ...p, tags: e.target.value }))} placeholder="core, payments" />
        </FormField>
        <FormField label="Workspace Paths (one per line, auto-prioritizes matching cwd)">
          <Textarea rows={3} value={sysForm.workspace_paths} onChange={(e) => setSysForm((p) => ({ ...p, workspace_paths: e.target.value }))} placeholder="~/Codes/order-core" />
        </FormField>
      </FormDialog>

      <FormDialog
        open={dialog === 'instances'}
        onOpenChange={(o) => !o && setDialog(null)}
        title={instForm.id ? 'Edit Instance' : 'New Instance'}
        error={formError}
        pending={saving}
        onSubmit={handleSave}
      >
        <FormField label="Name">
          <Input value={instForm.name ?? ''} onChange={(e) => setInstForm((p) => ({ ...p, name: e.target.value }))} placeholder="rds-order-prod-01" />
        </FormField>
        <div className="grid grid-cols-2 gap-3">
          <FormField label="Engine">
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
                {catalog.engines.map((e) => (
                  <SelectItem key={e.code} value={e.code}>{e.code}</SelectItem>
                ))}
              </SelectContent>
            </Select>
          </FormField>
          <FormField label="Role">
            <Select value={instForm.role ?? 'standalone'} onValueChange={(v) => setInstForm((p) => ({ ...p, role: v as InstanceRecord['role'] }))}>
              <SelectTrigger><SelectValue /></SelectTrigger>
              <SelectContent>
                <SelectItem value="standalone">standalone</SelectItem>
                <SelectItem value="primary">primary</SelectItem>
                <SelectItem value="replica">replica</SelectItem>
              </SelectContent>
            </Select>
          </FormField>
        </div>
        {instForm.engine === 'sqlite' ? (
          <FormField label="SQLite File Path">
            <Input
              value={instForm.host ?? ''}
              onChange={(e) => setInstForm((p) => ({ ...p, host: e.target.value, port: 0 }))}
              placeholder="~/.config/app/data.db"
            />
          </FormField>
        ) : (
          <>
            <div className="grid grid-cols-[1fr_110px] gap-3">
              <FormField label="Host">
                <Input value={instForm.host ?? ''} onChange={(e) => setInstForm((p) => ({ ...p, host: e.target.value }))} />
              </FormField>
              <FormField label="Port">
                <Input type="number" value={instForm.port ?? 0} onChange={(e) => setInstForm((p) => ({ ...p, port: Number(e.target.value) }))} />
              </FormField>
            </div>
            <div className="grid grid-cols-2 gap-3">
              <FormField label="Network Profile">
                <Select value={instForm.network_profile_id || '__direct'} onValueChange={(v) => setInstForm((p) => ({ ...p, network_profile_id: v === '__direct' ? '' : v }))}>
                  <SelectTrigger><SelectValue /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="__direct">Direct (default)</SelectItem>
                    {networks.map((n) => (
                      <SelectItem key={n.id} value={n.id}>{n.name} ({n.mode})</SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </FormField>
              <FormField label="TLS Mode">
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
        title={targetForm.id ? 'Edit Database Target' : 'New Database Target'}
        error={formError}
        pending={saving}
        onSubmit={handleSave}
      >
        <div className="grid grid-cols-2 gap-3">
          <FormField label="Ref">
            <Input value={targetForm.ref ?? ''} onChange={(e) => setTargetForm((p) => ({ ...p, ref: e.target.value }))} placeholder="order-core/prod/orders" />
          </FormField>
          <FormField label="Alias">
            <Input value={targetForm.alias ?? ''} onChange={(e) => setTargetForm((p) => ({ ...p, alias: e.target.value }))} placeholder="prod-orders" />
          </FormField>
        </div>
        <div className="grid grid-cols-2 gap-3">
          <FormField label="Owner System">
            <Select value={targetForm.owner_system_id ?? ''} onValueChange={(v) => setTargetForm((p) => ({ ...p, owner_system_id: v }))}>
              <SelectTrigger><SelectValue placeholder="Select system" /></SelectTrigger>
              <SelectContent>
                {systems.map((s) => (
                  <SelectItem key={s.id} value={s.id}>{s.name} ({s.slug})</SelectItem>
                ))}
              </SelectContent>
            </Select>
          </FormField>
          <FormField label="Environment">
            <Select value={targetForm.environment_code ?? 'dev'} onValueChange={(v) => setTargetForm((p) => ({ ...p, environment_code: v }))}>
              <SelectTrigger><SelectValue /></SelectTrigger>
              <SelectContent>
                {envs.map((e) => (
                  <SelectItem key={e.code} value={e.code}>{e.code} ({e.safety_tier})</SelectItem>
                ))}
              </SelectContent>
            </Select>
          </FormField>
        </div>
        <div className="grid grid-cols-2 gap-3">
          <FormField label="Instance">
            <Select value={targetForm.instance_id ?? ''} onValueChange={(v) => setTargetForm((p) => ({ ...p, instance_id: v }))}>
              <SelectTrigger><SelectValue placeholder="Select instance" /></SelectTrigger>
              <SelectContent>
                {instances.map((i) => (
                  <SelectItem key={i.id} value={i.id}>{i.name} ({i.engine})</SelectItem>
                ))}
              </SelectContent>
            </Select>
          </FormField>
          <FormField label="Database / Schema / DB Index">
            <Input value={targetForm.database_name ?? ''} onChange={(e) => setTargetForm((p) => ({ ...p, database_name: e.target.value }))} />
          </FormField>
        </div>
        <div className="grid grid-cols-2 gap-3">
          <FormField label="Read-Only Credential">
            <Select value={targetForm.ro_credential_id || '__none'} onValueChange={(v) => setTargetForm((p) => ({ ...p, ro_credential_id: v === '__none' ? '' : v }))}>
              <SelectTrigger><SelectValue /></SelectTrigger>
              <SelectContent>
                <SelectItem value="__none">None</SelectItem>
                {credentials.map((c) => (
                  <SelectItem key={c.id} value={c.id}>{c.name} ({c.access_level})</SelectItem>
                ))}
              </SelectContent>
            </Select>
          </FormField>
          <FormField label="Read-Write Credential">
            <Select value={targetForm.rw_credential_id || '__none'} onValueChange={(v) => setTargetForm((p) => ({ ...p, rw_credential_id: v === '__none' ? '' : v }))}>
              <SelectTrigger><SelectValue /></SelectTrigger>
              <SelectContent>
                <SelectItem value="__none">None</SelectItem>
                {credentials.map((c) => (
                  <SelectItem key={c.id} value={c.id}>{c.name} ({c.access_level})</SelectItem>
                ))}
              </SelectContent>
            </Select>
          </FormField>
        </div>
        <FormField label="Status">
          <Select value={targetForm.status ?? 'active'} onValueChange={(v) => setTargetForm((p) => ({ ...p, status: v as TargetRecord['status'] }))}>
            <SelectTrigger><SelectValue /></SelectTrigger>
            <SelectContent>
              <SelectItem value="active">active</SelectItem>
              <SelectItem value="maintenance">maintenance</SelectItem>
              <SelectItem value="disabled">disabled</SelectItem>
            </SelectContent>
          </Select>
        </FormField>
      </FormDialog>

      <FormDialog
        open={dialog === 'networks'}
        onOpenChange={(o) => !o && setDialog(null)}
        title={netForm.id ? 'Edit Network Profile' : 'New Network Profile'}
        error={formError}
        pending={saving}
        onSubmit={handleSave}
      >
        <FormField label="Name">
          <Input value={netForm.name ?? ''} onChange={(e) => setNetForm((p) => ({ ...p, name: e.target.value }))} />
        </FormField>
        <FormField label="Mode">
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
              <FormField label="Bastion Host"><Input value={netForm.bastion_host ?? ''} onChange={(e) => setNetForm((p) => ({ ...p, bastion_host: e.target.value }))} /></FormField>
              <FormField label="Port"><Input type="number" value={netForm.bastion_port ?? 22} onChange={(e) => setNetForm((p) => ({ ...p, bastion_port: Number(e.target.value) }))} /></FormField>
            </div>
            <FormField label="Bastion User"><Input value={netForm.bastion_user ?? ''} onChange={(e) => setNetForm((p) => ({ ...p, bastion_user: e.target.value }))} /></FormField>
            <FormField label="Bastion Credential (uses SSH_AUTH_SOCK if None)">
              <Select value={netForm.bastion_credential_id || '__none'} onValueChange={(v) => setNetForm((p) => ({ ...p, bastion_credential_id: v === '__none' ? '' : v }))}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="__none">None (SSH Agent)</SelectItem>
                  {credentials.map((c) => <SelectItem key={c.id} value={c.id}>{c.name}</SelectItem>)}
                </SelectContent>
              </Select>
            </FormField>
            <div className="flex items-center justify-between">
              <span className="text-sm">Strict SSH known_hosts check</span>
              <Switch checked={Boolean(netForm.ssh_strict_host_key)} onCheckedChange={(c) => setNetForm((p) => ({ ...p, ssh_strict_host_key: c }))} />
            </div>
          </>
        )}
        {(netForm.mode === 'socks5' || netForm.mode === 'http_proxy') && (
          <FormField label="Proxy URL"><Input value={netForm.proxy_url ?? ''} onChange={(e) => setNetForm((p) => ({ ...p, proxy_url: e.target.value }))} placeholder="socks5://127.0.0.1:1080" /></FormField>
        )}
      </FormDialog>

      <FormDialog
        open={dialog === 'credentials'}
        onOpenChange={(o) => !o && setDialog(null)}
        title={credForm.id ? 'Edit Credential' : 'New Credential'}
        error={formError}
        pending={saving}
        onSubmit={handleSave}
      >
        <FormField label="Name">
          <Input value={credForm.name ?? ''} onChange={(e) => setCredForm((p) => ({ ...p, name: e.target.value }))} />
        </FormField>
        <div className="grid grid-cols-2 gap-3">
          <FormField label="Kind">
            <Select value={credForm.kind ?? 'keychain'} onValueChange={(v) => setCredForm((p) => ({ ...p, kind: v as CredentialProfileRecord['kind'] }))}>
              <SelectTrigger><SelectValue /></SelectTrigger>
              <SelectContent>
                <SelectItem value="keychain">keychain</SelectItem>
                <SelectItem value="env_ref">env_ref</SelectItem>
                <SelectItem value="exec_provider">exec_provider</SelectItem>
              </SelectContent>
            </Select>
          </FormField>
          <FormField label="Access Level">
            <Select value={credForm.access_level ?? 'read_only'} onValueChange={(v) => setCredForm((p) => ({ ...p, access_level: v as CredentialProfileRecord['access_level'] }))}>
              <SelectTrigger><SelectValue /></SelectTrigger>
              <SelectContent>
                <SelectItem value="read_only">read_only</SelectItem>
                <SelectItem value="read_write">read_write</SelectItem>
              </SelectContent>
            </Select>
          </FormField>
        </div>
        <FormField label="Username">
          <Input value={credForm.username ?? ''} onChange={(e) => setCredForm((p) => ({ ...p, username: e.target.value }))} />
        </FormField>
        {credForm.kind === 'keychain' && (
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-xs font-medium text-muted-foreground">Secret / Password / Private Key (write-only)</span>
              <label className="flex cursor-pointer items-center gap-1.5 text-xs text-muted-foreground">
                <Switch checked={multilineSecret} onCheckedChange={setMultilineSecret} />
                <span>Private Key (multiline)</span>
              </label>
            </div>
            {multilineSecret ? (
              <Textarea
                rows={5}
                className="font-mono text-xs"
                value={credForm.secret_value ?? ''}
                onChange={(e) => setCredForm((p) => ({ ...p, secret_value: e.target.value }))}
                placeholder={credForm.id ? 'Leave blank to keep existing' : 'Paste SSH private key (PEM / OpenSSH)'}
              />
            ) : (
              <Input
                type="password"
                value={credForm.secret_value ?? ''}
                onChange={(e) => setCredForm((p) => ({ ...p, secret_value: e.target.value }))}
                placeholder={credForm.id ? 'Leave blank to keep existing' : 'Stored securely in Keychain'}
              />
            )}
          </div>
        )}
        {credForm.kind === 'env_ref' && (
          <FormField label="Environment Variable Name">
            <Input value={credForm.env_var_name ?? ''} onChange={(e) => setCredForm((p) => ({ ...p, env_var_name: e.target.value }))} placeholder="PROD_DB_PASSWORD" />
          </FormField>
        )}
        {credForm.kind === 'exec_provider' && (
          <FormField label="Command (executed directly without shell)">
            <Input value={credForm.exec_command ?? ''} onChange={(e) => setCredForm((p) => ({ ...p, exec_command: e.target.value }))} placeholder="op read op://prod/db/password" />
          </FormField>
        )}
      </FormDialog>

      <FormDialog
        open={dialog === 'environments'}
        onOpenChange={(o) => !o && setDialog(null)}
        title="Environment Configuration"
        error={formError}
        pending={saving}
        onSubmit={handleSave}
      >
        <FormField label="Code">
          <Input value={envForm.code} onChange={(e) => setEnvForm((p) => ({ ...p, code: e.target.value }))} placeholder="uat" />
        </FormField>
        <FormField label="Safety Tier">
          <Select value={envForm.safety_tier} onValueChange={(v) => setEnvForm((p) => ({ ...p, safety_tier: v as EnvironmentRecord['safety_tier'] }))}>
            <SelectTrigger><SelectValue /></SelectTrigger>
            <SelectContent>
              <SelectItem value="yolo">yolo (Dev free execution)</SelectItem>
              <SelectItem value="guarded">guarded (Staging confirmation on writes/high-cost)</SelectItem>
              <SelectItem value="strict">strict (Production protection + preflight)</SelectItem>
            </SelectContent>
          </Select>
        </FormField>
        <div className="grid grid-cols-2 gap-3">
          <FormField label="Label (EN)">
            <Input value={envForm.labels.en ?? ''} onChange={(e) => setEnvForm((p) => ({ ...p, labels: { ...p.labels, en: e.target.value } }))} />
          </FormField>
          <FormField label="Label (ZH)">
            <Input value={envForm.labels.zh ?? ''} onChange={(e) => setEnvForm((p) => ({ ...p, labels: { ...p.labels, zh: e.target.value } }))} />
          </FormField>
        </div>
        <div className="grid grid-cols-2 gap-3">
          <FormField label="Color (#RRGGBB)">
            <Input value={envForm.color} onChange={(e) => setEnvForm((p) => ({ ...p, color: e.target.value }))} />
          </FormField>
          <FormField label="Sort Order">
            <Input type="number" value={envForm.sort_order} onChange={(e) => setEnvForm((p) => ({ ...p, sort_order: Number(e.target.value) }))} />
          </FormField>
        </div>
      </FormDialog>

      <FormDialog
        open={dialog === 'topology'}
        onOpenChange={(o) => !o && setDialog(null)}
        title="Sanitized Topology Export / Import"
        submitLabel="Import YAML/JSON"
        error={formError}
        pending={saving}
        onSubmit={handleSave}
        maxWidthClassName="sm:max-w-[680px]"
      >
        <FormField label="Topology YAML/JSON (secret-free)">
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
            Download YAML
          </Button>
        </div>
      </FormDialog>

      <Sheet open={Boolean(discoverSheet)} onOpenChange={(o) => !o && setDiscoverSheet(null)}>
        <SheetContent>
          <SheetHeader>
            <SheetTitle>Discovered Databases · {discoverSheet?.instance.name}</SheetTitle>
          </SheetHeader>
          <SheetBody>
            {discoverSheet && (
              <div className="space-y-3">
                <div className="flex items-end gap-2">
                  <div className="flex-1">
                    <FormField label="Credential">
                      <Select
                        value={discoverSheet.credentialId || '__none'}
                        onValueChange={(v) => {
                          const cid = v === '__none' ? '' : v
                          void runDiscover(discoverSheet.instance, cid)
                        }}
                      >
                        <SelectTrigger><SelectValue /></SelectTrigger>
                        <SelectContent>
                          <SelectItem value="__none">None</SelectItem>
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
                    Scan
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
                        Attach
                      </Button>
                    </div>
                  ))}
                  {!discoverSheet.loading && !discoverSheet.error && discoverSheet.databases.length === 0 && (
                    <div className="py-6 text-center text-xs text-muted-foreground">No databases discovered.</div>
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
