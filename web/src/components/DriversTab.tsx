import {
  Badge,
  Button,
  type ColumnDef,
  DataTable,
  Notice,
  PageHeader,
  Panel,
  StatusDot,
  toast,
} from '../ui'
import { RefreshCw } from 'lucide-react'
import { useEffect, useState } from 'react'
import { api, type DiscoveredPlugin, type DriverMetadata } from '../api'

export function DriversTab() {
  const [drivers, setDrivers] = useState<DriverMetadata[]>([])
  const [plugins, setPlugins] = useState<DiscoveredPlugin[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  const load = async () => {
    setLoading(true)
    setError(null)
    try {
      const res = await api.listDrivers()
      setDrivers(res.drivers ?? [])
      setPlugins(res.plugins ?? [])
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to load drivers')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    void load()
  }, [])

  const reloadPlugins = async () => {
    setLoading(true)
    try {
      await api.reloadPlugins()
      await load()
      toast.success('Reloaded external driver plugins')
    } catch (e) {
      toast.error(e instanceof Error ? e.message : 'Plugin reload failed')
      setLoading(false)
    }
  }

  const driverCols: ColumnDef<DriverMetadata, unknown>[] = [
    { accessorKey: 'engine', header: 'Engine', cell: ({ row }) => <span className="font-mono text-xs font-semibold">{row.original.engine}</span> },
    { accessorKey: 'display_name', header: 'Name' },
    { accessorKey: 'family', header: 'Family', cell: ({ row }) => <Badge variant="outline" className="font-mono text-[11px]">{row.original.family}</Badge> },
    { accessorKey: 'tier', header: 'Tier', cell: ({ row }) => <Badge variant="outline" className="font-mono text-[11px]">{row.original.tier}</Badge> },
    {
      id: 'capabilities',
      header: 'Capabilities',
      cell: ({ row }) => (
        <span className="truncate font-mono text-xs text-muted-foreground">
          {(row.original.capabilities ?? []).join(', ')}
        </span>
      ),
    },
    {
      id: 'status',
      header: 'Status',
      cell: ({ row }) => (
        <StatusDot tone={row.original.verified ? 'success' : 'danger'}>
          {row.original.verified ? 'Verified' : 'Invalid'}
        </StatusDot>
      ),
    },
  ]

  const pluginCols: ColumnDef<DiscoveredPlugin, unknown>[] = [
    { id: 'id', header: 'Plugin ID', cell: ({ row }) => <span className="font-mono text-xs font-semibold">{row.original.Manifest.id || '—'}</span> },
    { id: 'engine', header: 'Engine', cell: ({ row }) => <span className="font-mono text-xs">{row.original.Manifest.engine || '—'}</span> },
    { id: 'version', header: 'Version', cell: ({ row }) => <span className="font-mono text-xs">{row.original.Manifest.version || '—'}</span> },
    {
      id: 'verified',
      header: 'SHA-256 & API Check',
      cell: ({ row }) => (
        <StatusDot tone={row.original.Verified ? 'success' : 'danger'}>
          <span className="truncate font-mono text-xs">
            {row.original.Verified ? `Verified (API v${row.original.Manifest.host_api_version})` : row.original.VerificationErr}
          </span>
        </StatusDot>
      ),
    },
  ]

  return (
    <div className="space-y-5">
      <PageHeader
        title="Drivers & Plugins"
        actions={
          <Button variant="outline" size="sm" onClick={() => void reloadPlugins()} disabled={loading}>
            <RefreshCw className={loading ? 'animate-spin' : undefined} />
            Reload Plugins
          </Button>
        }
      />

      {error && <Notice tone="error">{error}</Notice>}

      <Panel title="Active Drivers (Built-in Pure Go + Verified gRPC Plugins)" flush>
        <DataTable columns={driverCols} data={drivers} emptyLabel="No drivers registered." />
      </Panel>

      <Panel title="External gRPC Plugin Manifests (~/.config/agent-dbctl/plugins)" flush>
        <DataTable columns={pluginCols} data={plugins} emptyLabel="No external plugins installed." />
      </Panel>
    </div>
  )
}
