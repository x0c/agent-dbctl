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
} from '@x0c/ui'
import { RefreshCw } from 'lucide-react'
import { useEffect, useState } from 'react'
import { api, type DiscoveredPlugin, type DriverMetadata } from '../api'
import { useI18n } from '../lib/i18n'

export function DriversTab() {
  const { t } = useI18n()
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
      setError(e instanceof Error ? e.message : t('drivers.loadFailed'))
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
      toast.success(t('drivers.reloadedToast'))
    } catch (e) {
      toast.error(e instanceof Error ? e.message : t('drivers.reloadFailed'))
      setLoading(false)
    }
  }

  const driverCols: ColumnDef<DriverMetadata, unknown>[] = [
    {
      accessorKey: 'engine',
      header: t('drivers.col.engine'),
      cell: ({ row }) => <span className="font-mono text-xs font-semibold">{row.original.engine}</span>,
    },
    { accessorKey: 'display_name', header: t('drivers.col.name') },
    {
      accessorKey: 'family',
      header: t('drivers.col.family'),
      cell: ({ row }) => (
        <Badge variant="outline" className="font-mono text-[11px]">
          {row.original.family}
        </Badge>
      ),
    },
    {
      accessorKey: 'tier',
      header: t('drivers.col.tier'),
      cell: ({ row }) => (
        <Badge variant="outline" className="font-mono text-[11px]">
          {row.original.tier}
        </Badge>
      ),
    },
    {
      id: 'capabilities',
      header: t('drivers.col.capabilities'),
      cell: ({ row }) => (
        <span className="truncate font-mono text-xs text-muted-foreground">
          {(row.original.capabilities ?? []).join(', ')}
        </span>
      ),
    },
    {
      id: 'status',
      header: t('drivers.col.status'),
      cell: ({ row }) => (
        <StatusDot tone={row.original.verified ? 'success' : 'danger'}>
          {row.original.verified ? t('drivers.verified') : t('drivers.invalid')}
        </StatusDot>
      ),
    },
  ]

  const pluginCols: ColumnDef<DiscoveredPlugin, unknown>[] = [
    {
      id: 'id',
      header: t('drivers.col.pluginId'),
      cell: ({ row }) => <span className="font-mono text-xs font-semibold">{row.original.Manifest.id || '—'}</span>,
    },
    {
      id: 'engine',
      header: t('drivers.col.engine'),
      cell: ({ row }) => <span className="font-mono text-xs">{row.original.Manifest.engine || '—'}</span>,
    },
    {
      id: 'version',
      header: t('drivers.col.version'),
      cell: ({ row }) => <span className="font-mono text-xs">{row.original.Manifest.version || '—'}</span>,
    },
    {
      id: 'verified',
      header: t('drivers.col.check'),
      cell: ({ row }) => (
        <StatusDot tone={row.original.Verified ? 'success' : 'danger'}>
          <span className="truncate font-mono text-xs">
            {row.original.Verified
              ? t('drivers.verifiedApi', { ver: row.original.Manifest.host_api_version })
              : row.original.VerificationErr}
          </span>
        </StatusDot>
      ),
    },
  ]

  return (
    <div className="space-y-5">
      <PageHeader
        title={t('drivers.title')}
        actions={
          <Button variant="outline" size="sm" onClick={() => void reloadPlugins()} disabled={loading}>
            <RefreshCw className={loading ? 'animate-spin' : undefined} />
            {t('drivers.reloadPlugins')}
          </Button>
        }
      />

      {error && <Notice tone="error">{error}</Notice>}

      <Panel title={t('drivers.activeTitle')} flush>
        <DataTable
          columns={driverCols}
          data={drivers}
          searchPlaceholder={t('common.search')}
          emptyLabel={t('drivers.emptyDrivers')}
        />
      </Panel>

      <Panel title={t('drivers.pluginsTitle')} flush>
        <DataTable
          columns={pluginCols}
          data={plugins}
          searchPlaceholder={t('common.search')}
          emptyLabel={t('drivers.emptyPlugins')}
        />
      </Panel>
    </div>
  )
}
