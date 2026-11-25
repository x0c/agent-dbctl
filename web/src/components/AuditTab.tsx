import {
  Badge,
  Button,
  type ColumnDef,
  DataTable,
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
  Tabs,
  TabsContent,
  TabsList,
  TabsTrigger,
  fmtDateTime,
  toast,
} from '@x0c/ui'
import { RefreshCw, ShieldCheck } from 'lucide-react'
import { useEffect, useState } from 'react'
import {
  api,
  type AuditEntry,
  type AuditVerifyResult,
  type DisplayCatalog,
  type OperationRecord,
} from '../api'
import { resolveDisplayItem } from '../lib/catalog'
import { useI18n } from '../lib/i18n'
import { MetaBadge } from './MetaBadge'

export function AuditTab({ catalog }: { catalog: DisplayCatalog }) {
  const { locale, t } = useI18n()
  const [view, setView] = useState<'operations' | 'chain'>('operations')
  const [ops, setOps] = useState<OperationRecord[]>([])
  const [auditEntries, setAuditEntries] = useState<AuditEntry[]>([])
  const [verifyRes, setVerifyRes] = useState<AuditVerifyResult | null>(null)
  const [verifying, setVerifying] = useState(false)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  const [search, setSearch] = useState('')
  const [envFilter, setEnvFilter] = useState('__all')
  const [statusFilter, setStatusFilter] = useState('__all')
  const [selectedOp, setSelectedOp] = useState<OperationRecord | null>(null)

  const load = async () => {
    setLoading(true)
    setError(null)
    try {
      const [oRes, aRes] = await Promise.all([
        api.listOperations({
          search: search.trim(),
          env: envFilter === '__all' ? '' : envFilter,
          status: statusFilter === '__all' ? '' : statusFilter,
          limit: '100',
        }),
        api.listAudit({ search: search.trim(), limit: '150' }),
      ])
      setOps(oRes.items ?? [])
      setAuditEntries(aRes.items ?? [])
    } catch (e) {
      setError(e instanceof Error ? e.message : t('audit.loadFailed'))
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    void load()
  }, [envFilter, statusFilter])

  const handleVerify = async () => {
    setVerifying(true)
    try {
      const res = await api.verifyAuditChain()
      setVerifyRes(res)
      if (res.valid) toast.success(t('audit.verifiedToast', { count: res.checked_count }))
      else toast.error(res.reason || t('audit.verifyFailedToast'))
    } catch (e) {
      toast.error(e instanceof Error ? e.message : t('audit.verifyErrorToast'))
    } finally {
      setVerifying(false)
    }
  }

  const opColumns: ColumnDef<OperationRecord, unknown>[] = [
    {
      accessorKey: 'created_at_utc',
      header: t('audit.col.time'),
      cell: ({ row }) => (
        <span
          className="font-mono text-xs text-muted-foreground whitespace-nowrap"
          title={fmtDateTime(row.original.created_at_utc)}
        >
          {new Date(row.original.created_at_utc).toLocaleTimeString([], { hour12: false })}
        </span>
      ),
    },
    {
      accessorKey: 'target_ref',
      header: t('audit.col.target'),
      cell: ({ row }) => (
        <span className="block max-w-[170px] truncate font-mono text-xs font-semibold" title={row.original.target_ref}>
          {row.original.target_ref}
        </span>
      ),
    },
    {
      id: 'env',
      header: t('audit.col.env'),
      cell: ({ row }) => <MetaBadge items={catalog.environments} code={row.original.environment_code} />,
    },
    {
      id: 'risk',
      header: t('audit.col.risk'),
      cell: ({ row }) => <MetaBadge items={catalog.risk_levels} code={row.original.risk_level} />,
    },
    {
      id: 'status',
      header: t('audit.col.status'),
      cell: ({ row }) => <MetaBadge items={catalog.operation_statuses} code={row.original.status} />,
    },
    {
      accessorKey: 'query_redacted',
      header: t('audit.col.query'),
      cell: ({ row }) => (
        <span
          className="block max-w-[170px] truncate font-mono text-xs text-muted-foreground"
          title={row.original.query_redacted}
        >
          {row.original.query_redacted}
        </span>
      ),
    },
    {
      id: 'actions',
      header: '',
      cell: ({ row }) => (
        <div className="flex justify-end">
          <Button size="sm" variant="outline" onClick={() => setSelectedOp(row.original)}>
            {t('audit.inspect')}
          </Button>
        </div>
      ),
    },
  ]

  const auditColumns: ColumnDef<AuditEntry, unknown>[] = [
    { accessorKey: 'seq', header: '#', cell: ({ row }) => <span className="font-mono text-xs">{row.original.seq}</span> },
    {
      accessorKey: 'created_at_utc',
      header: t('audit.col.time'),
      cell: ({ row }) => <span className="font-mono text-xs text-muted-foreground">{fmtDateTime(row.original.created_at_utc)}</span>,
    },
    {
      accessorKey: 'actor',
      header: t('audit.col.actor'),
      cell: ({ row }) => <span className="font-mono text-xs">{row.original.actor}</span>,
    },
    {
      accessorKey: 'action',
      header: t('audit.col.action'),
      cell: ({ row }) => (
        <Badge variant="outline" className="font-mono text-[11px]">
          {row.original.action}
        </Badge>
      ),
    },
    {
      accessorKey: 'target_id',
      header: t('audit.col.target'),
      cell: ({ row }) => <span className="truncate font-mono text-xs">{row.original.target_id}</span>,
    },
    {
      accessorKey: 'entry_hash',
      header: t('audit.col.hash'),
      cell: ({ row }) => <span className="font-mono text-xs text-muted-foreground">{row.original.entry_hash.slice(0, 12)}</span>,
    },
  ]

  return (
    <div className="space-y-5">
      <PageHeader
        title={t('audit.title')}
        actions={
          <div className="flex items-center gap-2">
            <LoadingButton variant="outline" size="sm" pending={verifying} onClick={() => void handleVerify()}>
              <ShieldCheck className="size-3.5" />
              {t('audit.verifyChain')}
            </LoadingButton>
            <Button variant="outline" size="sm" onClick={() => void load()} disabled={loading}>
              <RefreshCw className={loading ? 'animate-spin' : undefined} />
              {t('common.refresh')}
            </Button>
          </div>
        }
      />

      {verifyRes && (
        <Notice tone={verifyRes.valid ? 'success' : 'error'}>
          {verifyRes.valid
            ? t('audit.chainIntact', {
                count: verifyRes.checked_count,
                head: verifyRes.last_hash?.slice(0, 16) ?? '',
              })
            : t('audit.chainBroken', {
                seq: verifyRes.first_broken_seq ?? 0,
                reason: verifyRes.reason ?? '',
              })}
        </Notice>
      )}
      {error && <Notice tone="error">{error}</Notice>}

      <div className="flex flex-wrap items-center gap-3">
        <Input
          className="max-w-xs"
          placeholder={t('audit.searchPlaceholder')}
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          onKeyDown={(e) => e.key === 'Enter' && void load()}
        />
        <div className="w-44">
          <Select value={envFilter} onValueChange={setEnvFilter}>
            <SelectTrigger>
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="__all">{t('audit.allEnvs')}</SelectItem>
              {catalog.environments.map((e) => (
                <SelectItem key={e.code} value={e.code}>
                  {resolveDisplayItem(catalog.environments, e.code, locale).label}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
        <div className="w-48">
          <Select value={statusFilter} onValueChange={setStatusFilter}>
            <SelectTrigger>
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="__all">{t('audit.allStatuses')}</SelectItem>
              {catalog.operation_statuses.map((s) => (
                <SelectItem key={s.code} value={s.code}>
                  {resolveDisplayItem(catalog.operation_statuses, s.code, locale).label}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
        <Button variant="outline" size="sm" onClick={() => void load()}>
          {t('common.filter')}
        </Button>
      </div>

      <Tabs value={view} onValueChange={(v) => setView(v as 'operations' | 'chain')}>
        <TabsList>
          <TabsTrigger value="operations">{t('audit.tab.operations', { count: ops.length })}</TabsTrigger>
          <TabsTrigger value="chain">{t('audit.tab.chain', { count: auditEntries.length })}</TabsTrigger>
        </TabsList>

        <TabsContent value="operations">
          <Panel flush>
            <DataTable columns={opColumns} data={ops} searchable={false} emptyLabel={t('audit.emptyOps')} />
          </Panel>
        </TabsContent>
        <TabsContent value="chain">
          <Panel flush>
            <DataTable columns={auditColumns} data={auditEntries} searchable={false} emptyLabel={t('audit.emptyAudit')} />
          </Panel>
        </TabsContent>
      </Tabs>

      <Sheet open={Boolean(selectedOp)} onOpenChange={(o) => !o && setSelectedOp(null)}>
        <SheetContent>
          <SheetHeader>
            <SheetTitle>{t('audit.sheetTitle', { id: selectedOp?.id ?? '' })}</SheetTitle>
          </SheetHeader>
          <SheetBody>
            {selectedOp && (
              <div className="space-y-4 text-xs">
                <div className="flex flex-wrap gap-2">
                  <MetaBadge items={catalog.environments} code={selectedOp.environment_code} />
                  <MetaBadge items={catalog.engines} code={selectedOp.engine} />
                  <MetaBadge items={catalog.risk_levels} code={selectedOp.risk_level} />
                  <MetaBadge items={catalog.operation_statuses} code={selectedOp.status} />
                </div>
                <div className="grid grid-cols-2 gap-2 rounded-md border border-border p-3">
                  <div>
                    <span className="text-muted-foreground">{t('audit.detail.target')}</span>{' '}
                    <span className="font-mono">{selectedOp.target_ref}</span>
                  </div>
                  <div>
                    <span className="text-muted-foreground">{t('audit.detail.actor')}</span>{' '}
                    <span className="font-mono">{selectedOp.actor}</span>
                  </div>
                  <div>
                    <span className="text-muted-foreground">{t('audit.detail.rows')}</span>{' '}
                    <span className="font-mono">
                      {selectedOp.fetched_rows} / {selectedOp.returned_rows}
                    </span>
                  </div>
                  <div>
                    <span className="text-muted-foreground">{t('audit.detail.truncated')}</span>{' '}
                    <span className="font-mono">
                      {String(selectedOp.truncated)} {selectedOp.cutoff_reason}
                    </span>
                  </div>
                </div>
                {selectedOp.reason && (
                  <div>
                    <div className="mb-1 text-muted-foreground">{t('audit.detail.reason')}</div>
                    <div className="rounded-md border border-border p-2.5 text-sm">{selectedOp.reason}</div>
                  </div>
                )}
                <div>
                  <div className="mb-1 text-muted-foreground">{t('audit.detail.queryText')}</div>
                  <pre className="max-h-60 overflow-auto rounded-md border border-border bg-muted/40 p-3 font-mono whitespace-pre-wrap break-all">
                    {selectedOp.query_text}
                  </pre>
                </div>
                {selectedOp.preflight?.plan_summary && (
                  <div>
                    <div className="mb-1 text-muted-foreground">{t('audit.detail.preflight')}</div>
                    <pre className="overflow-auto rounded-md border border-border bg-muted/30 p-2.5 font-mono whitespace-pre-wrap">
                      {selectedOp.preflight.plan_summary}
                    </pre>
                  </div>
                )}
                {selectedOp.error_message && (
                  <Notice tone="error">
                    [{selectedOp.error_code}] {selectedOp.error_message}
                  </Notice>
                )}
              </div>
            )}
          </SheetBody>
        </SheetContent>
      </Sheet>
    </div>
  )
}
