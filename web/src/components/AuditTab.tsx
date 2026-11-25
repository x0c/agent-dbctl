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
import { MetaBadge } from './MetaBadge'

export function AuditTab({ catalog }: { catalog: DisplayCatalog }) {
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
      setError(e instanceof Error ? e.message : 'Failed to load audit records')
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
      if (res.valid) toast.success(`Hash chain verified (${res.checked_count} entries)`)
      else toast.error(res.reason || 'Hash chain verification failed')
    } catch (e) {
      toast.error(e instanceof Error ? e.message : 'Verification error')
    } finally {
      setVerifying(false)
    }
  }

  const opColumns: ColumnDef<OperationRecord, unknown>[] = [
    {
      accessorKey: 'created_at_utc',
      header: 'Time',
      cell: ({ row }) => (
        <span className="font-mono text-xs text-muted-foreground whitespace-nowrap" title={fmtDateTime(row.original.created_at_utc)}>
          {new Date(row.original.created_at_utc).toLocaleTimeString([], { hour12: false })}
        </span>
      ),
    },
    {
      accessorKey: 'target_ref',
      header: 'Target',
      cell: ({ row }) => (
        <span className="block max-w-[170px] truncate font-mono text-xs font-semibold" title={row.original.target_ref}>
          {row.original.target_ref}
        </span>
      ),
    },
    {
      id: 'env',
      header: 'Env',
      cell: ({ row }) => <MetaBadge items={catalog.environments} code={row.original.environment_code} />,
    },
    {
      id: 'risk',
      header: 'Risk',
      cell: ({ row }) => <MetaBadge items={catalog.risk_levels} code={row.original.risk_level} />,
    },
    {
      id: 'status',
      header: 'Status',
      cell: ({ row }) => <MetaBadge items={catalog.operation_statuses} code={row.original.status} />,
    },
    {
      accessorKey: 'query_redacted',
      header: 'Query',
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
            Inspect
          </Button>
        </div>
      ),
    },
  ]

  const auditColumns: ColumnDef<AuditEntry, unknown>[] = [
    { accessorKey: 'seq', header: '#', cell: ({ row }) => <span className="font-mono text-xs">{row.original.seq}</span> },
    { accessorKey: 'created_at_utc', header: 'Time', cell: ({ row }) => <span className="font-mono text-xs text-muted-foreground">{fmtDateTime(row.original.created_at_utc)}</span> },
    { accessorKey: 'actor', header: 'Actor', cell: ({ row }) => <span className="font-mono text-xs">{row.original.actor}</span> },
    { accessorKey: 'action', header: 'Action', cell: ({ row }) => <Badge variant="outline" className="font-mono text-[11px]">{row.original.action}</Badge> },
    { accessorKey: 'target_id', header: 'Target', cell: ({ row }) => <span className="truncate font-mono text-xs">{row.original.target_id}</span> },
    { accessorKey: 'entry_hash', header: 'Hash', cell: ({ row }) => <span className="font-mono text-xs text-muted-foreground">{row.original.entry_hash.slice(0, 12)}</span> },
  ]

  return (
    <div className="space-y-5">
      <PageHeader
        title="Audit Logs"
        actions={
          <div className="flex items-center gap-2">
            <LoadingButton variant="outline" size="sm" pending={verifying} onClick={() => void handleVerify()}>
              <ShieldCheck className="size-3.5" />
              Verify Hash Chain
            </LoadingButton>
            <Button variant="outline" size="sm" onClick={() => void load()} disabled={loading}>
              <RefreshCw className={loading ? 'animate-spin' : undefined} />
              Refresh
            </Button>
          </div>
        }
      />

      {verifyRes && (
        <Notice tone={verifyRes.valid ? 'success' : 'error'}>
          {verifyRes.valid
            ? `Hash chain intact across ${verifyRes.checked_count} immutable entries (head ${verifyRes.last_hash?.slice(0, 16)}).`
            : `Hash chain violation at seq #${verifyRes.first_broken_seq}: ${verifyRes.reason}`}
        </Notice>
      )}
      {error && <Notice tone="error">{error}</Notice>}

      <div className="flex flex-wrap items-center gap-3">
        <Input
          className="max-w-xs"
          placeholder="Search SQL, reason, operation ID..."
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          onKeyDown={(e) => e.key === 'Enter' && void load()}
        />
        <div className="w-44">
          <Select value={envFilter} onValueChange={setEnvFilter}>
            <SelectTrigger><SelectValue /></SelectTrigger>
            <SelectContent>
              <SelectItem value="__all">All Environments</SelectItem>
              {catalog.environments.map((e) => (
                <SelectItem key={e.code} value={e.code}>{e.code}</SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
        <div className="w-48">
          <Select value={statusFilter} onValueChange={setStatusFilter}>
            <SelectTrigger><SelectValue /></SelectTrigger>
            <SelectContent>
              <SelectItem value="__all">All Statuses</SelectItem>
              {catalog.operation_statuses.map((s) => (
                <SelectItem key={s.code} value={s.code}>{s.code}</SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
        <Button variant="outline" size="sm" onClick={() => void load()}>Filter</Button>
      </div>

      <Tabs value={view} onValueChange={(v) => setView(v as 'operations' | 'chain')}>
        <TabsList>
          <TabsTrigger value="operations">Execution Log ({ops.length})</TabsTrigger>
          <TabsTrigger value="chain">Hash-Chain Ledger ({auditEntries.length})</TabsTrigger>
        </TabsList>

        <TabsContent value="operations">
          <Panel flush>
            <DataTable columns={opColumns} data={ops} searchable={false} emptyLabel="No SQL/command executions recorded yet." />
          </Panel>
        </TabsContent>
        <TabsContent value="chain">
          <Panel flush>
            <DataTable columns={auditColumns} data={auditEntries} searchable={false} emptyLabel="No audit entries." />
          </Panel>
        </TabsContent>
      </Tabs>

      <Sheet open={Boolean(selectedOp)} onOpenChange={(o) => !o && setSelectedOp(null)}>
        <SheetContent>
          <SheetHeader>
            <SheetTitle>Operation {selectedOp?.id}</SheetTitle>
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
                  <div><span className="text-muted-foreground">Target:</span> <span className="font-mono">{selectedOp.target_ref}</span></div>
                  <div><span className="text-muted-foreground">Actor:</span> <span className="font-mono">{selectedOp.actor}</span></div>
                  <div><span className="text-muted-foreground">Fetched/Returned:</span> <span className="font-mono">{selectedOp.fetched_rows} / {selectedOp.returned_rows}</span></div>
                  <div><span className="text-muted-foreground">Truncated:</span> <span className="font-mono">{String(selectedOp.truncated)} {selectedOp.cutoff_reason}</span></div>
                </div>
                {selectedOp.reason && (
                  <div>
                    <div className="mb-1 text-muted-foreground">Reason</div>
                    <div className="rounded-md border border-border p-2.5 text-sm">{selectedOp.reason}</div>
                  </div>
                )}
                <div>
                  <div className="mb-1 text-muted-foreground">Query Text</div>
                  <pre className="max-h-60 overflow-auto rounded-md border border-border bg-muted/40 p-3 font-mono whitespace-pre-wrap break-all">
                    {selectedOp.query_text}
                  </pre>
                </div>
                {selectedOp.preflight?.plan_summary && (
                  <div>
                    <div className="mb-1 text-muted-foreground">Preflight EXPLAIN</div>
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
