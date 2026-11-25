import {
  Badge,
  Button,
  FormField,
  Input,
  LoadingButton,
  Notice,
  PageHeader,
  Panel,
  fmtDateTime,
  toast,
} from '@x0c/ui'
import { AlertTriangle, Check, Clock, RefreshCw, ShieldAlert, X } from 'lucide-react'
import { useEffect, useMemo, useState } from 'react'
import {
  api,
  type ApprovalRecord,
  type DisplayCatalog,
  type GlobalSecurityConfig,
} from '../api'
import { MetaBadge } from './MetaBadge'

export function ApprovalsTab({
  catalog,
  globalSecurity,
  deepLinkId,
  deepLinkToken,
  onToggleFreeze,
  onCountChange,
}: {
  catalog: DisplayCatalog
  globalSecurity: GlobalSecurityConfig | null
  deepLinkId: string | null
  deepLinkToken: string | null
  onToggleFreeze: (next: boolean) => Promise<void>
  onCountChange: (pendingCount: number) => void
}) {
  const [items, setItems] = useState<ApprovalRecord[]>([])
  const [filterStatus, setFilterStatus] = useState<'pending' | 'all'>('pending')
  const [selectedId, setSelectedId] = useState<string | null>(deepLinkId)
  const [noteById, setNoteById] = useState<Record<string, string>>({})
  const [submittingId, setSubmittingId] = useState<string | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [nowMs, setNowMs] = useState(() => Date.now())

  const load = async () => {
    setLoading(true)
    setError(null)
    try {
      const res = await api.listApprovals(filterStatus === 'pending' ? 'pending' : undefined)
      const list = res.items ?? []
      setItems(list)
      if (filterStatus === 'pending') {
        onCountChange(list.length)
      } else {
        onCountChange(list.filter((x) => x.status === 'pending').length)
      }
      if (deepLinkId && list.some((x) => x.id === deepLinkId)) {
        setSelectedId(deepLinkId)
      } else if (!selectedId && list.length > 0) {
        setSelectedId(list[0].id)
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to load approvals')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    void load()
  }, [filterStatus, deepLinkId])

  useEffect(() => {
    const timer = window.setInterval(() => setNowMs(Date.now()), 1000)
    return () => window.clearInterval(timer)
  }, [])

  useEffect(() => {
    const es = new EventSource('/api/v1/events')
    const refresh = () => void load()
    es.addEventListener('approval_created', refresh)
    es.addEventListener('approval_resolved', refresh)
    es.addEventListener('operation_updated', refresh)
    return () => es.close()
  }, [filterStatus])

  const selected = useMemo(
    () => items.find((x) => x.id === selectedId) ?? items[0] ?? null,
    [items, selectedId],
  )

  const handleDecision = async (app: ApprovalRecord, approve: boolean) => {
    const note = (noteById[app.id] ?? '').trim()
    if (!approve && !note) {
      toast.error('Please enter a rejection note for the agent.')
      return
    }
    setSubmittingId(app.id)
    try {
      const token = app.id === deepLinkId && deepLinkToken ? deepLinkToken : undefined
      if (approve) {
        await api.approve(app.id, { reviewer: 'local-human', note, token })
        toast.success(`Approved ${app.target_ref}`)
      } else {
        await api.reject(app.id, { reviewer: 'local-human', note, token })
        toast.success(`Rejected ${app.target_ref}`)
      }
      await load()
    } catch (e) {
      toast.error(e instanceof Error ? e.message : 'Decision failed')
    } finally {
      setSubmittingId(null)
    }
  }

  const remainingText = (expiresAt: string) => {
    const diff = Math.floor((new Date(expiresAt).getTime() - nowMs) / 1000)
    if (Number.isNaN(diff)) return '—'
    if (diff <= 0) return 'Expired'
    const m = Math.floor(diff / 60)
    const s = diff % 60
    return m > 0 ? `${m}m ${s}s` : `${s}s`
  }

  return (
    <div className="space-y-5">
      <PageHeader
        title="Approvals"
        actions={
          <div className="flex items-center gap-2">
            <div className="flex rounded-md border border-border bg-card p-0.5 text-xs">
              <button
                type="button"
                onClick={() => setFilterStatus('pending')}
                className={`cursor-pointer rounded px-2.5 py-1 font-medium ${
                  filterStatus === 'pending' ? 'bg-primary text-primary-foreground' : 'text-muted-foreground'
                }`}
              >
                Pending
              </button>
              <button
                type="button"
                onClick={() => setFilterStatus('all')}
                className={`cursor-pointer rounded px-2.5 py-1 font-medium ${
                  filterStatus === 'all' ? 'bg-primary text-primary-foreground' : 'text-muted-foreground'
                }`}
              >
                All
              </button>
            </div>
            <Button variant="outline" size="sm" onClick={() => void load()} disabled={loading}>
              <RefreshCw className={loading ? 'animate-spin' : undefined} />
              Refresh
            </Button>
          </div>
        }
      />

      {globalSecurity?.prod_read_only_freeze && (
        <Notice tone="warning">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <span>
              Production read-only freeze is active. All mutating or unknown production operations are automatically denied.
            </span>
            <Button size="sm" variant="outline" onClick={() => void onToggleFreeze(false)}>
              Disable Freeze
            </Button>
          </div>
        </Notice>
      )}

      {error && <Notice tone="error">{error}</Notice>}

      <div className="grid gap-5 lg:grid-cols-[340px_1fr]">
        <Panel title={`Queue (${items.length})`} flush>
          {items.length === 0 ? (
            <div className="px-4 py-8 text-center text-sm text-muted-foreground">
              No {filterStatus === 'pending' ? 'pending' : ''} approval requests
            </div>
          ) : (
            <div className="divide-y divide-border">
              {items.map((app) => {
                const active = selected?.id === app.id
                return (
                  <button
                    key={app.id}
                    type="button"
                    onClick={() => setSelectedId(app.id)}
                    className={`flex h-[68px] w-full cursor-pointer flex-col justify-center gap-1 px-4 text-left transition-colors ${
                      active ? 'bg-muted/80' : 'hover:bg-muted/40'
                    }`}
                  >
                    <div className="flex items-center justify-between gap-2">
                      <span className="truncate font-mono text-xs font-semibold text-foreground">
                        {app.target_ref}
                      </span>
                      <MetaBadge items={catalog.environments} code={app.environment_code} />
                    </div>
                    <div className="flex items-center justify-between gap-2 text-xs text-muted-foreground">
                      <span className="truncate">{app.reason || app.query_text}</span>
                      <span className="shrink-0 font-mono tabular-nums">
                        {app.status === 'pending' ? remainingText(app.expires_at_utc) : app.status}
                      </span>
                    </div>
                  </button>
                )
              })}
            </div>
          )}
        </Panel>

        <Panel title={selected ? `Request ${selected.id}` : 'Approval Detail'}>
          {!selected ? (
            <div className="py-12 text-center text-sm text-muted-foreground">
              Select an approval request to inspect query details and execution plan.
            </div>
          ) : (
            <div className="space-y-4">
              <div className="flex flex-wrap items-center justify-between gap-2 border-b border-border pb-3">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="font-mono text-sm font-semibold">{selected.target_ref}</span>
                  <MetaBadge items={catalog.environments} code={selected.environment_code} />
                  <MetaBadge items={catalog.engines} code={selected.engine} />
                  <MetaBadge items={catalog.risk_levels} code={selected.risk_level} />
                </div>
                <div className="flex items-center gap-1.5 font-mono text-xs text-muted-foreground">
                  <Clock className="size-3.5" />
                  {selected.status === 'pending'
                    ? `Expires in ${remainingText(selected.expires_at_utc)}`
                    : fmtDateTime(selected.resolved_at_utc || selected.created_at_utc)}
                </div>
              </div>

              <div className="grid gap-3 rounded-md border border-border bg-muted/30 p-3 text-xs sm:grid-cols-3">
                <div>
                  <div className="text-muted-foreground">System</div>
                  <div className="mt-0.5 font-mono font-medium">{selected.system_slug || '—'}</div>
                </div>
                <div>
                  <div className="text-muted-foreground">Actor & Provider</div>
                  <div className="mt-0.5 font-mono font-medium">
                    {selected.actor} · {selected.provider}
                  </div>
                </div>
                <div>
                  <div className="text-muted-foreground">Workspace</div>
                  <div className="mt-0.5 truncate font-mono" title={selected.workspace_cwd}>
                    {selected.workspace_cwd ? selected.workspace_cwd.replace(/^\/Users\/[^/]+/, '~') : '—'}
                  </div>
                </div>
              </div>

              {selected.reason && (
                <div className="rounded-md border border-border bg-card px-3 py-2 text-sm">
                  <span className="mr-2 font-medium text-muted-foreground">Reason:</span>
                  <span>{selected.reason}</span>
                </div>
              )}

              {(selected.matched_rules ?? []).length > 0 && (
                <div className="space-y-2 rounded-md border border-amber-300 bg-amber-50/70 p-3 text-xs">
                  <div className="flex items-center gap-1.5 font-semibold text-amber-950">
                    <ShieldAlert className="size-4 text-amber-700" />
                    <span>High-Risk Pattern Confirmation</span>
                  </div>
                  <div className="space-y-1.5">
                    {selected.matched_rules!.map((mr) => (
                      <div
                        key={`${mr.rule_id}-${mr.rule_name}`}
                        className="rounded border border-amber-200 bg-white/80 px-2.5 py-2"
                      >
                        <div className="flex flex-wrap items-center gap-2">
                          <span className="font-semibold text-amber-950">{mr.confirm_title || mr.rule_name}</span>
                          <Badge variant="outline" className="font-mono text-[10px]">
                            {mr.scope}
                          </Badge>
                          <Badge variant="outline" className="border-amber-300 font-mono text-[10px] text-amber-900">
                            {mr.action}
                          </Badge>
                          {mr.matched_fragment && (
                            <code className="rounded bg-amber-100/80 px-1.5 py-0.5 font-mono text-[11px] text-amber-950">
                              {mr.matched_fragment}
                            </code>
                          )}
                        </div>
                        {mr.confirm_message && <div className="mt-1 text-amber-900">{mr.confirm_message}</div>}
                      </div>
                    ))}
                  </div>
                </div>
              )}

              <div>
                <div className="mb-1.5 flex items-center justify-between">
                  <span className="text-xs font-medium text-muted-foreground">Verbatim Query / Command</span>
                  <div className="flex flex-wrap gap-1">
                    {(selected.trigger_reasons ?? []).map((r) => (
                      <Badge key={r} variant="outline" className="font-mono text-[11px]">
                        <ShieldAlert className="mr-1 size-3" />
                        {r}
                      </Badge>
                    ))}
                  </div>
                </div>
                <pre className="max-h-40 overflow-auto rounded-md border border-border bg-muted/40 p-3 font-mono text-xs leading-relaxed whitespace-pre-wrap break-all">
                  {selected.query_text}
                </pre>
              </div>

              {selected.preflight && (
                <div className="rounded-md border border-border bg-muted/20 p-3">
                  <div className="mb-1.5 flex items-center justify-between text-xs font-medium">
                    <span className="flex items-center gap-1.5">
                      <AlertTriangle className="size-3.5 text-amber-600" />
                      Preflight EXPLAIN ({selected.preflight.format || 'plan'})
                    </span>
                    <span className="font-mono text-muted-foreground">
                      full_scan={String(selected.preflight.full_scan)} · est_rows={selected.preflight.estimated_rows}
                    </span>
                  </div>
                  {selected.preflight.plan_summary && (
                    <pre className="max-h-28 overflow-auto font-mono text-xs text-muted-foreground whitespace-pre-wrap">
                      {selected.preflight.plan_summary}
                    </pre>
                  )}
                </div>
              )}

              {selected.status === 'pending' ? (
                <div className="space-y-3 border-t border-border pt-3">
                  <FormField label="Reviewer Note (sent back to agent on reject)">
                    <Input
                      placeholder="Optional on approve; required on reject (e.g. Add LIMIT 100)"
                      value={noteById[selected.id] ?? ''}
                      onChange={(e) =>
                        setNoteById((prev) => ({ ...prev, [selected.id]: e.target.value }))
                      }
                    />
                  </FormField>
                  <div className="flex items-center justify-end gap-2">
                    <LoadingButton
                      variant="outline"
                      pending={submittingId === selected.id}
                      onClick={() => void handleDecision(selected, false)}
                    >
                      <X className="size-4" />
                      Reject
                    </LoadingButton>
                    <LoadingButton
                      pending={submittingId === selected.id}
                      onClick={() => void handleDecision(selected, true)}
                    >
                      <Check className="size-4" />
                      Approve & Execute
                    </LoadingButton>
                  </div>
                </div>
              ) : (
                <div className="rounded-md border border-border bg-muted/30 p-3 text-xs">
                  <div className="font-medium">
                    Decision: <span className="font-mono uppercase">{selected.status}</span> by{' '}
                    <span className="font-mono">{selected.reviewer || 'system'}</span>
                  </div>
                  {selected.reviewer_note && (
                    <div className="mt-1 text-muted-foreground">Note: {selected.reviewer_note}</div>
                  )}
                </div>
              )}
            </div>
          )}
        </Panel>
      </div>
    </div>
  )
}
