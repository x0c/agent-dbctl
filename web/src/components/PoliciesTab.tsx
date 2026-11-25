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
  Switch,
  toast,
} from '@x0c/ui'
import { Plus, RefreshCw, Save } from 'lucide-react'
import { useEffect, useState } from 'react'
import {
  api,
  type DisplayCatalog,
  type EnvironmentRecord,
  type GlobalSecurityConfig,
  type PolicyRuleSet,
  type SystemRecord,
  type TargetDetail,
} from '../api'

export function PoliciesTab({
  catalog,
  onSavedGlobal,
}: {
  catalog: DisplayCatalog
  onSavedGlobal: (cfg: GlobalSecurityConfig) => void
}) {
  const [globalCfg, setGlobalCfg] = useState<GlobalSecurityConfig | null>(null)
  const [policies, setPolicies] = useState<PolicyRuleSet[]>([])
  const [envs, setEnvs] = useState<EnvironmentRecord[]>([])
  const [systems, setSystems] = useState<SystemRecord[]>([])
  const [targets, setTargets] = useState<TargetDetail[]>([])
  const [loading, setLoading] = useState(true)
  const [savingGlobal, setSavingGlobal] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const [dialogOpen, setDialogOpen] = useState(false)
  const [savingPol, setSavingPol] = useState(false)
  const [polErr, setPolErr] = useState<string | null>(null)
  const [polForm, setPolForm] = useState<Partial<PolicyRuleSet>>({
    id: '',
    name: '',
    scope_type: 'env',
    scope_id: 'prod',
    approval_provider: 'local-web',
  })

  const load = async () => {
    setLoading(true)
    setError(null)
    try {
      const [gRes, pRes, eRes, sRes, tRes] = await Promise.all([
        api.getGlobalSecurity(),
        api.listPolicies(),
        api.listEnvironments(),
        api.listSystems(),
        api.listTargets(),
      ])
      setGlobalCfg(gRes)
      setPolicies(pRes.items ?? [])
      setEnvs(eRes.items ?? [])
      setSystems(sRes.items ?? [])
      setTargets(tRes.items ?? [])
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to load policies')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    void load()
  }, [])

  const saveGlobal = async () => {
    if (!globalCfg) return
    setSavingGlobal(true)
    try {
      const updated = await api.saveGlobalSecurity(globalCfg)
      setGlobalCfg(updated)
      onSavedGlobal(updated)
      toast.success('Global security guardrails updated')
    } catch (e) {
      toast.error(e instanceof Error ? e.message : 'Update failed')
    } finally {
      setSavingGlobal(false)
    }
  }

  const savePolicy = async () => {
    setSavingPol(true)
    setPolErr(null)
    try {
      await api.savePolicy(polForm)
      setDialogOpen(false)
      toast.success('Policy saved')
      await load()
    } catch (e) {
      setPolErr(e instanceof Error ? e.message : 'Save failed')
    } finally {
      setSavingPol(false)
    }
  }

  const columns: ColumnDef<PolicyRuleSet, unknown>[] = [
    {
      accessorKey: 'name',
      header: 'Policy Name',
      cell: ({ row }) => <span className="font-mono text-xs font-semibold">{row.original.name}</span>,
    },
    {
      id: 'scope',
      header: 'Scope',
      cell: ({ row }) => (
        <Badge variant="outline" className="font-mono text-[11px]">
          {row.original.scope_type}:{row.original.scope_id}
        </Badge>
      ),
    },
    {
      id: 'limits',
      header: 'Tightened Limits',
      cell: ({ row }) => (
        <span className="font-mono text-xs text-muted-foreground">
          timeout={row.original.exec_timeout_sec ?? 'inherit'}s · max_rows={row.original.max_rows ?? 'inherit'}
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
              setPolErr(null)
              setPolForm({ ...row.original })
              setDialogOpen(true)
            }}
          >
            Edit
          </Button>
          <ConfirmAction
            trigger={<Button size="sm" variant="ghost">Delete</Button>}
            title={`Delete policy ${row.original.name}?`}
            confirmLabel="Delete"
            destructive
            onConfirm={async () => {
              await api.deletePolicy(row.original.id)
              await load()
            }}
          />
        </div>
      ),
    },
  ]

  return (
    <div className="space-y-5">
      <PageHeader
        title="Policies & Guardrails"
        actions={
          <div className="flex items-center gap-2">
            <Button variant="outline" size="sm" onClick={() => void load()} disabled={loading}>
              <RefreshCw className={loading ? 'animate-spin' : undefined} />
              Refresh
            </Button>
            <Button
              size="sm"
              onClick={() => {
                setPolErr(null)
                setPolForm({
                  id: '',
                  name: '',
                  scope_type: 'env',
                  scope_id: envs[0]?.code ?? 'prod',
                  approval_provider: 'local-web',
                })
                setDialogOpen(true)
              }}
            >
              <Plus />
              New Policy Override
            </Button>
          </div>
        }
      />

      {error && <Notice tone="error">{error}</Notice>}

      {globalCfg && (
        <Panel
          title="Global Security Guardrails (Hard Ceilings)"
          action={
            <LoadingButton size="sm" pending={savingGlobal} onClick={() => void saveGlobal()}>
              <Save className="size-3.5" />
              Save Guardrails
            </LoadingButton>
          }
        >
          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
            <FormField label="Execution Timeout (sec)">
              <Input
                type="number"
                value={globalCfg.exec_timeout_sec}
                onChange={(e) => setGlobalCfg((p) => p && { ...p, exec_timeout_sec: Number(e.target.value) })}
              />
            </FormField>
            <FormField label="Approval Timeout (sec)">
              <Input
                type="number"
                value={globalCfg.approval_timeout_sec}
                onChange={(e) => setGlobalCfg((p) => p && { ...p, approval_timeout_sec: Number(e.target.value) })}
              />
            </FormField>
            <FormField label="Max Returned Rows">
              <Input
                type="number"
                value={globalCfg.max_rows}
                onChange={(e) => setGlobalCfg((p) => p && { ...p, max_rows: Number(e.target.value) })}
              />
            </FormField>
            <FormField label="Max Returned Bytes">
              <Input
                type="number"
                value={globalCfg.max_bytes}
                onChange={(e) => setGlobalCfg((p) => p && { ...p, max_bytes: Number(e.target.value) })}
              />
            </FormField>
            <FormField label="EXPLAIN Estimated Row Threshold">
              <Input
                type="number"
                value={globalCfg.explain_max_rows}
                onChange={(e) => setGlobalCfg((p) => p && { ...p, explain_max_rows: Number(e.target.value) })}
              />
            </FormField>
            <FormField label="Default Approval Provider">
              <Select
                value={globalCfg.default_approval_provider}
                onValueChange={(v) => setGlobalCfg((p) => p && { ...p, default_approval_provider: v })}
              >
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>
                  {catalog.approval_providers.map((ap) => (
                    <SelectItem key={ap.code} value={ap.code}>{ap.code}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </FormField>
          </div>

          <div className="mt-4 grid gap-3 border-t border-border pt-4 sm:grid-cols-3">
            <label className="flex items-center justify-between rounded-md border border-border px-3 py-2 text-sm">
              <span>Prod Read-Only Freeze</span>
              <Switch
                checked={globalCfg.prod_read_only_freeze}
                onCheckedChange={(c) => setGlobalCfg((p) => p && { ...p, prod_read_only_freeze: c })}
              />
            </label>
            <label className="flex items-center justify-between rounded-md border border-border px-3 py-2 text-sm">
              <span>Block Multi-Statement in Prod</span>
              <Switch
                checked={globalCfg.block_multi_statement_in_prod}
                onCheckedChange={(c) => setGlobalCfg((p) => p && { ...p, block_multi_statement_in_prod: c })}
              />
            </label>
            <label className="flex items-center justify-between rounded-md border border-border px-3 py-2 text-sm">
              <span>Redact Literals in Audit</span>
              <Switch
                checked={globalCfg.redact_audit_literals}
                onCheckedChange={(c) => setGlobalCfg((p) => p && { ...p, redact_audit_literals: c })}
              />
            </label>
          </div>
        </Panel>
      )}

      <Panel title="Scoped Policy Overrides (Env → System → Target)" flush>
        <DataTable columns={columns} data={policies} emptyLabel="No scoped policy overrides configured (using environment defaults)." />
      </Panel>

      <FormDialog
        open={dialogOpen}
        onOpenChange={setDialogOpen}
        title={polForm.id ? 'Edit Policy Override' : 'New Policy Override'}
        error={polErr}
        pending={savingPol}
        onSubmit={savePolicy}
      >
        <FormField label="Name">
          <Input value={polForm.name ?? ''} onChange={(e) => setPolForm((p) => ({ ...p, name: e.target.value }))} />
        </FormField>
        <div className="grid grid-cols-2 gap-3">
          <FormField label="Scope Type">
            <Select value={polForm.scope_type ?? 'env'} onValueChange={(v) => setPolForm((p) => ({ ...p, scope_type: v as PolicyRuleSet['scope_type'], scope_id: '' }))}>
              <SelectTrigger><SelectValue /></SelectTrigger>
              <SelectContent>
                <SelectItem value="env">env</SelectItem>
                <SelectItem value="system">system</SelectItem>
                <SelectItem value="target">target</SelectItem>
              </SelectContent>
            </Select>
          </FormField>
          <FormField label="Scope Target">
            <Select value={polForm.scope_id ?? ''} onValueChange={(v) => setPolForm((p) => ({ ...p, scope_id: v }))}>
              <SelectTrigger><SelectValue placeholder="Select scope" /></SelectTrigger>
              <SelectContent>
                {polForm.scope_type === 'env' && envs.map((e) => <SelectItem key={e.code} value={e.code}>{e.code}</SelectItem>)}
                {polForm.scope_type === 'system' && systems.map((s) => <SelectItem key={s.id} value={s.id}>{s.slug}</SelectItem>)}
                {polForm.scope_type === 'target' && targets.map((t) => <SelectItem key={t.target.id} value={t.target.id}>{t.target.ref}</SelectItem>)}
              </SelectContent>
            </Select>
          </FormField>
        </div>
        <div className="grid grid-cols-2 gap-3">
          <FormField label="Exec Timeout Override (sec)">
            <Input
              type="number"
              value={polForm.exec_timeout_sec ?? ''}
              onChange={(e) => setPolForm((p) => ({ ...p, exec_timeout_sec: e.target.value ? Number(e.target.value) : null }))}
              placeholder="Inherit global"
            />
          </FormField>
          <FormField label="Max Rows Override">
            <Input
              type="number"
              value={polForm.max_rows ?? ''}
              onChange={(e) => setPolForm((p) => ({ ...p, max_rows: e.target.value ? Number(e.target.value) : null }))}
              placeholder="Inherit global"
            />
          </FormField>
        </div>
        <div className="grid grid-cols-2 gap-3 text-sm">
          <label className="flex items-center justify-between rounded-md border border-border px-3 py-2">
            <span>Approve High-Cost Read</span>
            <Switch
              checked={polForm.require_approval_on_high_cost_read ?? true}
              onCheckedChange={(c) => setPolForm((p) => ({ ...p, require_approval_on_high_cost_read: c }))}
            />
          </label>
          <label className="flex items-center justify-between rounded-md border border-border px-3 py-2">
            <span>Approve Writes</span>
            <Switch
              checked={polForm.require_approval_on_write ?? true}
              onCheckedChange={(c) => setPolForm((p) => ({ ...p, require_approval_on_write: c }))}
            />
          </label>
        </div>
      </FormDialog>
    </div>
  )
}
