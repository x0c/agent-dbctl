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
  Tabs,
  TabsContent,
  TabsList,
  TabsTrigger,
  toast,
} from '@x0c/ui'
import { Plus, RefreshCw, Save } from 'lucide-react'
import { useEffect, useState, type FormEvent } from 'react'
import {
  api,
  type DisplayCatalog,
  type EnvironmentRecord,
  type GlobalSecurityConfig,
  type PolicyRuleSet,
  type SystemRecord,
  type TargetDetail,
} from '../api'
import { resolveDisplayItem } from '../lib/catalog'
import { useI18n } from '../lib/i18n'
import { RiskPatternsPanel } from './RiskPatternsPanel'

export function PoliciesTab({
  catalog,
  onSavedGlobal,
}: {
  catalog: DisplayCatalog
  onSavedGlobal: (cfg: GlobalSecurityConfig) => void
}) {
  const { locale, t } = useI18n()
  const [globalCfg, setGlobalCfg] = useState<GlobalSecurityConfig | null>(null)
  const [policies, setPolicies] = useState<PolicyRuleSet[]>([])
  const [envs, setEnvs] = useState<EnvironmentRecord[]>([])
  const [systems, setSystems] = useState<SystemRecord[]>([])
  const [targets, setTargets] = useState<TargetDetail[]>([])
  const [loading, setLoading] = useState(true)
  const [savingGlobal, setSavingGlobal] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const [subTab, setSubTab] = useState<'guardrails' | 'patterns'>('guardrails')
  const [dialogOpen, setDialogOpen] = useState(false)
  const [savingPol, setSavingPol] = useState(false)
  const [polErr, setPolErr] = useState<string | null>(null)
  const [polForm, setPolForm] = useState<Partial<PolicyRuleSet>>({
    id: '',
    name: '',
    scope_type: 'env',
    scope_id: 'prod',
    approval_provider: '',
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
      setError(e instanceof Error ? e.message : t('policies.loadFailed'))
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
      toast.success(t('policies.globalSaved'))
    } catch (e) {
      toast.error(e instanceof Error ? e.message : t('policies.updateFailed'))
    } finally {
      setSavingGlobal(false)
    }
  }

  const savePolicy = async (e?: FormEvent<HTMLFormElement>) => {
    e?.preventDefault()
    setSavingPol(true)
    setPolErr(null)
    try {
      await api.savePolicy(polForm)
      setDialogOpen(false)
      toast.success(t('policies.policySaved'))
      await load()
    } catch (e) {
      setPolErr(e instanceof Error ? e.message : t('common.saveFailed'))
    } finally {
      setSavingPol(false)
    }
  }

  const columns: ColumnDef<PolicyRuleSet, unknown>[] = [
    {
      accessorKey: 'name',
      header: t('policies.col.name'),
      cell: ({ row }) => <span className="font-mono text-xs font-semibold">{row.original.name}</span>,
    },
    {
      id: 'scope',
      header: t('policies.col.scope'),
      cell: ({ row }) => (
        <Badge variant="outline" className="font-mono text-[11px]">
          {row.original.scope_type}:{row.original.scope_id}
        </Badge>
      ),
    },
    {
      id: 'limits',
      header: t('policies.col.limits'),
      cell: ({ row }) => (
        <span className="font-mono text-xs text-muted-foreground">
          {t('policies.limitsSummary', {
            timeout: row.original.exec_timeout_sec ?? t('policies.inherit'),
            rows: row.original.max_rows ?? t('policies.inherit'),
          })}
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
            {t('common.edit')}
          </Button>
          <ConfirmAction
            trigger={<Button size="sm" variant="ghost">{t('common.delete')}</Button>}
            title={t('policies.deleteTitle', { name: row.original.name })}
            confirmLabel={t('common.delete')}
            cancelLabel={t('common.cancel')}
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
        title={t('policies.title')}
        actions={
          <div className="flex items-center gap-2">
            <Button variant="outline" size="sm" onClick={() => void load()} disabled={loading}>
              <RefreshCw className={loading ? 'animate-spin' : undefined} />
              {t('common.refresh')}
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
                  approval_provider: '',
                })
                setDialogOpen(true)
              }}
            >
              <Plus />
              {t('policies.newOverride')}
            </Button>
          </div>
        }
      />

      {error && <Notice tone="error">{error}</Notice>}

      <Tabs value={subTab} onValueChange={(v) => setSubTab(v as typeof subTab)}>
        <TabsList>
          <TabsTrigger value="guardrails">{t('policies.tab.guardrails')}</TabsTrigger>
          <TabsTrigger value="patterns">{t('policies.tab.patterns')}</TabsTrigger>
        </TabsList>

        <TabsContent value="guardrails" className="space-y-5 pt-2">
          {globalCfg && (
            <Panel
              title={t('policies.globalTitle')}
              action={
                <LoadingButton size="sm" pending={savingGlobal} onClick={() => void saveGlobal()}>
                  <Save className="size-3.5" />
                  {t('policies.saveGuardrails')}
                </LoadingButton>
              }
            >
              <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
                <FormField label={t('policies.execTimeout')}>
                  <Input
                    type="number"
                    value={globalCfg.exec_timeout_sec}
                    onChange={(e) => setGlobalCfg((p) => p && { ...p, exec_timeout_sec: Number(e.target.value) })}
                  />
                </FormField>
                <FormField label={t('policies.approvalTimeout')}>
                  <Input
                    type="number"
                    value={globalCfg.approval_timeout_sec}
                    onChange={(e) => setGlobalCfg((p) => p && { ...p, approval_timeout_sec: Number(e.target.value) })}
                  />
                </FormField>
                <FormField label={t('policies.maxRows')}>
                  <Input
                    type="number"
                    value={globalCfg.max_rows}
                    onChange={(e) => setGlobalCfg((p) => p && { ...p, max_rows: Number(e.target.value) })}
                  />
                </FormField>
                <FormField label={t('policies.maxBytes')}>
                  <Input
                    type="number"
                    value={globalCfg.max_bytes}
                    onChange={(e) => setGlobalCfg((p) => p && { ...p, max_bytes: Number(e.target.value) })}
                  />
                </FormField>
                <FormField label={t('policies.explainMaxRows')}>
                  <Input
                    type="number"
                    value={globalCfg.explain_max_rows}
                    onChange={(e) => setGlobalCfg((p) => p && { ...p, explain_max_rows: Number(e.target.value) })}
                  />
                </FormField>
                <FormField label={t('policies.defaultProvider')}>
                  <Select
                    value={globalCfg.default_approval_provider}
                    onValueChange={(v) => setGlobalCfg((p) => p && { ...p, default_approval_provider: v })}
                  >
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      {catalog.approval_providers.map((ap) => (
                        <SelectItem key={ap.code} value={ap.code}>
                          {resolveDisplayItem(catalog.approval_providers, ap.code, locale).label}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </FormField>
              </div>

              <div className="mt-4 grid gap-3 border-t border-border pt-4 sm:grid-cols-2">
                <label className="flex items-center justify-between rounded-md border border-border px-3 py-2 text-sm">
                  <span>{t('policies.prodFreeze')}</span>
                  <Switch
                    checked={globalCfg.prod_read_only_freeze}
                    onCheckedChange={(c) => setGlobalCfg((p) => p && { ...p, prod_read_only_freeze: c })}
                  />
                </label>
                <label className="flex items-center justify-between rounded-md border border-border px-3 py-2 text-sm">
                  <span>{t('policies.blockMultiProd')}</span>
                  <Switch
                    checked={globalCfg.block_multi_statement_in_prod}
                    onCheckedChange={(c) => setGlobalCfg((p) => p && { ...p, block_multi_statement_in_prod: c })}
                  />
                </label>
                <label className="flex items-center justify-between rounded-md border border-border px-3 py-2 text-sm">
                  <span>{t('policies.redactAudit')}</span>
                  <Switch
                    checked={globalCfg.redact_audit_literals}
                    onCheckedChange={(c) => setGlobalCfg((p) => p && { ...p, redact_audit_literals: c })}
                  />
                </label>
                <label className="flex items-center justify-between rounded-md border border-border px-3 py-2 text-sm">
                  <span>{t('policies.requireReason')}</span>
                  <Switch
                    checked={globalCfg.require_reason_for_approval}
                    onCheckedChange={(c) => setGlobalCfg((p) => p && { ...p, require_reason_for_approval: c })}
                  />
                </label>
              </div>
            </Panel>
          )}

          <Panel title={t('policies.overridesTitle')} flush>
            <DataTable
              columns={columns}
              data={policies}
              searchPlaceholder={t('common.search')}
              emptyLabel={t('policies.overridesEmpty')}
            />
          </Panel>
        </TabsContent>

        <TabsContent value="patterns" className="pt-2">
          <RiskPatternsPanel envs={envs} systems={systems} targets={targets} />
        </TabsContent>
      </Tabs>

      <FormDialog
        open={dialogOpen}
        onOpenChange={setDialogOpen}
        title={polForm.id ? t('policies.dialog.editTitle') : t('policies.dialog.newTitle')}
        submitLabel={t('common.save')}
        cancelLabel={t('common.cancel')}
        error={polErr}
        pending={savingPol}
        onSubmit={savePolicy}
      >
        <FormField label={t('policies.field.name')}>
          <Input value={polForm.name ?? ''} onChange={(e) => setPolForm((p) => ({ ...p, name: e.target.value }))} />
        </FormField>
        <div className="grid grid-cols-2 gap-3">
          <FormField label={t('policies.field.scopeType')}>
            <Select
              value={polForm.scope_type ?? 'env'}
              onValueChange={(v) =>
                setPolForm((p) => ({ ...p, scope_type: v as PolicyRuleSet['scope_type'], scope_id: '' }))
              }
            >
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="env">env</SelectItem>
                <SelectItem value="system">system</SelectItem>
                <SelectItem value="target">target</SelectItem>
              </SelectContent>
            </Select>
          </FormField>
          <FormField label={t('policies.field.scopeTarget')}>
            <Select value={polForm.scope_id ?? ''} onValueChange={(v) => setPolForm((p) => ({ ...p, scope_id: v }))}>
              <SelectTrigger>
                <SelectValue placeholder={t('policies.field.selectScope')} />
              </SelectTrigger>
              <SelectContent>
                {polForm.scope_type === 'env' &&
                  envs.map((e) => (
                    <SelectItem key={e.code} value={e.code}>
                      {e.code}
                    </SelectItem>
                  ))}
                {polForm.scope_type === 'system' &&
                  systems.map((s) => (
                    <SelectItem key={s.id} value={s.id}>
                      {s.slug}
                    </SelectItem>
                  ))}
                {polForm.scope_type === 'target' &&
                  targets.map((tg) => (
                    <SelectItem key={tg.target.id} value={tg.target.id}>
                      {tg.target.ref}
                    </SelectItem>
                  ))}
              </SelectContent>
            </Select>
          </FormField>
        </div>
        <div className="grid grid-cols-2 gap-3">
          <FormField label={t('policies.field.execTimeoutOverride')}>
            <Input
              type="number"
              value={polForm.exec_timeout_sec ?? ''}
              onChange={(e) =>
                setPolForm((p) => ({ ...p, exec_timeout_sec: e.target.value ? Number(e.target.value) : null }))
              }
              placeholder={t('policies.field.inheritGlobal')}
            />
          </FormField>
          <FormField label={t('policies.field.maxRowsOverride')}>
            <Input
              type="number"
              value={polForm.max_rows ?? ''}
              onChange={(e) =>
                setPolForm((p) => ({ ...p, max_rows: e.target.value ? Number(e.target.value) : null }))
              }
              placeholder={t('policies.field.inheritGlobal')}
            />
          </FormField>
        </div>
        <div className="grid grid-cols-2 gap-3 text-sm">
          <label className="flex items-center justify-between rounded-md border border-border px-3 py-2">
            <span>{t('policies.field.approveHighCost')}</span>
            <Switch
              checked={polForm.require_approval_on_high_cost_read ?? true}
              onCheckedChange={(c) => setPolForm((p) => ({ ...p, require_approval_on_high_cost_read: c }))}
            />
          </label>
          <label className="flex items-center justify-between rounded-md border border-border px-3 py-2">
            <span>{t('policies.field.approveWrites')}</span>
            <Switch
              checked={polForm.require_approval_on_write ?? true}
              onCheckedChange={(c) => setPolForm((p) => ({ ...p, require_approval_on_write: c }))}
            />
          </label>
        </div>
        <FormField label={t('policies.field.providerOverride')}>
          <Select
            value={polForm.approval_provider || '__inherit'}
            onValueChange={(v) => setPolForm((p) => ({ ...p, approval_provider: v === '__inherit' ? '' : v }))}
          >
            <SelectTrigger>
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="__inherit">{t('policies.field.inheritParent')}</SelectItem>
              {catalog.approval_providers.map((ap) => (
                <SelectItem key={ap.code} value={ap.code}>
                  {resolveDisplayItem(catalog.approval_providers, ap.code, locale).label}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </FormField>
      </FormDialog>
    </div>
  )
}
