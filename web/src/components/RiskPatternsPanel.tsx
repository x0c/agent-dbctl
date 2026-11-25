import {
  Badge,
  Button,
  type ColumnDef,
  ConfirmAction,
  DataTable,
  FilterSelect,
  FormDialog,
  FormField,
  Input,
  LoadingButton,
  Notice,
  Panel,
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
  Switch,
  Textarea,
  toast,
} from '@x0c/ui'
import { FlaskConical, PackagePlus, Plus, ShieldAlert, Trash2 } from 'lucide-react'
import { useEffect, useState, type FormEvent } from 'react'
import {
  api,
  type BuiltinRulePack,
  type EnvironmentRecord,
  type PatternAction,
  type PatternCondition,
  type PatternMatcherType,
  type PatternTestResult,
  type RiskPatternRule,
  type SystemRecord,
  type TargetDetail,
} from '../api'
import { useI18n, type TranslationKey } from '../lib/i18n'

const ENGINES = [
  '*',
  'postgres',
  'opengauss',
  'kingbase',
  'dameng',
  'tdengine',
  'mysql',
  'sqlite',
  'mongodb',
  'redis',
  'clickhouse',
  'mssql',
  'oracle',
  'elasticsearch',
] as const

const MATCHER_TYPES: PatternMatcherType[] = [
  'function_call',
  'table_ref',
  'pragma_name',
  'command_arg',
  'json_path',
  'regex',
  'risk_flag',
  'preflight_metric',
]

function matcherLabelKey(type: PatternMatcherType): TranslationKey {
  return `patterns.matcher.${type}` as TranslationKey
}

function defaultCondition(type: PatternMatcherType = 'table_ref'): PatternCondition {
  switch (type) {
    case 'function_call':
      return { type, values: ['pg_sleep'] }
    case 'table_ref':
      return { type, values: ['orders'] }
    case 'pragma_name':
      return { type, values: ['query_only'] }
    case 'risk_flag':
      return { type, values: ['recursive_cte'] }
    case 'command_arg':
      return { type, command: 'SCAN', arg_keyword: 'COUNT', arg_greater_than: 10000 }
    case 'json_path':
      return { type, json_path: '$where' }
    case 'regex':
      return { type, pattern: '\\bFOR\\s+UPDATE\\b', target: 'normalized_no_literals' }
    case 'preflight_metric':
      return { type, metric: 'full_scan', bool_value: true }
  }
}

function summarizeCondition(c: PatternCondition): string {
  if (c.all?.length) return `ALL (${c.all.length}): ${c.all.map(summarizeCondition).join(' & ')}`
  if (c.any?.length) return `ANY (${c.any.length}): ${c.any.map(summarizeCondition).join(' | ')}`
  if (c.not) return `NOT (${summarizeCondition(c.not)})`
  switch (c.type) {
    case 'function_call':
      return `fn: ${(c.values ?? []).join(', ')}`
    case 'table_ref':
      return `table: ${(c.values ?? []).join(', ')}`
    case 'pragma_name':
      return `pragma: ${(c.values ?? []).join(', ')}`
    case 'risk_flag':
      return `flag: ${(c.values ?? []).join(', ')}`
    case 'command_arg':
      return [c.command, c.subcommand, c.arg_keyword, c.arg_equals || (c.arg_greater_than != null ? `>${c.arg_greater_than}` : '')]
        .filter(Boolean)
        .join(' ')
    case 'json_path':
      return c.equals ? `${c.json_path}=${c.equals}` : c.json_path || 'json_path'
    case 'regex':
      return `/${c.pattern ?? ''}/`
    case 'preflight_metric':
      if (c.metric === 'estimated_rows') return `est_rows ${c.operator || 'gt'} ${c.threshold ?? 0}`
      if (c.metric === 'plan_contains') return `plan ~ /${c.pattern ?? ''}/`
      return `full_scan=${String(c.bool_value ?? true)}`
    default:
      return 'custom'
  }
}

function actionBadge(action: PatternAction) {
  if (action === 'deny') {
    return (
      <Badge variant="destructive" className="font-mono text-[11px]">
        deny
      </Badge>
    )
  }
  if (action === 'require_approval') {
    return (
      <Badge variant="outline" className="border-amber-300 bg-amber-50 font-mono text-[11px] text-amber-900">
        require_approval
      </Badge>
    )
  }
  return (
    <Badge variant="outline" className="font-mono text-[11px]">
      elevate_high_cost
    </Badge>
  )
}

function newDraftRule(): RiskPatternRule {
  return {
    id: '',
    name: '',
    description: '',
    scope_type: 'global',
    scope_id: 'global',
    enabled: true,
    engines: ['*'],
    action: 'require_approval',
    confirm_title: '',
    confirm_message: '',
    approval_provider: '',
    condition: defaultCondition('table_ref'),
    priority: 50,
  }
}

export function RiskPatternsPanel({
  envs,
  systems,
  targets,
}: {
  envs: EnvironmentRecord[]
  systems: SystemRecord[]
  targets: TargetDetail[]
}) {
  const { t } = useI18n()
  const [rules, setRules] = useState<RiskPatternRule[]>([])
  const [packs, setPacks] = useState<BuiltinRulePack[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  const [packScopeType, setPackScopeType] = useState<'global' | 'env' | 'system' | 'target'>('global')
  const [packScopeId, setPackScopeId] = useState<string>('global')
  const [installingPack, setInstallingPack] = useState<string | null>(null)

  const [dialogOpen, setDialogOpen] = useState(false)
  const [savingRule, setSavingRule] = useState(false)
  const [ruleErr, setRuleErr] = useState<string | null>(null)
  const [ruleForm, setRuleForm] = useState<RiskPatternRule>(newDraftRule)
  const [condMode, setCondMode] = useState<'visual' | 'json'>('visual')
  const [combMode, setCombMode] = useState<'single' | 'all' | 'any'>('single')
  const [leafList, setLeafList] = useState<PatternCondition[]>([defaultCondition('table_ref')])
  const [jsonText, setJsonText] = useState<string>('{}')

  const [testTarget, setTestTarget] = useState<string>('__custom__')
  const [testEngine, setTestEngine] = useState<string>('postgres')
  const [testTier, setTestTier] = useState<'yolo' | 'guarded' | 'strict'>('guarded')
  const [testQuery, setTestQuery] = useState<string>('SELECT id FROM orders WHERE status = \'paid\' LIMIT 20')
  const [simFullScan, setSimFullScan] = useState(false)
  const [simRows, setSimRows] = useState('')
  const [testing, setTesting] = useState(false)
  const [testErr, setTestErr] = useState<string | null>(null)
  const [testResult, setTestResult] = useState<PatternTestResult | null>(null)

  const load = async () => {
    setLoading(true)
    setError(null)
    try {
      const res = await api.listRiskPatterns()
      setRules(res.items ?? [])
      setPacks(res.builtin_packs ?? [])
    } catch (e) {
      setError(e instanceof Error ? e.message : t('patterns.loadFailed'))
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    void load()
  }, [])

  useEffect(() => {
    return api.subscribeEvents(['patterns_updated'], () => {
      void load()
    })
  }, [])

  const openEditor = (rule?: RiskPatternRule) => {
    const r = rule ? { ...rule } : newDraftRule()
    setRuleErr(null)
    setRuleForm(r)
    setJsonText(JSON.stringify(r.condition, null, 2))
    if (r.condition.all?.length && r.condition.all.every((c) => Boolean(c.type))) {
      setCombMode('all')
      setLeafList(r.condition.all)
      setCondMode('visual')
    } else if (r.condition.any?.length && r.condition.any.every((c) => Boolean(c.type))) {
      setCombMode('any')
      setLeafList(r.condition.any)
      setCondMode('visual')
    } else if (r.condition.type) {
      setCombMode('single')
      setLeafList([r.condition])
      setCondMode('visual')
    } else {
      setCombMode('single')
      setLeafList([defaultCondition('table_ref')])
      setCondMode('json')
    }
    setDialogOpen(true)
  }

  const buildConditionFromState = (): PatternCondition => {
    if (condMode === 'json') {
      return JSON.parse(jsonText) as PatternCondition
    }
    if (combMode === 'all') return { all: leafList }
    if (combMode === 'any') return { any: leafList }
    return leafList[0] ?? defaultCondition('table_ref')
  }

  const saveRule = async (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault()
    setSavingRule(true)
    setRuleErr(null)
    try {
      const cond = buildConditionFromState()
      await api.saveRiskPattern({
        ...ruleForm,
        scope_id: ruleForm.scope_type === 'global' ? 'global' : ruleForm.scope_id,
        condition: cond,
      })
      setDialogOpen(false)
      toast.success(t('patterns.ruleSaved'))
      await load()
    } catch (err) {
      setRuleErr(err instanceof Error ? err.message : t('patterns.ruleSaveFailed'))
    } finally {
      setSavingRule(false)
    }
  }

  const toggleRuleEnabled = async (rule: RiskPatternRule, next: boolean) => {
    try {
      await api.saveRiskPattern({ ...rule, enabled: next })
      setRules((prev) => prev.map((x) => (x.id === rule.id ? { ...x, enabled: next } : x)))
    } catch (err) {
      toast.error(err instanceof Error ? err.message : t('patterns.ruleUpdateFailed'))
    }
  }

  const installPack = async (packId: string) => {
    if (packScopeType !== 'global' && !packScopeId) {
      toast.error(t('patterns.selectScopeFirst', { scope: packScopeType }))
      return
    }
    setInstallingPack(packId)
    try {
      const res = await api.installRulePack(packId, {
        scope_type: packScopeType,
        scope_id: packScopeType === 'global' ? 'global' : packScopeId,
      })
      toast.success(t('patterns.packEnabledToast', { count: res.items?.length ?? 0, pack: packId }))
      await load()
    } catch (err) {
      toast.error(err instanceof Error ? err.message : t('patterns.packEnableFailed'))
    } finally {
      setInstallingPack(null)
    }
  }

  const runTest = async () => {
    setTesting(true)
    setTestErr(null)
    try {
      const useTarget = testTarget !== '__custom__'
      const rowsNum = simRows.trim() ? Number(simRows) : undefined
      const simPf =
        simFullScan || rowsNum !== undefined
          ? {
              supported: true,
              executed: false,
              full_scan: simFullScan,
              estimated_rows: rowsNum ?? 0,
            }
          : null
      const res = await api.testRiskPattern({
        target_id: useTarget ? testTarget : undefined,
        engine: useTarget ? undefined : testEngine,
        safety_tier: useTarget ? undefined : testTier,
        query: testQuery,
        simulated_preflight: simPf,
      })
      setTestResult(res)
    } catch (err) {
      setTestErr(err instanceof Error ? err.message : t('patterns.dryRunFailed'))
    } finally {
      setTesting(false)
    }
  }

  const toggleEngineChip = (eng: string) => {
    setRuleForm((prev) => {
      const cur = prev.engines ?? []
      if (eng === '*') {
        return { ...prev, engines: ['*'] }
      }
      const withoutWild = cur.filter((x) => x !== '*')
      const exists = withoutWild.includes(eng)
      const next = exists ? withoutWild.filter((x) => x !== eng) : [...withoutWild, eng]
      return { ...prev, engines: next.length === 0 ? ['*'] : next }
    })
  }

  const resolveScopeLabel = (scopeType: string, scopeID: string) => {
    if (scopeType === 'global') return 'global'
    if (scopeType === 'system') {
      const sys = systems.find((s) => s.id === scopeID)
      return `sys:${sys?.slug || scopeID}`
    }
    if (scopeType === 'target') {
      const tgt = targets.find((tg) => tg.target.id === scopeID)
      return tgt ? tgt.target.ref : `target:${scopeID}`
    }
    return `${scopeType}:${scopeID}`
  }

  const columns: ColumnDef<RiskPatternRule, unknown>[] = [
    {
      accessorKey: 'name',
      header: t('patterns.col.rule'),
      cell: ({ row }) => (
        <div className="max-w-[140px] truncate font-mono text-xs font-semibold" title={row.original.name}>
          {row.original.name}
        </div>
      ),
    },
    {
      id: 'scope',
      header: t('patterns.col.scope'),
      cell: ({ row }) => {
        const label = resolveScopeLabel(row.original.scope_type, row.original.scope_id)
        return (
          <Badge variant="outline" className="max-w-[120px] truncate font-mono text-[11px]" title={label}>
            {label}
          </Badge>
        )
      },
    },
    {
      id: 'engines',
      header: t('patterns.col.engine'),
      cell: ({ row }) => (
        <span className="block max-w-[68px] truncate font-mono text-xs text-muted-foreground">
          {row.original.engines?.length ? row.original.engines.join(', ') : '*'}
        </span>
      ),
    },
    {
      id: 'condition',
      header: t('patterns.col.condition'),
      cell: ({ row }) => {
        const text = summarizeCondition(row.original.condition)
        return (
          <div className="max-w-[150px] truncate font-mono text-xs text-muted-foreground" title={text}>
            {text}
          </div>
        )
      },
    },
    {
      id: 'action',
      header: t('patterns.col.action'),
      cell: ({ row }) => actionBadge(row.original.action),
    },
    {
      id: 'enabled',
      header: t('patterns.col.on'),
      cell: ({ row }) => (
        <Switch checked={row.original.enabled} onCheckedChange={(c) => void toggleRuleEnabled(row.original, c)} />
      ),
    },
    {
      id: 'actions',
      header: '',
      cell: ({ row }) => (
        <div className="flex justify-end gap-1">
          <Button size="sm" variant="outline" onClick={() => openEditor(row.original)}>
            {t('common.edit')}
          </Button>
          <ConfirmAction
            trigger={
              <Button size="icon" variant="ghost" aria-label={t('patterns.deleteRuleAria', { name: row.original.name })}>
                <Trash2 className="size-3.5" />
              </Button>
            }
            title={t('patterns.deleteRuleTitle', { name: row.original.name })}
            confirmLabel={t('common.delete')}
            cancelLabel={t('common.cancel')}
            destructive
            onConfirm={async () => {
              await api.deleteRiskPattern(row.original.id)
              await load()
            }}
          />
        </div>
      ),
    },
  ]

  return (
    <div className="space-y-5">
      {error && <Notice tone="error">{error}</Notice>}

      <Panel
        title={t('patterns.packsTitle')}
        action={
          <div className="flex flex-wrap items-center gap-2">
            <FilterSelect
              value={packScopeType}
              className="sm:min-w-[100px]"
              onValueChange={(v) => {
                const next = v as typeof packScopeType
                setPackScopeType(next)
                if (next === 'global') setPackScopeId('global')
                else if (next === 'env') setPackScopeId(envs[0]?.code ?? '')
                else if (next === 'system') setPackScopeId(systems[0]?.id ?? '')
                else setPackScopeId(targets[0]?.target.id ?? '')
              }}
              options={[
                { value: 'global', label: 'global' },
                { value: 'env', label: 'env' },
                { value: 'system', label: 'system' },
                { value: 'target', label: 'target' },
              ]}
            />
            {packScopeType !== 'global' && (
              <FilterSelect
                value={packScopeId}
                onValueChange={setPackScopeId}
                placeholder={t('patterns.col.scope')}
                options={
                  packScopeType === 'env'
                    ? envs.map((e) => ({ value: e.code, label: e.code }))
                    : packScopeType === 'system'
                      ? systems.map((s) => ({ value: s.id, label: s.slug }))
                      : targets.map((tg) => ({ value: tg.target.id, label: tg.target.ref }))
                }
              />
            )}
          </div>
        }
      >
        <div className="grid grid-cols-1 gap-3 md:grid-cols-2 xl:grid-cols-3">
          {packs.map((pack) => {
            const installedCount = rules.filter(
              (r) =>
                r.builtin_pack === pack.id &&
                r.scope_type === packScopeType &&
                (packScopeType === 'global' || r.scope_id === packScopeId),
            ).length
            return (
              <div
                key={pack.id}
                className="flex h-full flex-col justify-between gap-3 rounded-md border border-border bg-muted/20 p-3"
              >
                <div className="space-y-1.5">
                  <div className="flex items-center justify-between gap-2">
                    <span className="truncate text-xs font-semibold">{pack.name}</span>
                    <Badge variant="outline" className="shrink-0 font-mono text-[10px]">
                      {pack.engines.join(', ')}
                    </Badge>
                  </div>
                  <p className="line-clamp-2 min-h-[2rem] text-xs text-muted-foreground">{pack.description}</p>
                </div>
                <div className="flex items-center justify-between border-t border-border pt-2">
                  <span className="font-mono text-[11px] text-muted-foreground">
                    {installedCount > 0
                      ? t('patterns.rulesActive', { installed: installedCount, total: pack.rules.length })
                      : t('patterns.rulesCount', { total: pack.rules.length })}
                  </span>
                  <LoadingButton
                    size="sm"
                    variant={installedCount > 0 ? 'outline' : 'default'}
                    pending={installingPack === pack.id}
                    onClick={() => void installPack(pack.id)}
                  >
                    <PackagePlus className="size-3.5" />
                    {installedCount > 0 ? t('patterns.syncPack') : t('patterns.enablePack')}
                  </LoadingButton>
                </div>
              </div>
            )
          })}
        </div>
      </Panel>

      <Panel
        title={t('patterns.rulesTitle')}
        action={
          <Button size="sm" onClick={() => openEditor()}>
            <Plus />
            {t('patterns.newRule')}
          </Button>
        }
        flush
      >
        <DataTable
          columns={columns}
          data={rules}
          loading={loading}
          searchPlaceholder={t('common.search')}
          emptyLabel={t('patterns.emptyRules')}
          className="rounded-none border-0"
        />
      </Panel>

      <Panel
        title={t('patterns.sandboxTitle')}
        action={
          <LoadingButton size="sm" pending={testing} onClick={() => void runTest()}>
            <FlaskConical className="size-3.5" />
            {t('patterns.runDryRun')}
          </LoadingButton>
        }
      >
        <div className="space-y-3">
          <div className="grid gap-3 sm:grid-cols-3">
            <FormField label={t('patterns.sandboxTarget')}>
              <Select value={testTarget} onValueChange={setTestTarget}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="__custom__">{t('patterns.sandboxPreset')}</SelectItem>
                  {targets.map((tg) => (
                    <SelectItem key={tg.target.id} value={tg.target.id}>
                      {tg.target.ref}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </FormField>
            {testTarget === '__custom__' && (
              <>
                <FormField label={t('patterns.sandboxEngine')}>
                  <Select value={testEngine} onValueChange={setTestEngine}>
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      {ENGINES.filter((e) => e !== '*').map((e) => (
                        <SelectItem key={e} value={e}>
                          {e}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </FormField>
                <FormField label={t('patterns.sandboxTier')}>
                  <Select value={testTier} onValueChange={(v) => setTestTier(v as typeof testTier)}>
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="yolo">yolo (dev)</SelectItem>
                      <SelectItem value="guarded">guarded (staging)</SelectItem>
                      <SelectItem value="strict">strict (prod)</SelectItem>
                    </SelectContent>
                  </Select>
                </FormField>
              </>
            )}
          </div>

          <FormField label={t('patterns.sandboxQuery')} htmlFor="sandbox-query">
            <Textarea
              id="sandbox-query"
              rows={3}
              className="font-mono text-xs"
              value={testQuery}
              onChange={(e) => setTestQuery(e.target.value)}
            />
          </FormField>

          <div className="flex flex-wrap items-center gap-4 text-xs">
            <label className="flex items-center gap-2">
              <Switch checked={simFullScan} onCheckedChange={setSimFullScan} />
              <span>{t('patterns.simFullScan')}</span>
            </label>
            <div className="flex items-center gap-2">
              <span className="text-muted-foreground">{t('patterns.simEstRows')}</span>
              <Input
                type="number"
                className="h-8 w-32 font-mono text-xs"
                placeholder="0"
                value={simRows}
                onChange={(e) => setSimRows(e.target.value)}
              />
            </div>
          </div>

          {testErr && <Notice tone="error">{testErr}</Notice>}

          {testResult && (
            <div className="space-y-3 rounded-md border border-border bg-muted/30 p-3 text-xs">
              <div className="flex flex-wrap items-center gap-2">
                <Badge
                  variant={testResult.evaluation.decision === 'deny' ? 'destructive' : 'outline'}
                  className={
                    testResult.evaluation.decision === 'require_approval'
                      ? 'border-amber-300 bg-amber-50 font-mono text-amber-900'
                      : 'font-mono'
                  }
                >
                  decision={testResult.evaluation.decision}
                </Badge>
                <Badge variant="outline" className="font-mono">
                  risk={testResult.classification.risk_level}
                </Badge>
                <Badge variant="outline" className="font-mono">
                  read_only={String(testResult.classification.is_read_only)}
                </Badge>
                {(testResult.classification.risk_flags ?? []).map((f) => (
                  <Badge key={f} variant="secondary" className="font-mono text-[11px]">
                    {f}
                  </Badge>
                ))}
              </div>

              {(testResult.matched_rules ?? []).length > 0 && (
                <div className="space-y-2">
                  {testResult.matched_rules!.map((mr) => (
                    <div key={`${mr.rule_id}-${mr.rule_name}`} className="rounded border border-amber-300 bg-amber-50/70 p-2.5">
                      <div className="flex flex-wrap items-center gap-2">
                        <ShieldAlert className="size-3.5 text-amber-700" />
                        <span className="font-semibold text-amber-950">{mr.confirm_title || mr.rule_name}</span>
                        {actionBadge(mr.action)}
                        <Badge variant="outline" className="font-mono text-[10px]">
                          {mr.scope}
                        </Badge>
                        {mr.matched_fragment && (
                          <code className="rounded bg-white/80 px-1.5 py-0.5 font-mono text-[11px] text-amber-950">
                            {mr.matched_fragment}
                          </code>
                        )}
                      </div>
                      {mr.confirm_message && <p className="mt-1 text-amber-900">{mr.confirm_message}</p>}
                    </div>
                  ))}
                </div>
              )}

              <div className="flex flex-wrap gap-2 text-[11px] text-muted-foreground">
                {(testResult.extracted.tables ?? []).map((tbl) => (
                  <Badge key={`t-${tbl}`} variant="outline" className="font-mono">
                    tbl:{tbl}
                  </Badge>
                ))}
                {(testResult.extracted.functions ?? []).map((fn) => (
                  <Badge key={`f-${fn}`} variant="outline" className="font-mono">
                    fn:{fn}
                  </Badge>
                ))}
                {(testResult.extracted.pragmas ?? []).map((pr) => (
                  <Badge key={`p-${pr}`} variant="outline" className="font-mono">
                    pragma:{pr}
                  </Badge>
                ))}
                {(testResult.extracted.mongo_operators ?? []).map((op) => (
                  <Badge key={`m-${op}`} variant="outline" className="font-mono">
                    op:{op}
                  </Badge>
                ))}
              </div>
            </div>
          )}
        </div>
      </Panel>

      <FormDialog
        open={dialogOpen}
        onOpenChange={setDialogOpen}
        title={ruleForm.id ? t('patterns.dialog.editTitle') : t('patterns.dialog.newTitle')}
        submitLabel={t('common.save')}
        cancelLabel={t('common.cancel')}
        maxWidthClassName="max-w-2xl"
        error={ruleErr}
        pending={savingRule}
        onSubmit={saveRule}
      >
        <div className="grid grid-cols-2 gap-3">
          <FormField label={t('patterns.field.ruleName')}>
            <Input
              value={ruleForm.name}
              onChange={(e) => setRuleForm((p) => ({ ...p, name: e.target.value }))}
              placeholder="e.g. confirm-orders-scan"
            />
          </FormField>
          <FormField label={t('patterns.field.action')}>
            <Select
              value={ruleForm.action}
              onValueChange={(v) => setRuleForm((p) => ({ ...p, action: v as PatternAction }))}
            >
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="require_approval">require_approval</SelectItem>
                <SelectItem value="elevate_high_cost">elevate_high_cost</SelectItem>
                <SelectItem value="deny">deny</SelectItem>
              </SelectContent>
            </Select>
          </FormField>
        </div>

        <div className="grid grid-cols-3 gap-3">
          <FormField label={t('patterns.field.scopeType')}>
            <Select
              value={ruleForm.scope_type}
              onValueChange={(v) => {
                const st = v as RiskPatternRule['scope_type']
                setRuleForm((p) => ({
                  ...p,
                  scope_type: st,
                  scope_id: st === 'global' ? 'global' : '',
                }))
              }}
            >
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="global">global</SelectItem>
                <SelectItem value="env">env</SelectItem>
                <SelectItem value="system">system</SelectItem>
                <SelectItem value="target">target</SelectItem>
              </SelectContent>
            </Select>
          </FormField>
          <FormField label={t('patterns.field.scopeTarget')}>
            {ruleForm.scope_type === 'global' ? (
              <Input value="global" disabled />
            ) : (
              <Select
                value={ruleForm.scope_id || '__pick__'}
                onValueChange={(v) => setRuleForm((p) => ({ ...p, scope_id: v === '__pick__' ? '' : v }))}
              >
                <SelectTrigger>
                  <SelectValue placeholder={t('policies.field.selectScope')} />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="__pick__" disabled>
                    {t('policies.field.selectScope')}
                  </SelectItem>
                  {ruleForm.scope_type === 'env' &&
                    envs.map((e) => (
                      <SelectItem key={e.code} value={e.code}>
                        {e.code}
                      </SelectItem>
                    ))}
                  {ruleForm.scope_type === 'system' &&
                    systems.map((s) => (
                      <SelectItem key={s.id} value={s.id}>
                        {s.slug}
                      </SelectItem>
                    ))}
                  {ruleForm.scope_type === 'target' &&
                    targets.map((tg) => (
                      <SelectItem key={tg.target.id} value={tg.target.id}>
                        {tg.target.ref}
                      </SelectItem>
                    ))}
                </SelectContent>
              </Select>
            )}
          </FormField>
          <FormField label={t('patterns.field.priority')}>
            <Input
              type="number"
              value={ruleForm.priority}
              onChange={(e) => setRuleForm((p) => ({ ...p, priority: Number(e.target.value) || 0 }))}
            />
          </FormField>
        </div>

        <FormField label={t('patterns.field.engines')}>
          <div className="flex flex-wrap gap-1.5">
            {ENGINES.map((eng) => {
              const active = (ruleForm.engines ?? ['*']).includes(eng)
              return (
                <button
                  key={eng}
                  type="button"
                  onClick={() => toggleEngineChip(eng)}
                  className={`cursor-pointer rounded-md border px-2.5 py-1 font-mono text-xs ${
                    active
                      ? 'border-primary bg-primary text-primary-foreground'
                      : 'border-border bg-card text-muted-foreground hover:bg-muted'
                  }`}
                >
                  {eng === '*' ? t('patterns.field.allEngines') : eng}
                </button>
              )
            })}
          </div>
        </FormField>

        <div className="grid grid-cols-2 gap-3">
          <FormField label={t('patterns.field.confirmTitle')}>
            <Input
              value={ruleForm.confirm_title ?? ''}
              onChange={(e) => setRuleForm((p) => ({ ...p, confirm_title: e.target.value }))}
              placeholder={t('patterns.field.confirmTitlePh')}
            />
          </FormField>
          <FormField label={t('patterns.field.providerOverride')}>
            <Input
              value={ruleForm.approval_provider ?? ''}
              onChange={(e) => setRuleForm((p) => ({ ...p, approval_provider: e.target.value }))}
              placeholder={t('patterns.field.providerOverridePh')}
            />
          </FormField>
        </div>

        <FormField label={t('patterns.field.confirmMessage')}>
          <Input
            value={ruleForm.confirm_message ?? ''}
            onChange={(e) => setRuleForm((p) => ({ ...p, confirm_message: e.target.value }))}
            placeholder={t('patterns.field.confirmMessagePh')}
          />
        </FormField>

        <div className="space-y-2 rounded-md border border-border p-3">
          <div className="flex items-center justify-between gap-2">
            <div className="flex items-center gap-2">
              <span className="text-xs font-semibold">{t('patterns.conditionBuilder')}</span>
              {condMode === 'visual' && (
                <div className="w-36">
                  <Select
                    value={combMode}
                    onValueChange={(v) => {
                      const next = v as typeof combMode
                      setCombMode(next)
                      if (next === 'single' && leafList.length > 1) {
                        setLeafList([leafList[0]])
                      }
                    }}
                  >
                    <SelectTrigger size="sm">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="single">{t('patterns.comb.single')}</SelectItem>
                      <SelectItem value="all">{t('patterns.comb.all')}</SelectItem>
                      <SelectItem value="any">{t('patterns.comb.any')}</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
              )}
            </div>
            <div className="flex gap-1">
              <Button
                type="button"
                size="sm"
                variant={condMode === 'visual' ? 'default' : 'outline'}
                onClick={() => setCondMode('visual')}
              >
                {t('patterns.mode.visual')}
              </Button>
              <Button
                type="button"
                size="sm"
                variant={condMode === 'json' ? 'default' : 'outline'}
                onClick={() => {
                  try {
                    const built = combMode === 'all' ? { all: leafList } : combMode === 'any' ? { any: leafList } : leafList[0]
                    setJsonText(JSON.stringify(built, null, 2))
                  } catch {
                    // keep previous
                  }
                  setCondMode('json')
                }}
              >
                {t('patterns.mode.json')}
              </Button>
            </div>
          </div>

          {condMode === 'json' ? (
            <Textarea
              rows={6}
              className="font-mono text-xs"
              value={jsonText}
              onChange={(e) => setJsonText(e.target.value)}
            />
          ) : (
            <div className="space-y-2">
              {leafList.map((leaf, idx) => {
                const mType = (leaf.type || 'table_ref') as PatternMatcherType
                return (
                  <div key={idx} className="grid grid-cols-[170px_1fr_auto] items-start gap-2 rounded border border-border bg-muted/20 p-2">
                    <Select
                      value={mType}
                      onValueChange={(v) => {
                        const next = defaultCondition(v as PatternMatcherType)
                        setLeafList((prev) => prev.map((x, i) => (i === idx ? next : x)))
                      }}
                    >
                      <SelectTrigger size="sm">
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        {MATCHER_TYPES.map((k) => (
                          <SelectItem key={k} value={k}>
                            {t(matcherLabelKey(k))}
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>

                    <div className="space-y-1.5">
                      {(mType === 'function_call' || mType === 'table_ref' || mType === 'pragma_name' || mType === 'risk_flag') && (
                        <Input
                          className="h-8 font-mono text-xs"
                          value={(leaf.values ?? []).join(', ')}
                          onChange={(e) => {
                            const vals = e.target.value
                              .split(',')
                              .map((s) => s.trim())
                              .filter(Boolean)
                            setLeafList((prev) => prev.map((x, i) => (i === idx ? { ...x, type: mType, values: vals } : x)))
                          }}
                          placeholder={t('patterns.ph.csvValues')}
                        />
                      )}
                      {mType === 'regex' && (
                        <div className="grid grid-cols-[1fr_140px] gap-1.5">
                          <Input
                            className="h-8 font-mono text-xs"
                            value={leaf.pattern ?? ''}
                            onChange={(e) =>
                              setLeafList((prev) => prev.map((x, i) => (i === idx ? { ...x, pattern: e.target.value } : x)))
                            }
                            placeholder={t('patterns.ph.re2')}
                          />
                          <Select
                            value={leaf.target || 'normalized_no_literals'}
                            onValueChange={(v) =>
                              setLeafList((prev) => prev.map((x, i) => (i === idx ? { ...x, target: v } : x)))
                            }
                          >
                            <SelectTrigger size="sm">
                              <SelectValue />
                            </SelectTrigger>
                            <SelectContent>
                              <SelectItem value="normalized_no_literals">{t('patterns.regex.noLiterals')}</SelectItem>
                              <SelectItem value="normalized">{t('patterns.regex.noComments')}</SelectItem>
                              <SelectItem value="raw">{t('patterns.regex.raw')}</SelectItem>
                            </SelectContent>
                          </Select>
                        </div>
                      )}
                      {mType === 'command_arg' && (
                        <div className="grid grid-cols-2 gap-1.5">
                          <Input
                            className="h-8 font-mono text-xs"
                            value={leaf.command ?? ''}
                            onChange={(e) =>
                              setLeafList((prev) => prev.map((x, i) => (i === idx ? { ...x, command: e.target.value } : x)))
                            }
                            placeholder={t('patterns.ph.cmd')}
                          />
                          <Input
                            className="h-8 font-mono text-xs"
                            value={leaf.subcommand ?? ''}
                            onChange={(e) =>
                              setLeafList((prev) => prev.map((x, i) => (i === idx ? { ...x, subcommand: e.target.value } : x)))
                            }
                            placeholder={t('patterns.ph.subcmd')}
                          />
                          <Input
                            className="h-8 font-mono text-xs"
                            value={leaf.arg_keyword ?? ''}
                            onChange={(e) =>
                              setLeafList((prev) => prev.map((x, i) => (i === idx ? { ...x, arg_keyword: e.target.value } : x)))
                            }
                            placeholder={t('patterns.ph.argKw')}
                          />
                          <Input
                            className="h-8 font-mono text-xs"
                            type="number"
                            value={leaf.arg_greater_than ?? ''}
                            onChange={(e) =>
                              setLeafList((prev) =>
                                prev.map((x, i) =>
                                  i === idx ? { ...x, arg_greater_than: e.target.value ? Number(e.target.value) : null } : x,
                                ),
                              )
                            }
                            placeholder={t('patterns.ph.argGt')}
                          />
                        </div>
                      )}
                      {mType === 'json_path' && (
                        <div className="grid grid-cols-2 gap-1.5">
                          <Input
                            className="h-8 font-mono text-xs"
                            value={leaf.json_path ?? ''}
                            onChange={(e) =>
                              setLeafList((prev) => prev.map((x, i) => (i === idx ? { ...x, json_path: e.target.value } : x)))
                            }
                            placeholder={t('patterns.ph.jsonPath')}
                          />
                          <Input
                            className="h-8 font-mono text-xs"
                            value={leaf.equals ?? ''}
                            onChange={(e) =>
                              setLeafList((prev) => prev.map((x, i) => (i === idx ? { ...x, equals: e.target.value } : x)))
                            }
                            placeholder={t('patterns.ph.equalsOpt')}
                          />
                        </div>
                      )}
                      {mType === 'preflight_metric' && (
                        <div className="grid grid-cols-2 gap-1.5">
                          <Select
                            value={leaf.metric || 'full_scan'}
                            onValueChange={(v) =>
                              setLeafList((prev) => prev.map((x, i) => (i === idx ? { ...x, metric: v } : x)))
                            }
                          >
                            <SelectTrigger size="sm">
                              <SelectValue />
                            </SelectTrigger>
                            <SelectContent>
                              <SelectItem value="full_scan">full_scan</SelectItem>
                              <SelectItem value="estimated_rows">estimated_rows</SelectItem>
                              <SelectItem value="plan_contains">plan_contains</SelectItem>
                            </SelectContent>
                          </Select>
                          {(leaf.metric || 'full_scan') === 'estimated_rows' && (
                            <Input
                              className="h-8 font-mono text-xs"
                              type="number"
                              value={leaf.threshold ?? 10000}
                              onChange={(e) =>
                                setLeafList((prev) =>
                                  prev.map((x, i) => (i === idx ? { ...x, threshold: Number(e.target.value) || 0 } : x)),
                                )
                              }
                              placeholder={t('patterns.ph.thresholdRows')}
                            />
                          )}
                          {leaf.metric === 'plan_contains' && (
                            <Input
                              className="h-8 font-mono text-xs"
                              value={leaf.pattern ?? ''}
                              onChange={(e) =>
                                setLeafList((prev) => prev.map((x, i) => (i === idx ? { ...x, pattern: e.target.value } : x)))
                              }
                              placeholder={t('patterns.ph.planRegex')}
                            />
                          )}
                        </div>
                      )}
                    </div>

                    {combMode !== 'single' && leafList.length > 1 && (
                      <Button
                        type="button"
                        size="icon"
                        variant="ghost"
                        aria-label={t('patterns.removeConditionAria')}
                        onClick={() => setLeafList((prev) => prev.filter((_, i) => i !== idx))}
                      >
                        <Trash2 className="size-3.5" />
                      </Button>
                    )}
                  </div>
                )
              })}
              {combMode !== 'single' && (
                <Button
                  type="button"
                  size="sm"
                  variant="outline"
                  onClick={() => setLeafList((prev) => [...prev, defaultCondition('table_ref')])}
                >
                  <Plus className="size-3.5" />
                  {t('patterns.addCondition')}
                </Button>
              )}
            </div>
          )}
        </div>
      </FormDialog>
    </div>
  )
}
