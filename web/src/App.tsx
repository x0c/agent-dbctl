import { AdminShell, type AdminNavItem, Badge, Button, Toaster, toast } from '@x0c/ui'
import { Cpu, Database, Languages, ScrollText, ShieldAlert, ShieldCheck } from 'lucide-react'
import { useEffect, useState } from 'react'
import { api, type BootstrapPayload, type DisplayCatalog } from './api'
import { ApprovalsTab } from './components/ApprovalsTab'
import { AuditTab } from './components/AuditTab'
import { CatalogTab, type CatalogSubTab } from './components/CatalogTab'
import { DriversTab } from './components/DriversTab'
import { PoliciesTab, type PoliciesSubTab } from './components/PoliciesTab'
import { loadCachedCatalog, saveCachedCatalog } from './lib/catalog'
import { useI18n } from './lib/i18n'

type Tab = 'approvals' | 'catalog' | 'policies' | 'audit' | 'drivers'

const CATALOG_SUBTABS = new Set<CatalogSubTab>(['targets', 'systems', 'instances', 'networks', 'credentials'])

function parseDeepLink(): {
  tab: Tab
  approvalId: string | null
  approvalToken: string | null
  catalogSubTab: CatalogSubTab
  policiesSubTab: PoliciesSubTab
  credentialId: string | null
} {
  const path = window.location.pathname
  const sp = new URLSearchParams(window.location.search)
  const approvalMatch = path.match(/^\/approvals\/([^/]+)$/)
  if (approvalMatch) {
    return {
      tab: 'approvals',
      approvalId: decodeURIComponent(approvalMatch[1]),
      approvalToken: sp.get('token'),
      catalogSubTab: 'targets',
      policiesSubTab: 'guardrails',
      credentialId: null,
    }
  }
  if (path === '/targets' || path.startsWith('/targets/')) {
    return {
      tab: 'catalog',
      approvalId: null,
      approvalToken: null,
      catalogSubTab: 'targets',
      policiesSubTab: 'guardrails',
      credentialId: null,
    }
  }
  if (path === '/catalog' || path.startsWith('/catalog/')) {
    const rawSub = sp.get('subtab')
    if (rawSub === 'environments') {
      return {
        tab: 'policies',
        approvalId: null,
        approvalToken: null,
        catalogSubTab: 'targets',
        policiesSubTab: 'environments',
        credentialId: null,
      }
    }
    const credential = sp.get('credential')
    const catalogSubTab: CatalogSubTab =
      rawSub && CATALOG_SUBTABS.has(rawSub as CatalogSubTab)
        ? (rawSub as CatalogSubTab)
        : credential
          ? 'credentials'
          : 'targets'
    return {
      tab: 'catalog',
      approvalId: null,
      approvalToken: null,
      catalogSubTab,
      policiesSubTab: 'guardrails',
      credentialId: credential,
    }
  }
  if (path === '/policies' || path.startsWith('/policies/')) {
    const rawSub = sp.get('subtab')
    const policiesSubTab: PoliciesSubTab =
      rawSub === 'patterns' || rawSub === 'environments' ? rawSub : 'guardrails'
    return { tab: 'policies', approvalId: null, approvalToken: null, catalogSubTab: 'targets', policiesSubTab, credentialId: null }
  }
  if (path === '/audit' || path.startsWith('/audit/')) {
    return { tab: 'audit', approvalId: null, approvalToken: null, catalogSubTab: 'targets', policiesSubTab: 'guardrails', credentialId: null }
  }
  if (path === '/drivers' || path.startsWith('/drivers/')) {
    return { tab: 'drivers', approvalId: null, approvalToken: null, catalogSubTab: 'targets', policiesSubTab: 'guardrails', credentialId: null }
  }
  return { tab: 'approvals', approvalId: null, approvalToken: null, catalogSubTab: 'targets', policiesSubTab: 'guardrails', credentialId: null }
}

export function App() {
  const { locale, setLocale, t } = useI18n()
  const initialLink = parseDeepLink()
  const [tab, setTab] = useState<Tab>(initialLink.tab)
  const [catalog, setCatalog] = useState<DisplayCatalog>(() => loadCachedCatalog())
  const [bootstrap, setBootstrap] = useState<BootstrapPayload | null>(null)
  const [pendingCount, setPendingCount] = useState<number>(0)

  const refreshBootstrap = async () => {
    try {
      const data = await api.bootstrap()
      setBootstrap(data)
      setPendingCount(data.pending_approval_count ?? 0)
      if (data.display_catalog) {
        setCatalog(saveCachedCatalog(data.display_catalog))
      }
    } catch {
      // Keep last-known-good offline cached display catalog.
    }
  }

  useEffect(() => {
    void refreshBootstrap()
  }, [])

  const navItems: Array<AdminNavItem & { id: Tab }> = [
    {
      id: 'approvals',
      label: pendingCount > 0 ? t('nav.approvalsCount', { count: pendingCount }) : t('nav.approvals'),
      icon: ShieldAlert,
      section: t('nav.section.gate'),
    },
    { id: 'catalog', label: t('nav.catalog'), icon: Database, section: t('nav.section.assets') },
    { id: 'policies', label: t('nav.policies'), icon: ShieldCheck, section: t('nav.section.assets') },
    { id: 'audit', label: t('nav.audit'), icon: ScrollText, section: t('nav.section.observability') },
    { id: 'drivers', label: t('nav.drivers'), icon: Cpu, section: t('nav.section.observability') },
  ]

  const handleToggleFreeze = async (next: boolean) => {
    if (!bootstrap?.global_security) return
    try {
      const updated = await api.saveGlobalSecurity({
        ...bootstrap.global_security,
        prod_read_only_freeze: next,
      })
      setBootstrap((prev) => (prev ? { ...prev, global_security: updated } : prev))
      toast.success(next ? t('freeze.enabledToast') : t('freeze.disabledToast'))
    } catch (e) {
      toast.error(e instanceof Error ? e.message : t('freeze.toggleFailed'))
    }
  }

  return (
    <>
      <AdminShell
        product="agent-dbctl"
        nav={navItems}
        activeId={tab}
        onSelectNav={(id) => setTab(id as Tab)}
        onBrandClick={() => setTab('approvals')}
        navAriaLabel={t('nav.ariaLabel')}
        enableCommandPalette
        topbarExtra={
          <div className="flex items-center gap-2">
            {bootstrap && (
              <Badge variant="outline" className="font-mono text-[11px]">
                {bootstrap.identity.session} · {bootstrap.identity.version}
              </Badge>
            )}
            <Button
              variant="outline"
              size="sm"
              className="h-7 px-2 text-xs"
              title={t('common.langToggleTitle')}
              aria-label={t('common.langToggleTitle')}
              onClick={() => setLocale(locale === 'zh' ? 'en' : 'zh')}
            >
              <Languages className="size-3.5" />
              {t('common.langToggle')}
            </Button>
          </div>
        }
      >
        {tab === 'approvals' && (
          <ApprovalsTab
            catalog={catalog}
            globalSecurity={bootstrap?.global_security ?? null}
            deepLinkId={initialLink.approvalId}
            deepLinkToken={initialLink.approvalToken}
            onToggleFreeze={handleToggleFreeze}
            onCountChange={setPendingCount}
          />
        )}
        {tab === 'catalog' && (
          <CatalogTab
            catalog={catalog}
            onRefreshBootstrap={refreshBootstrap}
            initialSubTab={initialLink.catalogSubTab}
            deepLinkCredential={initialLink.credentialId}
          />
        )}
        {tab === 'policies' && (
          <PoliciesTab
            catalog={catalog}
            initialSubTab={initialLink.policiesSubTab}
            onRefreshBootstrap={refreshBootstrap}
            onSavedGlobal={(cfg) =>
              setBootstrap((prev) => (prev ? { ...prev, global_security: cfg } : prev))
            }
          />
        )}
        {tab === 'audit' && <AuditTab catalog={catalog} />}
        {tab === 'drivers' && <DriversTab />}
      </AdminShell>
      <Toaster />
    </>
  )
}

export default App
