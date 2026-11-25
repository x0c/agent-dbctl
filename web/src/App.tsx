import {
  type AdminNavItem,
  AppFrame,
  AppTopbar,
  Button,
  type CommandAction,
  CommandPalette,
  MobileTabBar,
  SideNav,
  SideNavItem,
  SideNavSection,
  Toaster,
  toast,
} from '@x0c/ui'
import { Cpu, Database, Languages, ScrollText, Search, ShieldAlert, ShieldCheck } from 'lucide-react'
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
  const [cmdOpen, setCmdOpen] = useState(false)

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

  const sections: Array<{ title?: string; items: Array<AdminNavItem & { id: Tab }> }> = []
  for (const item of navItems) {
    const last = sections[sections.length - 1]
    if (!last || last.title !== item.section) {
      sections.push({ title: item.section, items: [item] })
    } else {
      last.items.push(item)
    }
  }

  const commandItems: CommandAction[] = [
    ...navItems.map((item) => ({
      id: `nav:${item.id}`,
      label: item.label,
      group: item.section,
      icon: item.icon,
      onSelect: () => setTab(item.id),
    })),
    {
      id: 'pref:lang',
      label: t('common.langToggleTitle'),
      group: t('command.group.preferences'),
      icon: Languages,
      onSelect: () => setLocale(locale === 'zh' ? 'en' : 'zh'),
    },
  ]

  const metaLine = bootstrap
    ? bootstrap.identity.session && bootstrap.identity.session !== 'default'
      ? `${bootstrap.identity.session} · ${bootstrap.identity.version}`
      : bootstrap.identity.version
    : null

  return (
    <div className="min-h-svh bg-background text-foreground">
      <AppTopbar product="agent-dbctl" onBrandClick={() => setTab('approvals')}>
        <div className="flex items-center gap-2">
          <Button
            type="button"
            variant="outline"
            size="sm"
            onClick={() => setCmdOpen(true)}
            className="hidden h-8 gap-2 px-2.5 text-xs text-muted-foreground sm:inline-flex"
            aria-label={t('command.ariaLabel')}
          >
            <Search className="size-3.5" />
            <span>{t('command.trigger')}</span>
            <kbd className="rounded border border-border bg-muted px-1 py-0.5 font-mono text-[10px] leading-none">
              ⌘K
            </kbd>
          </Button>
          <Button
            type="button"
            variant="ghost"
            size="sm"
            className="h-8 gap-1.5 px-2.5 text-xs font-medium text-muted-foreground hover:text-foreground"
            title={t('common.langToggleTitle')}
            aria-label={t('common.langToggleTitle')}
            onClick={() => setLocale(locale === 'zh' ? 'en' : 'zh')}
          >
            <Languages className="size-3.5" />
            <span>{t('common.langToggle')}</span>
          </Button>
        </div>
      </AppTopbar>

      <CommandPalette
        open={cmdOpen}
        onOpenChange={setCmdOpen}
        items={commandItems}
        title={t('command.title')}
        placeholder={t('command.placeholder')}
        emptyLabel={t('command.empty')}
      />

      <MobileTabBar
        items={navItems}
        activeId={tab}
        onSelect={(id) => setTab(id as Tab)}
        label={t('nav.ariaLabel')}
      />

      <AppFrame
        sidebar={
          <div className="flex flex-col">
            <SideNav label={t('nav.ariaLabel')}>
              {sections.map((sec, idx) => (
                <div key={sec.title ?? idx}>
                  {sec.title && <SideNavSection>{sec.title}</SideNavSection>}
                  <div className="flex flex-col gap-0.5">
                    {sec.items.map((item) => (
                      <SideNavItem
                        key={item.id}
                        active={item.id === tab}
                        icon={item.icon}
                        onClick={() => setTab(item.id)}
                      >
                        {item.label}
                      </SideNavItem>
                    ))}
                  </div>
                </div>
              ))}
            </SideNav>
            {metaLine && (
              <div className="px-2.5 pt-6 font-mono text-[11px] text-muted-foreground/60">
                {metaLine}
              </div>
            )}
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
      </AppFrame>
      <Toaster />
    </div>
  )
}

export default App
