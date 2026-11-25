import {
  type AdminNavItem,
  AppFrame,
  AppTopbar,
  Button,
  type CommandAction,
  CommandPalette,
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
  MobileTabBar,
  SideNav,
  SideNavItem,
  SideNavSection,
  Toaster,
  UserAvatar,
  toast,
} from '@x0c/ui'
import { Cpu, Database, KeyRound, Languages, LogOut, ScrollText, Search, ShieldAlert, ShieldCheck } from 'lucide-react'
import { useEffect, useState } from 'react'
import {
  AuthRequiredError,
  api,
  closeEventStream,
  setOnAuthRequired,
  type BootstrapPayload,
  type DisplayCatalog,
  type PublicAuthInfo,
} from './api'
import { AccessTab } from './components/AccessTab'
import { ApprovalsTab } from './components/ApprovalsTab'
import { AuditTab } from './components/AuditTab'
import { CatalogTab, type CatalogSubTab } from './components/CatalogTab'
import { DeviceAuthView } from './components/DeviceAuthView'
import { DriversTab } from './components/DriversTab'
import { LoginView } from './components/LoginView'
import { PoliciesTab, type PoliciesSubTab } from './components/PoliciesTab'
import { EMPTY_CATALOG, clearCachedCatalog, loadCachedCatalog, saveCachedCatalog } from './lib/catalog'
import { useI18n } from './lib/i18n'

type Tab = 'approvals' | 'catalog' | 'policies' | 'audit' | 'drivers' | 'access'

const CATALOG_SUBTABS = new Set<CatalogSubTab>(['targets', 'systems', 'instances', 'networks', 'credentials'])

function parseDeepLink(): {
  tab: Tab
  approvalId: string | null
  approvalToken: string | null
  catalogSubTab: CatalogSubTab
  policiesSubTab: PoliciesSubTab
  credentialId: string | null
  deviceAuth: boolean
  deviceUserCode: string | null
} {
  const path = window.location.pathname
  const sp = new URLSearchParams(window.location.search)
  if (path === '/device' || path === '/device/') {
    return {
      tab: 'approvals',
      approvalId: null,
      approvalToken: null,
      catalogSubTab: 'targets',
      policiesSubTab: 'guardrails',
      credentialId: null,
      deviceAuth: true,
      deviceUserCode: sp.get('user_code'),
    }
  }
  const approvalMatch = path.match(/^\/approvals\/([^/]+)$/)
  if (approvalMatch) {
    return {
      tab: 'approvals',
      approvalId: decodeURIComponent(approvalMatch[1]),
      approvalToken: sp.get('token'),
      catalogSubTab: 'targets',
      policiesSubTab: 'guardrails',
      credentialId: null,
      deviceAuth: false,
      deviceUserCode: null,
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
      deviceAuth: false,
      deviceUserCode: null,
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
        deviceAuth: false,
        deviceUserCode: null,
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
      deviceAuth: false,
      deviceUserCode: null,
    }
  }
  if (path === '/policies' || path.startsWith('/policies/')) {
    const rawSub = sp.get('subtab')
    const policiesSubTab: PoliciesSubTab =
      rawSub === 'patterns' || rawSub === 'environments' ? rawSub : 'guardrails'
    return { tab: 'policies', approvalId: null, approvalToken: null, catalogSubTab: 'targets', policiesSubTab, credentialId: null, deviceAuth: false, deviceUserCode: null }
  }
  if (path === '/audit' || path.startsWith('/audit/')) {
    return { tab: 'audit', approvalId: null, approvalToken: null, catalogSubTab: 'targets', policiesSubTab: 'guardrails', credentialId: null, deviceAuth: false, deviceUserCode: null }
  }
  if (path === '/drivers' || path.startsWith('/drivers/')) {
    return { tab: 'drivers', approvalId: null, approvalToken: null, catalogSubTab: 'targets', policiesSubTab: 'guardrails', credentialId: null, deviceAuth: false, deviceUserCode: null }
  }
  if (path === '/access' || path.startsWith('/access/')) {
    return { tab: 'access', approvalId: null, approvalToken: null, catalogSubTab: 'targets', policiesSubTab: 'guardrails', credentialId: null, deviceAuth: false, deviceUserCode: null }
  }
  return { tab: 'approvals', approvalId: null, approvalToken: null, catalogSubTab: 'targets', policiesSubTab: 'guardrails', credentialId: null, deviceAuth: false, deviceUserCode: null }
}

export function App() {
  const { locale, setLocale, t } = useI18n()
  const initialLink = parseDeepLink()
  const [tab, setTab] = useState<Tab>(initialLink.tab)
  const [catalog, setCatalog] = useState<DisplayCatalog>(() => loadCachedCatalog())
  const [bootstrap, setBootstrap] = useState<BootstrapPayload | null>(null)
  const [authState, setAuthState] = useState<'checking' | 'authenticated' | 'unauthenticated'>(() =>
    loadCachedCatalog().environments.length > 0 ? 'authenticated' : 'checking',
  )
  const [authInfo, setAuthInfo] = useState<PublicAuthInfo | null>(null)
  const [pendingCount, setPendingCount] = useState<number>(0)
  const [cmdOpen, setCmdOpen] = useState(false)
  const [deviceViewOpen, setDeviceViewOpen] = useState(initialLink.deviceAuth)

  const handleUnauthenticated = (info?: PublicAuthInfo) => {
    clearCachedCatalog()
    setCatalog(EMPTY_CATALOG)
    setBootstrap(null)
    if (info) {
      setAuthInfo(info)
    }
    setAuthState('unauthenticated')
  }

  const refreshBootstrap = async () => {
    try {
      const data = await api.bootstrap()
      try {
        sessionStorage.removeItem('dbctl_manual_logout')
        sessionStorage.removeItem('dbctl_oidc_auto_ts')
      } catch {
        // Ignore restricted storage environments.
      }
      setAuthState('authenticated')
      setAuthInfo(null)
      setBootstrap(data)
      setPendingCount(data.pending_approval_count ?? 0)
      if (data.display_catalog) {
        const ns = data.mode === 'server' ? 'server' : 'local'
        setCatalog(saveCachedCatalog(data.display_catalog, ns))
      }
    } catch (e) {
      if (e instanceof AuthRequiredError) {
        handleUnauthenticated(e.authInfo)
        if (!e.authInfo) {
          void api.getAuthConfig().then(setAuthInfo).catch(() => undefined)
        }
        return
      }
      // Keep last-known-good offline cached display catalog.
    }
  }

  useEffect(() => {
    setOnAuthRequired((info) => handleUnauthenticated(info))
    void refreshBootstrap()
    return () => {
      setOnAuthRequired(null)
      closeEventStream()
    }
  }, [])

  const handleLogout = async () => {
    try {
      sessionStorage.setItem('dbctl_manual_logout', '1')
      sessionStorage.removeItem('dbctl_oidc_auto_ts')
    } catch {
      // Ignore restricted storage environments.
    }
    await api.logout()
    clearCachedCatalog()
    setCatalog(EMPTY_CATALOG)
    setBootstrap(null)
    setAuthState('unauthenticated')
    try {
      setAuthInfo(await api.getAuthConfig())
    } catch {
      // Ignore auth config fetch failures on logout.
    }
  }

  if (authState === 'checking') {
    return <div className="min-h-svh bg-background" />
  }

  if (authState === 'unauthenticated') {
    return (
      <>
        <LoginView authInfo={authInfo} onSuccess={refreshBootstrap} />
        <Toaster />
      </>
    )
  }

  if (deviceViewOpen) {
    return (
      <>
        <DeviceAuthView
          initialUserCode={initialLink.deviceUserCode}
          userEmail={bootstrap?.current_user?.email}
          onDone={() => {
            window.history.replaceState({}, '', '/')
            setDeviceViewOpen(false)
          }}
        />
        <Toaster />
      </>
    )
  }

  const isServerMode = bootstrap?.mode === 'server'
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
    ...(isServerMode
      ? [
          {
            id: 'access' as Tab,
            label: t('nav.access'),
            icon: KeyRound,
            section: t('nav.section.observability'),
          },
        ]
      : []),
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
          {isServerMode && bootstrap?.current_user ? (
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <button
                  type="button"
                  aria-label={bootstrap.current_user.email || bootstrap.current_user.display_name}
                  className="ml-1 cursor-pointer rounded-full transition-opacity hover:opacity-85 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-foreground"
                >
                  <UserAvatar
                    name={bootstrap.current_user.display_name}
                    email={bootstrap.current_user.email}
                    size="sm"
                  />
                </button>
              </DropdownMenuTrigger>
              <DropdownMenuContent align="end" className="w-60">
                <DropdownMenuLabel className="flex items-center gap-3 py-2">
                  <UserAvatar
                    name={bootstrap.current_user.display_name}
                    email={bootstrap.current_user.email}
                  />
                  <div className="min-w-0">
                    <div className="truncate text-sm font-medium">
                      {bootstrap.current_user.display_name || bootstrap.current_user.email}
                    </div>
                    {bootstrap.current_user.display_name && bootstrap.current_user.email && (
                      <div className="truncate text-xs font-normal text-muted-foreground">
                        {bootstrap.current_user.email}
                      </div>
                    )}
                  </div>
                </DropdownMenuLabel>
                <DropdownMenuSeparator />
                <DropdownMenuItem onSelect={() => setLocale(locale === 'zh' ? 'en' : 'zh')}>
                  <Languages className="size-4" />
                  <span>{locale === 'zh' ? 'English' : '中文'}</span>
                </DropdownMenuItem>
                <DropdownMenuSeparator />
                <DropdownMenuItem onSelect={() => void handleLogout()}>
                  <LogOut className="size-4" />
                  <span>{t('nav.signOut')}</span>
                </DropdownMenuItem>
              </DropdownMenuContent>
            </DropdownMenu>
          ) : (
            <Button
              type="button"
              variant="ghost"
              size="sm"
              className="h-8 px-2 text-xs text-muted-foreground hover:text-foreground"
              title={t('common.langToggleTitle')}
              aria-label={t('common.langToggleTitle')}
              onClick={() => setLocale(locale === 'zh' ? 'en' : 'zh')}
            >
              <Languages className="size-4" />
            </Button>
          )}
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
        {!bootstrap ? (
          <div className="space-y-3" aria-busy="true">
            <div className="h-7 w-44 rounded-md bg-muted/60" />
            <div className="h-28 rounded-xl border border-border/60 bg-card/50" />
          </div>
        ) : (
          <>
            {tab === 'approvals' && (
              <ApprovalsTab
                catalog={catalog}
                globalSecurity={bootstrap.global_security ?? null}
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
            {tab === 'access' && isServerMode && bootstrap.current_user && (
              <AccessTab currentUser={bootstrap.current_user} />
            )}
          </>
        )}
      </AppFrame>
      <Toaster />
    </div>
  )
}

export default App
