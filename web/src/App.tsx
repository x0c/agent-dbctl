import { AdminShell, type AdminNavItem, Badge, Toaster, toast } from './ui'
import { Cpu, Database, ScrollText, ShieldCheck, ShieldAlert } from 'lucide-react'
import { useEffect, useState } from 'react'
import { api, type BootstrapPayload, type DisplayCatalog } from './api'
import { ApprovalsTab } from './components/ApprovalsTab'
import { AuditTab } from './components/AuditTab'
import { CatalogTab } from './components/CatalogTab'
import { DriversTab } from './components/DriversTab'
import { PoliciesTab } from './components/PoliciesTab'
import { loadCachedCatalog, saveCachedCatalog } from './lib/catalog'

type Tab = 'approvals' | 'catalog' | 'policies' | 'audit' | 'drivers'

function parseApprovalDeepLink(): { tab: Tab; id: string | null; token: string | null } {
  const path = window.location.pathname
  const match = path.match(/^\/approvals\/([^/]+)$/)
  const sp = new URLSearchParams(window.location.search)
  const token = sp.get('token')
  if (match) {
    return { tab: 'approvals', id: decodeURIComponent(match[1]), token }
  }
  return { tab: 'approvals', id: null, token: null }
}

export function App() {
  const initialLink = parseApprovalDeepLink()
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
      label: pendingCount > 0 ? `Approvals (${pendingCount})` : 'Approvals',
      icon: ShieldAlert,
      section: 'Gate',
    },
    { id: 'catalog', label: 'Systems & DBs', icon: Database, section: 'Control Plane' },
    { id: 'policies', label: 'Policies', icon: ShieldCheck, section: 'Control Plane' },
    { id: 'audit', label: 'Audit Logs', icon: ScrollText, section: 'Observability' },
    { id: 'drivers', label: 'Drivers', icon: Cpu, section: 'Observability' },
  ]

  const handleToggleFreeze = async (next: boolean) => {
    if (!bootstrap?.global_security) return
    try {
      const updated = await api.saveGlobalSecurity({
        ...bootstrap.global_security,
        prod_read_only_freeze: next,
      })
      setBootstrap((prev) => (prev ? { ...prev, global_security: updated } : prev))
      toast.success(next ? 'Production freeze enabled' : 'Production freeze disabled')
    } catch (e) {
      toast.error(e instanceof Error ? e.message : 'Failed to toggle freeze')
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
        enableCommandPalette
        topbarExtra={
          bootstrap ? (
            <Badge variant="outline" className="font-mono text-[11px]">
              {bootstrap.identity.session} · {bootstrap.identity.version}
            </Badge>
          ) : null
        }
      >
        {tab === 'approvals' && (
          <ApprovalsTab
            catalog={catalog}
            globalSecurity={bootstrap?.global_security ?? null}
            deepLinkId={initialLink.id}
            deepLinkToken={initialLink.token}
            onToggleFreeze={handleToggleFreeze}
            onCountChange={setPendingCount}
          />
        )}
        {tab === 'catalog' && (
          <CatalogTab catalog={catalog} onRefreshBootstrap={refreshBootstrap} />
        )}
        {tab === 'policies' && (
          <PoliciesTab
            catalog={catalog}
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
