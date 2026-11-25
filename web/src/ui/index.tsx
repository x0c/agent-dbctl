import {
  AlertCircle,
  CheckCircle2,
  Database,
  Info,
  Loader2,
  Search,
  TriangleAlert,
  X,
  type LucideIcon,
} from 'lucide-react'
import {
  cloneElement,
  createContext,
  isValidElement,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ButtonHTMLAttributes,
  type InputHTMLAttributes,
  type ReactElement,
  type ReactNode,
  type TextareaHTMLAttributes,
} from 'react'

function cn(...parts: Array<string | undefined | false | null>) {
  return parts.filter(Boolean).join(' ')
}

export function fmtDateTime(iso?: string): string {
  if (!iso) return '—'
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return iso
  return d.toLocaleString(undefined, {
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false,
  })
}

// ---- Toast Bus ----
type ToastKind = 'success' | 'error' | 'info'
interface ToastItem {
  id: number
  kind: ToastKind
  message: string
}
let toastSeq = 1
const toastListeners = new Set<(item: ToastItem) => void>()

function emitToast(kind: ToastKind, message: string) {
  const item: ToastItem = { id: toastSeq++, kind, message }
  toastListeners.forEach((fn) => fn(item))
}

export const toast = {
  success: (message: string) => emitToast('success', message),
  error: (message: string) => emitToast('error', message),
  info: (message: string) => emitToast('info', message),
}

export function Toaster() {
  const [items, setItems] = useState<ToastItem[]>([])
  useEffect(() => {
    const onItem = (item: ToastItem) => {
      setItems((prev) => [...prev.slice(-4), item])
      window.setTimeout(() => {
        setItems((prev) => prev.filter((x) => x.id !== item.id))
      }, 3600)
    }
    toastListeners.add(onItem)
    return () => {
      toastListeners.delete(onItem)
    }
  }, [])
  if (items.length === 0) return null
  return (
    <div className="pointer-events-none fixed right-4 bottom-4 z-50 flex flex-col gap-2">
      {items.map((item) => (
        <div
          key={item.id}
          className={cn(
            'pointer-events-auto flex items-center gap-2 rounded-md border px-3 py-2 text-xs font-medium shadow-sm',
            item.kind === 'error'
              ? 'border-red-300 bg-red-50 text-red-900'
              : item.kind === 'success'
                ? 'border-emerald-300 bg-emerald-50 text-emerald-950'
                : 'border-border bg-card text-foreground',
          )}
        >
          {item.kind === 'error' ? (
            <AlertCircle className="size-3.5 shrink-0 text-red-600" />
          ) : (
            <CheckCircle2 className="size-3.5 shrink-0 text-emerald-600" />
          )}
          <span>{item.message}</span>
          <button
            type="button"
            aria-label="Dismiss notification"
            className="ml-1 cursor-pointer opacity-60 hover:opacity-100"
            onClick={() => setItems((prev) => prev.filter((x) => x.id !== item.id))}
          >
            <X className="size-3" />
          </button>
        </div>
      ))}
    </div>
  )
}

// ---- Shell ----
export interface AdminNavItem {
  id: string
  label: string
  icon: LucideIcon
  section?: string
}

export function AdminShell({
  product,
  nav,
  activeId,
  onSelectNav,
  onBrandClick,
  enableCommandPalette,
  topbarExtra,
  children,
}: {
  product: string
  nav: AdminNavItem[]
  activeId: string
  onSelectNav: (id: string) => void
  onBrandClick?: () => void
  enableCommandPalette?: boolean
  topbarExtra?: ReactNode
  children: ReactNode
}) {
  const [paletteOpen, setPaletteOpen] = useState(false)
  const [query, setQuery] = useState('')

  useEffect(() => {
    if (!enableCommandPalette) return
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault()
        setPaletteOpen((v) => !v)
        setQuery('')
      } else if (e.key === 'Escape') {
        setPaletteOpen(false)
      }
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [enableCommandPalette])

  const sections = useMemo(() => {
    const map = new Map<string, AdminNavItem[]>()
    for (const item of nav) {
      const key = item.section || 'General'
      const list = map.get(key) ?? []
      list.push(item)
      map.set(key, list)
    }
    return Array.from(map.entries())
  }, [nav])

  const filteredNav = useMemo(() => {
    const q = query.trim().toLowerCase()
    if (!q) return nav
    return nav.filter((n) => n.label.toLowerCase().includes(q) || n.id.toLowerCase().includes(q))
  }, [nav, query])

  return (
    <div className="min-h-screen bg-background text-foreground">
      <header className="sticky top-0 z-30 border-b border-border bg-card/95 backdrop-blur">
        <div className="mx-auto flex h-13 max-w-[1440px] items-center justify-between gap-4 px-5">
          <div className="flex items-center gap-3">
            <button
              type="button"
              onClick={onBrandClick}
              className="flex cursor-pointer items-center gap-2 text-sm font-semibold tracking-tight text-foreground"
            >
              <span className="inline-flex size-6 items-center justify-center rounded-md bg-primary text-primary-foreground">
                <Database className="size-3.5" />
              </span>
              <span className="font-mono">{product}</span>
            </button>
            {enableCommandPalette && (
              <button
                type="button"
                onClick={() => {
                  setQuery('')
                  setPaletteOpen(true)
                }}
                className="hidden cursor-pointer items-center gap-2 rounded-md border border-border bg-muted/40 px-2.5 py-1 text-xs text-muted-foreground hover:bg-muted sm:inline-flex"
              >
                <Search className="size-3" />
                <span>Jump to...</span>
                <kbd className="rounded border border-border bg-card px-1 font-mono text-[10px]">⌘K</kbd>
              </button>
            )}
          </div>
          <div className="flex items-center gap-2">{topbarExtra}</div>
        </div>
      </header>

      <div className="mx-auto grid max-w-[1440px] grid-cols-1 gap-6 px-5 py-6 md:grid-cols-[210px_minmax(0,1fr)]">
        <aside className="space-y-4">
          {sections.map(([sectionName, items]) => (
            <div key={sectionName}>
              <div className="mb-1.5 px-2.5 text-[11px] font-semibold tracking-wider text-muted-foreground uppercase">
                {sectionName}
              </div>
              <nav className="space-y-0.5">
                {items.map((item) => {
                  const Icon = item.icon
                  const active = item.id === activeId
                  return (
                    <button
                      key={item.id}
                      type="button"
                      onClick={() => onSelectNav(item.id)}
                      className={cn(
                        'flex w-full cursor-pointer items-center gap-2.5 rounded-md px-2.5 py-1.5 text-left text-[13px] font-medium transition-colors',
                        active
                          ? 'bg-primary text-primary-foreground'
                          : 'text-muted-foreground hover:bg-muted hover:text-foreground',
                      )}
                    >
                      <Icon className="size-4 shrink-0" />
                      <span className="truncate">{item.label}</span>
                    </button>
                  )
                })}
              </nav>
            </div>
          ))}
        </aside>

        <main className="min-w-0">{children}</main>
      </div>

      {paletteOpen && (
        <div
          className="fixed inset-0 z-50 flex items-start justify-center bg-black/30 pt-24 backdrop-blur-[1px]"
          onClick={() => setPaletteOpen(false)}
        >
          <div
            className="w-full max-w-md rounded-lg border border-border bg-card shadow-lg"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="flex items-center gap-2 border-b border-border px-3 py-2.5">
              <Search className="size-4 text-muted-foreground" />
              <input
                autoFocus
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                placeholder="Jump to view..."
                className="w-full bg-transparent text-sm outline-none"
              />
              <button
                type="button"
                aria-label="Close palette"
                onClick={() => setPaletteOpen(false)}
                className="cursor-pointer rounded p-1 text-muted-foreground hover:bg-muted"
              >
                <X className="size-4" />
              </button>
            </div>
            <div className="max-h-64 divide-y divide-border overflow-y-auto p-1">
              {filteredNav.map((item) => {
                const Icon = item.icon
                return (
                  <button
                    key={item.id}
                    type="button"
                    onClick={() => {
                      onSelectNav(item.id)
                      setPaletteOpen(false)
                    }}
                    className="flex w-full cursor-pointer items-center gap-2.5 rounded-md px-3 py-2 text-left text-sm hover:bg-muted"
                  >
                    <Icon className="size-4 text-muted-foreground" />
                    <span>{item.label}</span>
                    {item.section && (
                      <span className="ml-auto text-xs text-muted-foreground">{item.section}</span>
                    )}
                  </button>
                )
              })}
              {filteredNav.length === 0 && (
                <div className="px-3 py-4 text-center text-xs text-muted-foreground">No matching view</div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

// ---- Primitives ----
export function PageHeader({
  title,
  subtitle,
  actions,
}: {
  title: string
  subtitle?: string
  actions?: ReactNode
}) {
  return (
    <div className="flex flex-wrap items-center justify-between gap-3">
      <div>
        <h1 className="text-lg font-semibold tracking-tight text-foreground">{title}</h1>
        {subtitle && <p className="mt-0.5 text-xs text-muted-foreground">{subtitle}</p>}
      </div>
      {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
    </div>
  )
}

export function Panel({
  title,
  action,
  flush,
  className,
  children,
}: {
  title?: string
  action?: ReactNode
  flush?: boolean
  className?: string
  children: ReactNode
}) {
  return (
    <section className={cn('rounded-lg border border-border bg-card', className)}>
      {(title || action) && (
        <div className="flex flex-wrap items-center justify-between gap-2 border-b border-border px-4 py-2.5">
          {title ? <h2 className="text-sm font-semibold text-foreground">{title}</h2> : <div />}
          {action}
        </div>
      )}
      <div className={flush ? '' : 'p-4'}>{children}</div>
    </section>
  )
}

export function Badge({
  variant = 'default',
  className,
  children,
}: {
  variant?: 'default' | 'outline' | 'secondary'
  className?: string
  children: ReactNode
}) {
  const styles =
    variant === 'outline'
      ? 'border-border bg-card text-foreground'
      : variant === 'secondary'
        ? 'border-transparent bg-muted text-foreground'
        : 'border-transparent bg-primary text-primary-foreground'
  return (
    <span
      className={cn(
        'inline-flex items-center rounded-md border px-2 py-0.5 text-xs font-medium whitespace-nowrap',
        styles,
        className,
      )}
    >
      {children}
    </span>
  )
}

export interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: 'default' | 'outline' | 'ghost' | 'destructive'
  size?: 'sm' | 'md' | 'icon'
}

export function Button({
  variant = 'default',
  size = 'md',
  className,
  type = 'button',
  ...props
}: ButtonProps) {
  const vClass =
    variant === 'outline'
      ? 'border border-border bg-card text-foreground hover:bg-muted'
      : variant === 'ghost'
        ? 'border border-transparent bg-transparent text-foreground hover:bg-muted'
        : variant === 'destructive'
          ? 'border border-destructive bg-destructive text-destructive-foreground hover:opacity-90'
          : 'border border-primary bg-primary text-primary-foreground hover:opacity-90'
  const sClass =
    size === 'sm'
      ? 'h-8 px-2.5 text-xs gap-1.5'
      : size === 'icon'
        ? 'h-8 w-8 p-0'
        : 'h-9 px-3.5 text-sm gap-2'
  return (
    <button
      type={type}
      className={cn(
        'inline-flex cursor-pointer items-center justify-center rounded-md font-medium whitespace-nowrap transition-colors disabled:pointer-events-none disabled:opacity-50',
        vClass,
        sClass,
        className,
      )}
      {...props}
    />
  )
}

export function LoadingButton({
  pending,
  disabled,
  children,
  ...props
}: ButtonProps & { pending?: boolean }) {
  return (
    <Button disabled={pending || disabled} {...props}>
      {pending && <Loader2 className="size-3.5 animate-spin" />}
      {children}
    </Button>
  )
}

export function Notice({
  tone = 'info',
  children,
}: {
  tone?: 'info' | 'warning' | 'error' | 'success'
  children: ReactNode
}) {
  const toneClass =
    tone === 'error'
      ? 'border-red-200 bg-red-50 text-red-900'
      : tone === 'warning'
        ? 'border-amber-200 bg-amber-50 text-amber-950'
        : tone === 'success'
          ? 'border-emerald-200 bg-emerald-50 text-emerald-950'
          : 'border-border bg-muted/40 text-foreground'
  const Icon =
    tone === 'error'
      ? AlertCircle
      : tone === 'warning'
        ? TriangleAlert
        : tone === 'success'
          ? CheckCircle2
          : Info
  return (
    <div className={cn('flex items-start gap-2.5 rounded-md border px-3.5 py-2.5 text-xs', toneClass)}>
      <Icon className="mt-0.5 size-4 shrink-0" />
      <div className="min-w-0 flex-1">{children}</div>
    </div>
  )
}

export function StatusDot({
  tone = 'neutral',
  children,
}: {
  tone?: 'success' | 'danger' | 'warning' | 'neutral'
  children: ReactNode
}) {
  const dotColor =
    tone === 'success'
      ? 'bg-emerald-600'
      : tone === 'danger'
        ? 'bg-red-600'
        : tone === 'warning'
          ? 'bg-amber-500'
          : 'bg-gray-400'
  return (
    <span className="inline-flex items-center gap-1.5 text-xs">
      <span className={cn('size-2 shrink-0 rounded-full', dotColor)} />
      {children}
    </span>
  )
}

export function FormField({ label, children }: { label: string; children: ReactNode }) {
  return (
    <label className="block space-y-1">
      <span className="block text-xs font-medium text-muted-foreground">{label}</span>
      {children}
    </label>
  )
}

export function Input({ className, ...props }: InputHTMLAttributes<HTMLInputElement>) {
  return (
    <input
      className={cn(
        'h-9 w-full rounded-md border border-input bg-card px-3 text-sm text-foreground outline-none focus:border-primary disabled:bg-muted',
        className,
      )}
      {...props}
    />
  )
}

export function Textarea({ className, ...props }: TextareaHTMLAttributes<HTMLTextAreaElement>) {
  return (
    <textarea
      className={cn(
        'w-full rounded-md border border-input bg-card px-3 py-2 text-sm text-foreground outline-none focus:border-primary disabled:bg-muted',
        className,
      )}
      {...props}
    />
  )
}

export function Switch({
  checked = false,
  onCheckedChange,
  disabled,
}: {
  checked?: boolean
  onCheckedChange?: (checked: boolean) => void
  disabled?: boolean
}) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={checked}
      disabled={disabled}
      onClick={() => onCheckedChange?.(!checked)}
      className={cn(
        'relative inline-flex h-5 w-9 shrink-0 cursor-pointer items-center rounded-full border border-transparent transition-colors disabled:opacity-50',
        checked ? 'bg-primary' : 'bg-gray-300',
      )}
    >
      <span
        className={cn(
          'inline-block size-4 rounded-full bg-white shadow transition-transform',
          checked ? 'translate-x-4' : 'translate-x-0.5',
        )}
      />
    </button>
  )
}

// ---- Select ----
interface SelectContextVal {
  value: string
  onValueChange: (val: string) => void
  open: boolean
  setOpen: (open: boolean) => void
  labels: Record<string, string>
  registerLabel: (val: string, label: string) => void
}
const SelectContext = createContext<SelectContextVal | null>(null)

export function Select({
  value = '',
  onValueChange,
  children,
}: {
  value?: string
  onValueChange: (val: string) => void
  children: ReactNode
}) {
  const [open, setOpen] = useState(false)
  const [labels, setLabels] = useState<Record<string, string>>({})
  const boxRef = useRef<HTMLDivElement>(null)

  const registerLabel = (val: string, label: string) => {
    setLabels((prev) => (prev[val] === label ? prev : { ...prev, [val]: label }))
  }

  useEffect(() => {
    if (!open) return
    const onDown = (e: MouseEvent) => {
      if (boxRef.current && !boxRef.current.contains(e.target as Node)) {
        setOpen(false)
      }
    }
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') setOpen(false)
    }
    document.addEventListener('mousedown', onDown)
    window.addEventListener('keydown', onKey)
    return () => {
      document.removeEventListener('mousedown', onDown)
      window.removeEventListener('keydown', onKey)
    }
  }, [open])

  return (
    <SelectContext.Provider value={{ value, onValueChange, open, setOpen, labels, registerLabel }}>
      <div ref={boxRef} className="relative w-full">
        {children}
      </div>
    </SelectContext.Provider>
  )
}

export function SelectTrigger({ children }: { children: ReactNode }) {
  const ctx = useContext(SelectContext)
  if (!ctx) return null
  return (
    <button
      type="button"
      onClick={() => ctx.setOpen(!ctx.open)}
      className="flex h-9 w-full cursor-pointer items-center justify-between gap-2 rounded-md border border-input bg-card px-3 text-left text-sm text-foreground outline-none hover:border-gray-400"
    >
      <span className="truncate">{children}</span>
      <span className="text-[10px] text-muted-foreground">▼</span>
    </button>
  )
}

export function SelectValue({ placeholder }: { placeholder?: string }) {
  const ctx = useContext(SelectContext)
  if (!ctx) return null
  const label = ctx.value ? ctx.labels[ctx.value] ?? ctx.value : ''
  return <span className={label ? '' : 'text-muted-foreground'}>{label || placeholder || 'Select...'}</span>
}

export function SelectContent({ children }: { children: ReactNode }) {
  const ctx = useContext(SelectContext)
  if (!ctx) return null
  return (
    <div
      className={cn(
        'absolute z-50 mt-1 max-h-60 w-full min-w-[160px] overflow-auto rounded-md border border-border bg-card p-1 shadow-md',
        !ctx.open && 'hidden',
      )}
    >
      {children}
    </div>
  )
}

function extractNodeText(node: ReactNode): string {
  if (typeof node === 'string' || typeof node === 'number') return String(node)
  if (Array.isArray(node)) return node.map(extractNodeText).join('')
  if (isValidElement<{ children?: ReactNode }>(node)) return extractNodeText(node.props.children)
  return ''
}

export function SelectItem({ value, children }: { value: string; children: ReactNode }) {
  const ctx = useContext(SelectContext)
  const textLabel = extractNodeText(children).trim() || value
  useEffect(() => {
    ctx?.registerLabel(value, textLabel)
  }, [value, textLabel])
  if (!ctx) return null
  const selected = ctx.value === value
  return (
    <button
      type="button"
      onClick={() => {
        ctx.onValueChange(value)
        ctx.setOpen(false)
      }}
      className={cn(
        'flex w-full cursor-pointer items-center rounded px-2.5 py-1.5 text-left text-xs',
        selected ? 'bg-primary font-medium text-primary-foreground' : 'text-foreground hover:bg-muted',
      )}
    >
      {children}
    </button>
  )
}

// ---- Tabs ----
const TabsContext = createContext<{ value: string; onValueChange: (v: string) => void } | null>(null)

export function Tabs({
  value,
  onValueChange,
  children,
}: {
  value: string
  onValueChange: (v: string) => void
  children: ReactNode
}) {
  return (
    <TabsContext.Provider value={{ value, onValueChange }}>
      <div className="space-y-4">{children}</div>
    </TabsContext.Provider>
  )
}

export function TabsList({ children }: { children: ReactNode }) {
  return (
    <div className="inline-flex flex-wrap items-center gap-1 rounded-md border border-border bg-muted/50 p-1">
      {children}
    </div>
  )
}

export function TabsTrigger({ value, children }: { value: string; children: ReactNode }) {
  const ctx = useContext(TabsContext)
  if (!ctx) return null
  const active = ctx.value === value
  return (
    <button
      type="button"
      onClick={() => ctx.onValueChange(value)}
      className={cn(
        'cursor-pointer rounded px-3 py-1 text-xs font-medium transition-colors',
        active ? 'bg-card text-foreground shadow-xs' : 'text-muted-foreground hover:text-foreground',
      )}
    >
      {children}
    </button>
  )
}

export function TabsContent({ value, children }: { value: string; children: ReactNode }) {
  const ctx = useContext(TabsContext)
  if (!ctx || ctx.value !== value) return null
  return <div>{children}</div>
}

// ---- DataTable ----
export interface ColumnDef<T, _V = unknown> {
  id?: string
  accessorKey?: string
  header: ReactNode
  cell?: (info: { row: { original: T } }) => ReactNode
}

function getByPath(obj: unknown, path?: string): unknown {
  if (!path || typeof obj !== 'object' || obj === null) return ''
  return path.split('.').reduce<unknown>((acc, key) => {
    if (acc && typeof acc === 'object' && key in (acc as Record<string, unknown>)) {
      return (acc as Record<string, unknown>)[key]
    }
    return undefined
  }, obj)
}

export function DataTable<T>({
  columns,
  data,
  emptyLabel = 'No rows',
  searchable: _searchable,
}: {
  columns: ColumnDef<T, unknown>[]
  data: T[]
  emptyLabel?: string
  searchable?: boolean
}) {
  if (data.length === 0) {
    return <div className="px-4 py-10 text-center text-sm text-muted-foreground">{emptyLabel}</div>
  }
  return (
    <div className="overflow-x-auto">
      <table className="w-full border-collapse text-left text-sm">
        <thead>
          <tr className="border-b border-border bg-muted/40 text-xs font-medium text-muted-foreground">
            {columns.map((col, idx) => (
              <th key={col.id || col.accessorKey || idx} className="px-4 py-2.5 whitespace-nowrap">
                {col.header}
              </th>
            ))}
          </tr>
        </thead>
        <tbody className="divide-y divide-border">
          {data.map((item, rIdx) => (
            <tr key={rIdx} className="hover:bg-muted/25">
              {columns.map((col, cIdx) => (
                <td key={col.id || col.accessorKey || cIdx} className="px-4 py-2.5 align-middle">
                  {col.cell
                    ? col.cell({ row: { original: item } })
                    : String(getByPath(item, col.accessorKey) ?? '—')}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

// ---- Dialogs & Confirm & Sheet ----
export function FormDialog({
  open,
  onOpenChange,
  title,
  submitLabel = 'Save',
  maxWidthClassName = 'max-w-lg',
  error,
  pending,
  onSubmit,
  children,
}: {
  open: boolean
  onOpenChange: (open: boolean) => void
  title: string
  submitLabel?: string
  maxWidthClassName?: string
  error?: string | null
  pending?: boolean
  onSubmit: () => Promise<void> | void
  children: ReactNode
}) {
  useEffect(() => {
    if (!open) return
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onOpenChange(false)
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [open, onOpenChange])

  if (!open) return null
  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/35 p-4"
      onClick={() => onOpenChange(false)}
    >
      <div
        className={cn('w-full rounded-lg border border-border bg-card shadow-lg', maxWidthClassName)}
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center justify-between border-b border-border px-4 py-3">
          <h3 className="text-sm font-semibold">{title}</h3>
          <button
            type="button"
            aria-label="Close dialog"
            onClick={() => onOpenChange(false)}
            className="cursor-pointer rounded p-1 text-muted-foreground hover:bg-muted"
          >
            <X className="size-4" />
          </button>
        </div>
        <form
          onSubmit={(e) => {
            e.preventDefault()
            void onSubmit()
          }}
        >
          <div className="max-h-[70vh] space-y-3 overflow-y-auto p-4">
            {error && <Notice tone="error">{error}</Notice>}
            {children}
          </div>
          <div className="flex items-center justify-end gap-2 border-t border-border px-4 py-3">
            <Button variant="outline" size="sm" onClick={() => onOpenChange(false)}>
              Cancel
            </Button>
            <LoadingButton type="submit" size="sm" pending={pending}>
              {submitLabel}
            </LoadingButton>
          </div>
        </form>
      </div>
    </div>
  )
}

export function ConfirmAction({
  trigger,
  title,
  description,
  confirmLabel = 'Confirm',
  destructive,
  onConfirm,
}: {
  trigger: ReactNode
  title: string
  description?: string
  confirmLabel?: string
  destructive?: boolean
  onConfirm: () => Promise<void> | void
}) {
  const [open, setOpen] = useState(false)
  const [pending, setPending] = useState(false)

  const wrappedTrigger = isValidElement(trigger)
    ? cloneElement(trigger as ReactElement<{ onClick?: () => void }>, {
        onClick: () => setOpen(true),
      })
    : <span onClick={() => setOpen(true)}>{trigger}</span>

  return (
    <>
      {wrappedTrigger}
      {open && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/35 p-4"
          onClick={() => !pending && setOpen(false)}
        >
          <div
            className="w-full max-w-sm rounded-lg border border-border bg-card p-4 shadow-lg"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="flex items-start justify-between gap-2">
              <h3 className="text-sm font-semibold">{title}</h3>
              <button
                type="button"
                aria-label="Close confirmation"
                onClick={() => !pending && setOpen(false)}
                className="cursor-pointer rounded p-0.5 text-muted-foreground hover:bg-muted"
              >
                <X className="size-4" />
              </button>
            </div>
            {description && <p className="mt-1.5 text-xs text-muted-foreground">{description}</p>}
            <div className="mt-4 flex justify-end gap-2">
              <Button variant="outline" size="sm" disabled={pending} onClick={() => setOpen(false)}>
                Cancel
              </Button>
              <LoadingButton
                variant={destructive ? 'destructive' : 'default'}
                size="sm"
                pending={pending}
                onClick={async () => {
                  setPending(true)
                  try {
                    await onConfirm()
                    setOpen(false)
                  } finally {
                    setPending(false)
                  }
                }}
              >
                {confirmLabel}
              </LoadingButton>
            </div>
          </div>
        </div>
      )}
    </>
  )
}

const SheetContext = createContext<{ onClose: () => void } | null>(null)

export function Sheet({
  open,
  onOpenChange,
  children,
}: {
  open: boolean
  onOpenChange: (open: boolean) => void
  children: ReactNode
}) {
  useEffect(() => {
    if (!open) return
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onOpenChange(false)
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [open, onOpenChange])

  if (!open) return null
  return (
    <SheetContext.Provider value={{ onClose: () => onOpenChange(false) }}>
      <div className="fixed inset-0 z-50 flex justify-end bg-black/35" onClick={() => onOpenChange(false)}>
        <div
          className="flex h-full w-full max-w-lg flex-col border-l border-border bg-card shadow-xl"
          onClick={(e) => e.stopPropagation()}
        >
          {children}
        </div>
      </div>
    </SheetContext.Provider>
  )
}

export function SheetContent({ children }: { children: ReactNode }) {
  return <div className="flex h-full flex-col overflow-hidden">{children}</div>
}

export function SheetHeader({ children }: { children: ReactNode }) {
  const ctx = useContext(SheetContext)
  return (
    <div className="flex items-center justify-between border-b border-border px-4 py-3">
      <div>{children}</div>
      {ctx && (
        <button
          type="button"
          aria-label="Close drawer"
          onClick={ctx.onClose}
          className="cursor-pointer rounded p-1 text-muted-foreground hover:bg-muted"
        >
          <X className="size-4" />
        </button>
      )}
    </div>
  )
}

export function SheetTitle({ children }: { children: ReactNode }) {
  return <h3 className="text-sm font-semibold">{children}</h3>
}

export function SheetBody({ children }: { children: ReactNode }) {
  return <div className="flex-1 overflow-y-auto p-4">{children}</div>
}
