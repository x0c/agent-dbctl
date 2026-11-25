import type { DisplayMetaItem } from '../api'
import { resolveDisplayItem } from '../lib/catalog'

export function MetaBadge({ items, code }: { items?: DisplayMetaItem[]; code: string }) {
  const { label, color } = resolveDisplayItem(items, code)
  return (
    <span
      className="inline-flex items-center gap-1.5 rounded-md border px-2 py-0.5 text-xs font-medium whitespace-nowrap"
      style={{
        borderColor: `${color}40`,
        backgroundColor: `${color}14`,
        color,
      }}
    >
      <span className="size-1.5 rounded-full" style={{ backgroundColor: color }} />
      {label}
    </span>
  )
}
