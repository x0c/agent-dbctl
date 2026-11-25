import type { DisplayMetaItem } from '../api'
import { resolveDisplayItem } from '../lib/catalog'
import { useI18n } from '../lib/i18n'

export function MetaBadge({ items, code }: { items?: DisplayMetaItem[]; code: string }) {
  const { locale } = useI18n()
  const { label, color } = resolveDisplayItem(items, code, locale)
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
