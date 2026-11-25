import type { DisplayCatalog, DisplayMetaItem } from '../api'

const STORAGE_KEY = 'agent-dbctl.display_catalog.v1'

export const EMPTY_CATALOG: DisplayCatalog = {
  catalog_version: 0,
  environments: [],
  operation_statuses: [],
  risk_levels: [],
  engines: [],
  approval_providers: [],
}

/** Synchronously reads last-known-good display catalog for frame-0 offline-first rendering. */
export function loadCachedCatalog(): DisplayCatalog {
  try {
    const raw = localStorage.getItem(STORAGE_KEY)
    if (!raw) return EMPTY_CATALOG
    const parsed = JSON.parse(raw) as DisplayCatalog
    if (!parsed || typeof parsed !== 'object') return EMPTY_CATALOG
    return parsed
  } catch {
    return EMPTY_CATALOG
  }
}

/** Replaces the cached catalog wholesale when version changes (never merges partial entries). */
export function saveCachedCatalog(cat: DisplayCatalog): DisplayCatalog {
  try {
    const current = loadCachedCatalog()
    if (current.catalog_version !== cat.catalog_version || current.environments.length !== cat.environments.length) {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(cat))
    } else {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(cat))
    }
  } catch {
    // Ignore storage quota errors in restricted environments.
  }
  return cat
}

/**
 * Resolves localized label + color strictly from server-provided DisplayMetaItem[].
 * Unknown codes are returned verbatim (never mapped to fallback words like "Unknown").
 */
export function resolveDisplayItem(
  items: DisplayMetaItem[] | undefined,
  code: string,
): { label: string; color: string } {
  const item = items?.find((x) => x.code.toLowerCase() === code.toLowerCase())
  if (!item) {
    return { label: code, color: '#6B7280' }
  }
  const lang = (typeof navigator !== 'undefined' ? navigator.language : 'en').toLowerCase()
  const primary = lang.split('-')[0]
  const labels = item.labels || {}
  const label = labels[lang] ?? labels[primary] ?? labels['en'] ?? code
  return { label, color: item.color || '#6B7280' }
}
