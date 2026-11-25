import { BrandMark, Button, FormField, Input, LoadingButton, Notice, Panel } from '@x0c/ui'
import { ChevronDown, KeyRound } from 'lucide-react'
import { useEffect, useState, type FormEvent } from 'react'
import { api, type PublicAuthInfo } from '../api'
import { useI18n } from '../lib/i18n'

const MANUAL_LOGOUT_KEY = 'dbctl_manual_logout'
const OIDC_AUTO_TS_KEY = 'dbctl_oidc_auto_ts'

function shouldAutoRedirectOIDC(): boolean {
  try {
    const sp = new URLSearchParams(window.location.search)
    if (sp.has('local') || sp.has('logged_out') || sp.has('error')) {
      return false
    }
    if (sessionStorage.getItem(MANUAL_LOGOUT_KEY) === '1') {
      return false
    }
    const rawTs = sessionStorage.getItem(OIDC_AUTO_TS_KEY)
    if (rawTs && Date.now() - Number(rawTs) < 15000) {
      return false
    }
    return true
  } catch {
    return false
  }
}

export function LoginView({
  authInfo,
  onSuccess,
}: {
  authInfo: PublicAuthInfo | null
  onSuccess: () => Promise<void>
}) {
  const { locale, setLocale, t } = useI18n()
  const sp = new URLSearchParams(window.location.search)
  const oidcError = sp.get('error')
  const oidcEnabled = Boolean(authInfo?.oidc_enabled)
  const localEnabled = authInfo?.local_enabled ?? true

  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [showLocalForm, setShowLocalForm] = useState(!oidcEnabled || sp.has('local'))
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState<string | null>(oidcError)

  const returnParams = new URLSearchParams(window.location.search)
  returnParams.delete('error')
  returnParams.delete('logged_out')
  returnParams.delete('local')
  const cleanSearch = returnParams.toString()
  const oidcHref = `/api/v1/auth/oidc/login?return_to=${encodeURIComponent(
    `${window.location.pathname}${cleanSearch ? `?${cleanSearch}` : ''}`,
  )}`

  const willAutoRedirect = oidcEnabled && shouldAutoRedirectOIDC()

  useEffect(() => {
    if (!oidcEnabled) {
      setShowLocalForm(true)
    }
  }, [oidcEnabled])

  useEffect(() => {
    if (!willAutoRedirect) return
    try {
      sessionStorage.setItem(OIDC_AUTO_TS_KEY, String(Date.now()))
    } catch {
      // Ignore restricted storage environments.
    }
    window.location.replace(oidcHref)
  }, [willAutoRedirect, oidcHref])

  if (willAutoRedirect) {
    return <div className="min-h-svh bg-background" />
  }

  const handleLocalLogin = async (e: FormEvent) => {
    e.preventDefault()
    if (!email.trim() || !password) {
      setError(t('login.requiredFields'))
      return
    }
    setSubmitting(true)
    setError(null)
    try {
      await api.loginLocal(email.trim(), password)
      try {
        sessionStorage.removeItem(MANUAL_LOGOUT_KEY)
        sessionStorage.removeItem(OIDC_AUTO_TS_KEY)
      } catch {
        // Ignore storage failures.
      }
      setPassword('')
      await onSuccess()
    } catch (err) {
      setError(err instanceof Error ? err.message : t('login.failed'))
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <div className="min-h-svh bg-background text-foreground flex flex-col items-center justify-center px-4 py-10">
      <div className="w-full max-w-[368px] space-y-6">
        <div className="flex flex-col items-center gap-3 text-center">
          <BrandMark size="md" label="agent-dbctl" />
          <h1 className="text-lg font-semibold tracking-[-0.02em] text-foreground">
            {t('login.title')}
          </h1>
        </div>

        <Panel flush>
          <div className="p-6 space-y-4">
            {error && <Notice tone="error">{error}</Notice>}

            {oidcEnabled && (
              <Button
                type="button"
                className="h-10 w-full gap-2 font-medium"
                asChild
                onClick={() => {
                  try {
                    sessionStorage.removeItem(MANUAL_LOGOUT_KEY)
                  } catch {
                    // Ignore storage failures.
                  }
                }}
              >
                <a href={oidcHref}>
                  <KeyRound className="size-4" />
                  <span>{t('login.oidcButton')}</span>
                </a>
              </Button>
            )}

            {oidcEnabled && localEnabled && (
              <button
                type="button"
                onClick={() => setShowLocalForm((prev) => !prev)}
                className="flex w-full cursor-pointer items-center justify-center gap-1.5 py-1 text-xs text-muted-foreground transition-colors hover:text-foreground"
              >
                <span>{showLocalForm ? t('login.hideLocal') : t('login.useLocal')}</span>
                <ChevronDown
                  className={`size-3.5 transition-transform duration-150 ${showLocalForm ? 'rotate-180' : ''}`}
                />
              </button>
            )}

            {localEnabled && (!oidcEnabled || showLocalForm) && (
              <form
                onSubmit={(e) => void handleLocalLogin(e)}
                className={`space-y-4 ${oidcEnabled ? 'border-t border-border pt-4' : ''}`}
              >
                <FormField label={t('login.email')}>
                  <Input
                    type="email"
                    autoComplete="username"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    placeholder="admin@localhost"
                  />
                </FormField>
                <FormField label={t('login.password')}>
                  <Input
                    type="password"
                    autoComplete="current-password"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                  />
                </FormField>
                <LoadingButton
                  type="submit"
                  variant={oidcEnabled ? 'secondary' : 'default'}
                  pending={submitting}
                  className="h-10 w-full font-medium"
                >
                  {t('login.submit')}
                </LoadingButton>
              </form>
            )}
          </div>
        </Panel>

        <div className="mt-2 flex items-center justify-center">
          <button
            type="button"
            onClick={() => setLocale(locale === 'zh' ? 'en' : 'zh')}
            className="cursor-pointer text-xs text-muted-foreground/80 transition-colors hover:text-foreground"
          >
            {locale === 'zh' ? 'English' : '中文'}
          </button>
        </div>
      </div>
    </div>
  )
}
