import { Button, FormField, Input, LoadingButton, Notice, Panel } from '@x0c/ui'
import { KeyRound, Languages, Lock } from 'lucide-react'
import { useState, type FormEvent } from 'react'
import { api, type PublicAuthInfo } from '../api'
import { useI18n } from '../lib/i18n'

export function LoginView({
  authInfo,
  onSuccess,
}: {
  authInfo: PublicAuthInfo | null
  onSuccess: () => Promise<void>
}) {
  const { locale, setLocale, t } = useI18n()
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const oidcEnabled = Boolean(authInfo?.oidc_enabled)
  const localEnabled = authInfo?.local_enabled ?? true

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
      setPassword('')
      await onSuccess()
    } catch (err) {
      setError(err instanceof Error ? err.message : t('login.failed'))
    } finally {
      setSubmitting(false)
    }
  }

  const oidcHref = `/api/v1/auth/oidc/login?return_to=${encodeURIComponent(
    `${window.location.pathname}${window.location.search}`,
  )}`

  return (
    <div className="min-h-svh bg-background text-foreground flex flex-col">
      <div className="flex items-center justify-between border-b border-border px-6 py-3">
        <div className="flex items-center gap-2 font-semibold text-sm">
          <Lock className="size-4 text-primary" />
          <span>agent-dbctl</span>
        </div>
        <Button
          type="button"
          variant="ghost"
          size="sm"
          className="h-8 gap-1.5 px-2.5 text-xs font-medium text-muted-foreground hover:text-foreground"
          onClick={() => setLocale(locale === 'zh' ? 'en' : 'zh')}
          title={t('common.langToggleTitle')}
          aria-label={t('common.langToggleTitle')}
        >
          <Languages className="size-3.5" />
          <span>{t('common.langToggle')}</span>
        </Button>
      </div>

      <div className="flex-1 flex items-center justify-center p-6">
        <Panel className="w-full max-w-md space-y-5 p-6">
          <div className="space-y-1">
            <h1 className="text-lg font-semibold tracking-tight">{t('login.title')}</h1>
          </div>

          {error && <Notice tone="error">{error}</Notice>}

          {oidcEnabled && (
            <Button type="button" className="w-full gap-2" asChild>
              <a href={oidcHref}>
                <KeyRound className="size-4" />
                <span>{t('login.oidcButton')}</span>
              </a>
            </Button>
          )}

          {oidcEnabled && localEnabled && (
            <div className="relative flex items-center py-1">
              <div className="flex-grow border-t border-border" />
              <span className="mx-3 shrink text-xs text-muted-foreground">{t('login.or')}</span>
              <div className="flex-grow border-t border-border" />
            </div>
          )}

          {localEnabled && (
            <form onSubmit={(e) => void handleLocalLogin(e)} className="space-y-4">
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
              <LoadingButton type="submit" pending={submitting} className="w-full">
                {t('login.submit')}
              </LoadingButton>
            </form>
          )}
        </Panel>
      </div>
    </div>
  )
}
