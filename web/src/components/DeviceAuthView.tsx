import { Button, FormField, Input, LoadingButton, Notice, Panel } from '@x0c/ui'
import { CheckCircle2, Terminal, XCircle } from 'lucide-react'
import { useState, type FormEvent } from 'react'
import { api } from '../api'
import { useI18n } from '../lib/i18n'

export function DeviceAuthView({
  initialUserCode,
  userEmail,
  onDone,
}: {
  initialUserCode: string | null
  userEmail?: string
  onDone: () => void
}) {
  const { t } = useI18n()
  const [userCode, setUserCode] = useState((initialUserCode ?? '').trim().toUpperCase())
  const [submitting, setSubmitting] = useState<'approve' | 'reject' | null>(null)
  const [result, setResult] = useState<'approved' | 'rejected' | null>(null)
  const [error, setError] = useState<string | null>(null)

  const submitDecision = async (decision: 'approve' | 'reject') => {
    const code = userCode.trim().toUpperCase()
    if (!code) {
      setError(t('device.codeRequired'))
      return
    }
    setSubmitting(decision)
    setError(null)
    try {
      const resp = await api.decideDeviceLogin(code, decision)
      setUserCode(resp.user_code)
      setResult(resp.status === 'approved' ? 'approved' : 'rejected')
    } catch (err) {
      setError(err instanceof Error ? err.message : t('device.failed'))
    } finally {
      setSubmitting(null)
    }
  }

  const handleFormSubmit = (e: FormEvent) => {
    e.preventDefault()
    void submitDecision('approve')
  }

  return (
    <div className="min-h-svh bg-background text-foreground flex items-center justify-center p-6">
      <Panel className="w-full max-w-md space-y-5 p-6">
        <div className="flex items-center gap-2.5">
          <Terminal className="size-5 text-primary" />
          <h1 className="text-lg font-semibold tracking-tight">{t('device.title')}</h1>
        </div>

        {userEmail && (
          <div className="text-xs text-muted-foreground">
            {t('device.signedInAs', { email: userEmail })}
          </div>
        )}

        {error && <Notice tone="error">{error}</Notice>}

        {result ? (
          <div className="space-y-4">
            <Notice tone={result === 'approved' ? 'success' : 'warning'}>
              <div className="flex items-center gap-2">
                {result === 'approved' ? (
                  <CheckCircle2 className="size-4 shrink-0" />
                ) : (
                  <XCircle className="size-4 shrink-0" />
                )}
                <span>{result === 'approved' ? t('device.approvedNotice') : t('device.rejectedNotice')}</span>
              </div>
            </Notice>
            <Button type="button" variant="outline" className="w-full" onClick={onDone}>
              {t('device.backToConsole')}
            </Button>
          </div>
        ) : (
          <form onSubmit={handleFormSubmit} className="space-y-4">
            <FormField label={t('device.codeLabel')}>
              <Input
                value={userCode}
                onChange={(e) => setUserCode(e.target.value.toUpperCase())}
                placeholder="ABCD-EFGH"
                className="font-mono text-center text-base tracking-widest uppercase"
              />
            </FormField>
            <div className="flex gap-2.5">
              <LoadingButton
                type="submit"
                pending={submitting === 'approve'}
                disabled={submitting !== null}
                className="flex-1"
              >
                {t('device.approve')}
              </LoadingButton>
              <LoadingButton
                type="button"
                variant="outline"
                pending={submitting === 'reject'}
                disabled={submitting !== null}
                onClick={() => void submitDecision('reject')}
              >
                {t('device.reject')}
              </LoadingButton>
            </div>
          </form>
        )}
      </Panel>
    </div>
  )
}
