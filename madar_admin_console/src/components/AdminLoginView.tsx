'use client';

import React, { useState } from 'react';
import { useI18n } from '@/lib/i18n';
import { bffFetch, setClientCsrfToken } from '@/lib/api-client';

interface AdminLoginViewProps {
  workspaceName?: string;
  primaryColor?: string;
  onLoginSuccess: (payload: { user: any; csrf_token: string }) => void;
}

export function AdminLoginView({
  workspaceName,
  primaryColor,
  onLoginSuccess,
}: AdminLoginViewProps) {
  const { t, locale, toggleLocale } = useI18n();
  const [identifier, setIdentifier] = useState('');
  const [password, setPassword] = useState('');
  const [totpCode, setTotpCode] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    if (!identifier.trim() || !password) {
      setError(
        locale === 'ar'
          ? 'يرجى إدخال الرقم الوظيفي/البريد الإلكتروني وكلمة المرور.'
          : 'Please enter your Employee ID / Email and password.',
      );
      return;
    }

    setLoading(true);
    try {
      const res = await bffFetch('/admin-api/session/login', {
        method: 'POST',
        body: {
          identifier: identifier.trim(),
          password,
          totp_code: totpCode.trim() || undefined,
          device_fingerprint: 'madar-admin-console-nextjs-bff',
          device_name: 'Madar Sovereign Admin Console (Next.js BFF)',
        },
      });

      if (!res.ok) {
        setError(
          res.data?.error ||
            (locale === 'ar'
              ? 'فشل تسجيل الدخول. تحقق من البيانات أو صلاحيات المشرف.'
              : 'Authentication failed. Check your credentials and admin role.'),
        );
        setLoading(false);
        return;
      }

      if (res.data?.csrf_token) {
        setClientCsrfToken(res.data.csrf_token);
      }

      onLoginSuccess({
        user: res.data?.user,
        csrf_token: res.data?.csrf_token,
      });
    } catch (err: any) {
      setError(err?.message || 'Network error while contacting Admin BFF');
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col">
      {/* Top Header */}
      <header className="border-b border-slate-800 bg-slate-900/80 backdrop-blur px-6 py-4 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div
            className="w-10 h-10 rounded-xl flex items-center justify-center font-bold text-white shadow-lg"
            style={{ backgroundColor: primaryColor || '#14b8a6' }}
          >
            M
          </div>
          <div>
            <h1 className="font-bold text-lg text-white">{t.appTitle}</h1>
            <p className="text-xs text-slate-400">{t.appSubtitle}</p>
          </div>
        </div>
        <div className="flex items-center gap-3">
          <span className="hidden sm:inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-medium bg-emerald-500/10 text-emerald-300 border border-emerald-500/30">
            <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
            {t.firstTimeCompletedBadge}
          </span>
          <button
            type="button"
            onClick={toggleLocale}
            className="px-3.5 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 border border-slate-700 text-xs font-semibold text-teal-300 transition"
          >
            {t.switchLang}
          </button>
        </div>
      </header>

      {/* Main Centered Login Card */}
      <main className="flex-1 flex items-center justify-center p-6">
        <div className="w-full max-w-md bg-slate-900 border border-slate-800 rounded-2xl p-8 shadow-2xl">
          <div className="mb-6">
            <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full text-xs font-semibold bg-teal-500/10 text-teal-300 border border-teal-500/30 mb-3">
              {workspaceName || 'Madar Sovereign Workspace'}
            </div>
            <h2 className="text-2xl font-bold text-white">{t.loginTitle}</h2>
            <p className="text-xs text-slate-400 mt-1.5 leading-relaxed">{t.loginSubtitle}</p>
          </div>

          {error && (
            <div className="mb-5 p-3.5 rounded-xl bg-rose-500/10 border border-rose-500/30 text-rose-300 text-xs font-medium">
              {error}
            </div>
          )}

          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <label className="block text-xs font-semibold text-slate-300 mb-1.5">
                {t.identifierLabel}
              </label>
              <input
                type="text"
                value={identifier}
                onChange={(e) => setIdentifier(e.target.value)}
                placeholder={t.identifierPlaceholder}
                autoComplete="username"
                className="w-full px-3.5 py-2.5 rounded-xl bg-slate-950 border border-slate-800 text-white text-sm focus:outline-none focus:border-teal-500"
              />
            </div>

            <div>
              <label className="block text-xs font-semibold text-slate-300 mb-1.5">
                {t.passwordLabel}
              </label>
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="••••••••••••"
                autoComplete="current-password"
                className="w-full px-3.5 py-2.5 rounded-xl bg-slate-950 border border-slate-800 text-white text-sm focus:outline-none focus:border-teal-500"
              />
            </div>

            <div>
              <label className="block text-xs font-semibold text-slate-300 mb-1.5">
                {t.totpLabel}
              </label>
              <input
                type="text"
                value={totpCode}
                onChange={(e) => setTotpCode(e.target.value)}
                placeholder={t.totpPlaceholder}
                className="w-full px-3.5 py-2.5 rounded-xl bg-slate-950 border border-slate-800 text-white text-sm font-mono focus:outline-none focus:border-teal-500"
              />
            </div>

            <button
              type="submit"
              disabled={loading}
              className="w-full mt-2 py-3 rounded-xl bg-teal-500 hover:bg-teal-400 disabled:opacity-50 text-slate-950 font-bold text-sm shadow-lg shadow-teal-500/20 transition"
            >
              {loading ? t.signingIn : t.signInBtn}
            </button>
          </form>

          <div className="mt-6 pt-5 border-t border-slate-800/80 text-[11px] text-slate-400 flex items-center justify-between">
            <span>{t.isolatedBadge}</span>
            <span className="font-mono text-slate-500">RBAC: SUPER_ADMIN / IT / HR / COMP</span>
          </div>
        </div>
      </main>
    </div>
  );
}
