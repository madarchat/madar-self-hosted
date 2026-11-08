'use client';

import React, { useEffect, useState } from 'react';
import { useI18n } from '@/lib/i18n';
import { bffFetch } from '@/lib/api-client';
import {
  Building2,
  CheckCircle2,
  Globe,
  KeyRound,
  Layers,
  Lock,
  Plus,
  ShieldCheck,
  Sparkles,
  Trash2,
  UserCheck,
} from 'lucide-react';

interface FirstTimeSetupWizardProps {
  initialWorkspace?: any;
  onComplete?: (setupResponse: any) => void;
  onSetupCompleted?: (setupResponse: any) => void;
}

export function FirstTimeSetupWizard({
  initialWorkspace,
  onComplete,
  onSetupCompleted,
}: FirstTimeSetupWizardProps) {
  const { locale, toggleLocale, t } = useI18n();
  const [step, setStep] = useState<number>(1);
  const [submitting, setSubmitting] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  // Step 1: Organization Identity
  const [workspaceName, setWorkspaceName] = useState('');
  const [serverUrl, setServerUrl] = useState('http://localhost:5025');
  const [primaryColor, setPrimaryColor] = useState(
    initialWorkspace?.primary_color || '#0F766E',
  );
  const [wsLocale, setWsLocale] = useState<'en' | 'ar'>('en');
  const [timezone, setTimezone] = useState(
    initialWorkspace?.timezone || 'Asia/Riyadh',
  );

  // Step 2: Initial Super-Admin
  const [employeeNo, setEmployeeNo] = useState('ADM-001');
  const [adminName, setAdminName] = useState('');
  const [adminEmail, setAdminEmail] = useState('');
  const [adminTitle, setAdminTitle] = useState('Chief Information Officer (Super Admin)');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');

  // Step 3: Departments & Policy Preset
  const [policyPreset, setPolicyPreset] = useState<'standard' | 'regulated' | 'defense'>(
    'standard',
  );
  const [departments, setDepartments] = useState<Array<{ name: string; code: string }>>([
    { name: 'Information Technology & Security', code: 'IT' },
    { name: 'Engineering & Operations', code: 'ENG' },
    { name: 'Executive Management', code: 'EXEC' },
  ]);

  // Auto-detect reachable madar_server URL (port 5025) from browser location (including GitHub Codespaces / LAN IP)
  useEffect(() => {
    if (typeof window !== 'undefined') {
      const { protocol, hostname } = window.location;
      if (hostname.includes('.app.github.dev') && hostname.includes('-5030')) {
        setServerUrl(`${protocol}//${hostname.replace('-5030', '-5025')}`);
      } else {
        setServerUrl(`${protocol}//${hostname}:5025`);
      }
    }
  }, []);

  const pwChecks = {
    minLen: password.length >= 10,
    upper: /[A-Z]/.test(password),
    lower: /[a-z]/.test(password),
    digit: /[0-9]/.test(password),
    symbol: /[^A-Za-z0-9]/.test(password),
    match: password.length > 0 && password === confirmPassword,
  };
  const isPasswordValid =
    pwChecks.minLen &&
    pwChecks.upper &&
    pwChecks.lower &&
    pwChecks.digit &&
    pwChecks.symbol &&
    pwChecks.match;

  function validateStep(currentStep: number): boolean {
    setErrorMsg(null);
    if (currentStep === 1) {
      if (workspaceName.trim().length < 2) {
        setErrorMsg(
          locale === 'ar'
            ? 'الرجاء إدخال اسم مساحة العمل (حرفان على الأقل).'
            : 'Please enter your Organization / Workspace Name (at least 2 characters).',
        );
        return false;
      }
      return true;
    }
    if (currentStep === 2) {
      if (!employeeNo.trim() || !adminName.trim() || !adminEmail.trim()) {
        setErrorMsg(
          locale === 'ar'
            ? 'الرجاء تعبئة الرقم الوظيفي والاسم الكامل والبريد الإلكتروني للمدير العام.'
            : 'Please fill in the Super-Admin Employee ID, Full Name, and Work Email.',
        );
        return false;
      }
      if (!isPasswordValid) {
        setErrorMsg(
          locale === 'ar'
            ? 'يرجى استيفاء جميع شروط قوة كلمة المرور ومطابقتها.'
            : 'Please satisfy all password complexity requirements and ensure passwords match.',
        );
        return false;
      }
      return true;
    }
    if (currentStep === 3) {
      const validDepts = departments.filter((d) => d.name.trim() && d.code.trim());
      if (validDepts.length === 0) {
        setErrorMsg(
          locale === 'ar'
            ? 'يرجى إضافة قسم واحد على الأقل لتجهيز قنوات مساحة العمل.'
            : 'Please keep at least one department to initialize your organization channels.',
        );
        return false;
      }
      return true;
    }
    return true;
  }

  async function handleFinishSetup() {
    if (!validateStep(3)) return;
    setSubmitting(true);
    setErrorMsg(null);

    try {
      const cleanDepts = departments
        .map((d) => ({
          name: d.name.trim(),
          code: d.code.trim().toUpperCase(),
        }))
        .filter((d) => d.name && d.code);

      const { ok, data } = await bffFetch('/admin-api/setup', {
        method: 'POST',
        body: {
          workspace_name: workspaceName.trim(),
          primary_color: primaryColor,
          locale: wsLocale,
          timezone,
          deployment_profile: 'workspace',
          policy_preset: policyPreset,
          server_url: serverUrl.trim(),
          admin_user: {
            employee_no: employeeNo.trim(),
            name: adminName.trim(),
            email: adminEmail.trim(),
            title: adminTitle.trim() || 'Super Admin',
            password,
          },
          departments: cleanDepts,
        },
      });

      if (!ok) {
        setErrorMsg(
          data?.error?.message ||
            (locale === 'ar'
              ? 'تعذر إكمال التهيئة الأولية. تحقق من المدخلات.'
              : 'Failed to complete setup. Please verify your inputs.'),
        );
        setSubmitting(false);
        return;
      }

      onComplete?.(data);
      onSetupCompleted?.(data);
    } catch (err: any) {
      setErrorMsg(err?.message || 'Unexpected error during setup');
      setSubmitting(false);
    }
  }

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col">
      {/* Top Bar */}
      <header className="border-b border-slate-800/80 bg-slate-900/70 backdrop-blur sticky top-0 z-20">
        <div className="max-w-5xl mx-auto px-6 py-4 flex items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="h-10 w-10 rounded-xl bg-teal-600/20 border border-teal-500/40 flex items-center justify-center text-teal-400 font-bold text-lg">
              M
            </div>
            <div>
              <h1 className="font-bold text-base sm:text-lg text-white">{t.appTitle}</h1>
              <p className="text-xs text-slate-400">{t.appSubtitle}</p>
            </div>
          </div>

          <div className="flex items-center gap-3">
            <span className="hidden sm:inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-medium bg-amber-500/10 text-amber-300 border border-amber-500/30">
              <Sparkles className="w-3.5 h-3.5" />
              {t.setupBadge}
            </span>
            <button
              type="button"
              onClick={toggleLocale}
              className="inline-flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg text-xs font-semibold bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 transition"
            >
              <Globe className="w-3.5 h-3.5 text-teal-400" />
              {t.switchLang}
            </button>
          </div>
        </div>
      </header>

      {/* Main Wizard Container */}
      <main className="flex-1 max-w-4xl w-full mx-auto px-6 py-8">
        <div className="mb-8">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-teal-500/10 border border-teal-500/30 text-teal-300 text-xs font-medium mb-3">
            <ShieldCheck className="w-4 h-4" />
            {t.setupBadge}
          </div>
          <h2 className="text-2xl sm:text-3xl font-bold text-white tracking-tight">
            {t.setupTitle}
          </h2>
          <p className="mt-2 text-sm text-slate-300 leading-relaxed">{t.setupDesc}</p>
        </div>

        {/* Stepper Progress */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-2.5 mb-8">
          {[
            { num: 1, label: t.step1Title, icon: Building2 },
            { num: 2, label: t.step2Title, icon: UserCheck },
            { num: 3, label: t.step3Title, icon: Layers },
            { num: 4, label: t.step4Title, icon: CheckCircle2 },
          ].map((item) => {
            const Icon = item.icon;
            const active = step === item.num;
            const done = step > item.num;
            return (
              <button
                key={item.num}
                type="button"
                onClick={() => {
                  if (item.num < step) setStep(item.num);
                }}
                className={`flex items-center gap-2.5 p-3 rounded-xl border text-start transition ${
                  active
                    ? 'bg-teal-950/60 border-teal-500 text-white shadow-lg shadow-teal-950/50'
                    : done
                      ? 'bg-slate-900/90 border-teal-800/60 text-teal-300 cursor-pointer'
                      : 'bg-slate-900/40 border-slate-800 text-slate-500 cursor-default'
                }`}
              >
                <div
                  className={`w-7 h-7 rounded-lg flex items-center justify-center text-xs font-bold shrink-0 ${
                    active
                      ? 'bg-teal-500 text-slate-950'
                      : done
                        ? 'bg-teal-800/60 text-teal-200'
                        : 'bg-slate-800 text-slate-400'
                  }`}
                >
                  <Icon className="w-4 h-4" />
                </div>
                <span className="text-xs font-semibold truncate">{item.label}</span>
              </button>
            );
          })}
        </div>

        {errorMsg && (
          <div className="mb-6 p-4 rounded-xl bg-rose-950/60 border border-rose-500/40 text-rose-200 text-sm">
            {errorMsg}
          </div>
        )}

        {/* Step Card */}
        <div className="bg-slate-900/90 border border-slate-800 rounded-2xl p-6 sm:p-8 shadow-xl">
          {step === 1 && (
            <div className="space-y-5">
              <div>
                <label className="block text-xs font-semibold uppercase tracking-wider text-slate-300 mb-2">
                  {t.orgNameLabel} *
                </label>
                <input
                  type="text"
                  value={workspaceName}
                  onChange={(e) => setWorkspaceName(e.target.value)}
                  placeholder={t.orgNamePlaceholder}
                  className="w-full px-4 py-3 rounded-xl bg-slate-950 border border-slate-700 text-white placeholder-slate-500 focus:outline-none focus:border-teal-500"
                  autoFocus
                />
              </div>

              <div>
                <label className="block text-xs font-semibold uppercase tracking-wider text-slate-300 mb-2">
                  {t.serverUrlLabel} *
                </label>
                <input
                  type="url"
                  value={serverUrl}
                  onChange={(e) => setServerUrl(e.target.value)}
                  placeholder="http://192.168.1.100:5025"
                  dir="ltr"
                  className="w-full px-4 py-3 rounded-xl bg-slate-950 border border-slate-700 text-teal-300 font-mono text-sm focus:outline-none focus:border-teal-500"
                />
                <p className="mt-1.5 text-xs text-slate-400">{t.serverUrlHelp}</p>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 pt-2">
                <div>
                  <label className="block text-xs font-semibold text-slate-300 mb-2">
                    {t.primaryColorLabel}
                  </label>
                  <div className="flex items-center gap-2">
                    <input
                      type="color"
                      value={primaryColor}
                      onChange={(e) => setPrimaryColor(e.target.value)}
                      className="h-10 w-14 rounded-lg bg-slate-950 border border-slate-700 cursor-pointer"
                    />
                    <input
                      type="text"
                      value={primaryColor}
                      onChange={(e) => setPrimaryColor(e.target.value)}
                      dir="ltr"
                      className="flex-1 px-3 py-2 rounded-lg bg-slate-950 border border-slate-700 text-sm font-mono text-white"
                    />
                  </div>
                </div>

                <div>
                  <label className="block text-xs font-semibold text-slate-300 mb-2">
                    {t.defaultLocaleLabel}
                  </label>
                  <select
                    value={wsLocale}
                    onChange={(e) => setWsLocale(e.target.value as 'en' | 'ar')}
                    className="w-full px-3 py-2.5 rounded-lg bg-slate-950 border border-slate-700 text-sm text-white"
                  >
                    <option value="en">English (Default)</option>
                    <option value="ar">العربية (Arabic)</option>
                  </select>
                </div>

                <div>
                  <label className="block text-xs font-semibold text-slate-300 mb-2">
                    {t.timezoneLabel}
                  </label>
                  <input
                    type="text"
                    value={timezone}
                    onChange={(e) => setTimezone(e.target.value)}
                    dir="ltr"
                    className="w-full px-3 py-2.5 rounded-lg bg-slate-950 border border-slate-700 text-sm text-white"
                  />
                </div>
              </div>
            </div>
          )}

          {step === 2 && (
            <div className="space-y-5">
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div>
                  <label className="block text-xs font-semibold text-slate-300 mb-2">
                    {t.adminEmpNoLabel} *
                  </label>
                  <input
                    type="text"
                    value={employeeNo}
                    onChange={(e) => setEmployeeNo(e.target.value)}
                    dir="ltr"
                    placeholder="ADM-001"
                    className="w-full px-4 py-2.5 rounded-xl bg-slate-950 border border-slate-700 text-white font-mono"
                  />
                </div>
                <div>
                  <label className="block text-xs font-semibold text-slate-300 mb-2">
                    {t.adminNameLabel} *
                  </label>
                  <input
                    type="text"
                    value={adminName}
                    onChange={(e) => setAdminName(e.target.value)}
                    placeholder={locale === 'ar' ? 'م. طارق المنصور' : 'Tariq Al-Mansour'}
                    className="w-full px-4 py-2.5 rounded-xl bg-slate-950 border border-slate-700 text-white"
                  />
                </div>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div>
                  <label className="block text-xs font-semibold text-slate-300 mb-2">
                    {t.adminEmailLabel} *
                  </label>
                  <input
                    type="email"
                    value={adminEmail}
                    onChange={(e) => setAdminEmail(e.target.value)}
                    dir="ltr"
                    placeholder="admin@organization.gov"
                    className="w-full px-4 py-2.5 rounded-xl bg-slate-950 border border-slate-700 text-white"
                  />
                </div>
                <div>
                  <label className="block text-xs font-semibold text-slate-300 mb-2">
                    {t.adminTitleLabel}
                  </label>
                  <input
                    type="text"
                    value={adminTitle}
                    onChange={(e) => setAdminTitle(e.target.value)}
                    className="w-full px-4 py-2.5 rounded-xl bg-slate-950 border border-slate-700 text-white"
                  />
                </div>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 pt-2">
                <div>
                  <label className="block text-xs font-semibold text-slate-300 mb-2">
                    {t.adminPasswordLabel} *
                  </label>
                  <input
                    type="password"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    dir="ltr"
                    placeholder="••••••••••••"
                    className="w-full px-4 py-2.5 rounded-xl bg-slate-950 border border-slate-700 text-white"
                  />
                </div>
                <div>
                  <label className="block text-xs font-semibold text-slate-300 mb-2">
                    {t.adminPasswordConfirmLabel} *
                  </label>
                  <input
                    type="password"
                    value={confirmPassword}
                    onChange={(e) => setConfirmPassword(e.target.value)}
                    dir="ltr"
                    placeholder="••••••••••••"
                    className="w-full px-4 py-2.5 rounded-xl bg-slate-950 border border-slate-700 text-white"
                  />
                </div>
              </div>

              {/* Password Complexity Checklist */}
              <div className="p-4 rounded-xl bg-slate-950/90 border border-slate-800 grid grid-cols-2 sm:grid-cols-3 gap-2 text-xs">
                {[
                  { ok: pwChecks.minLen, label: locale === 'ar' ? '10 خانات على الأقل' : '10+ characters' },
                  { ok: pwChecks.upper, label: locale === 'ar' ? 'حرف كبير (A-Z)' : 'Uppercase (A-Z)' },
                  { ok: pwChecks.lower, label: locale === 'ar' ? 'حرف صغير (a-z)' : 'Lowercase (a-z)' },
                  { ok: pwChecks.digit, label: locale === 'ar' ? 'رقم (0-9)' : 'Number (0-9)' },
                  { ok: pwChecks.symbol, label: locale === 'ar' ? 'رمز خاص (!@#$)' : 'Symbol (!@#$)' },
                  { ok: pwChecks.match, label: locale === 'ar' ? 'تطابق كلمتي المرور' : 'Passwords match' },
                ].map((item, idx) => (
                  <div
                    key={idx}
                    className={`flex items-center gap-1.5 ${
                      item.ok ? 'text-teal-400 font-medium' : 'text-slate-500'
                    }`}
                  >
                    <CheckCircle2 className="w-3.5 h-3.5 shrink-0" />
                    <span>{item.label}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {step === 3 && (
            <div className="space-y-6">
              <div>
                <label className="block text-xs font-semibold uppercase tracking-wider text-slate-300 mb-3">
                  {t.policyPresetLabel}
                </label>
                <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                  {[
                    {
                      id: 'standard',
                      title: t.presetStandardTitle,
                      desc: t.presetStandardDesc,
                    },
                    {
                      id: 'regulated',
                      title: t.presetRegulatedTitle,
                      desc: t.presetRegulatedDesc,
                    },
                    {
                      id: 'defense',
                      title: t.presetDefenseTitle,
                      desc: t.presetDefenseDesc,
                    },
                  ].map((p) => (
                    <button
                      key={p.id}
                      type="button"
                      onClick={() => setPolicyPreset(p.id as any)}
                      className={`p-4 rounded-xl border text-start transition flex flex-col justify-between ${
                        policyPreset === p.id
                          ? 'bg-teal-950/50 border-teal-500 text-white'
                          : 'bg-slate-950/60 border-slate-800 text-slate-300 hover:border-slate-700'
                      }`}
                    >
                      <div>
                        <div className="font-bold text-sm mb-1.5 flex items-center justify-between">
                          <span>{p.title}</span>
                          {policyPreset === p.id && (
                            <CheckCircle2 className="w-4 h-4 text-teal-400 shrink-0" />
                          )}
                        </div>
                        <p className="text-xs text-slate-400 leading-relaxed">{p.desc}</p>
                      </div>
                    </button>
                  ))}
                </div>
              </div>

              <div>
                <div className="flex items-center justify-between mb-3">
                  <label className="block text-xs font-semibold uppercase tracking-wider text-slate-300">
                    {t.initialDeptsLabel}
                  </label>
                  <button
                    type="button"
                    onClick={() =>
                      setDepartments([...departments, { name: '', code: '' }])
                    }
                    className="inline-flex items-center gap-1 text-xs font-semibold text-teal-400 hover:text-teal-300"
                  >
                    <Plus className="w-3.5 h-3.5" />
                    {t.addDeptRow}
                  </button>
                </div>

                <div className="space-y-2.5">
                  {departments.map((dept, idx) => (
                    <div key={idx} className="flex items-center gap-2.5">
                      <input
                        type="text"
                        value={dept.name}
                        onChange={(e) => {
                          const next = [...departments];
                          next[idx] = { ...next[idx], name: e.target.value };
                          setDepartments(next);
                        }}
                        placeholder={t.deptNamePlaceholder}
                        className="flex-1 px-3.5 py-2 rounded-xl bg-slate-950 border border-slate-700 text-sm text-white"
                      />
                      <input
                        type="text"
                        value={dept.code}
                        onChange={(e) => {
                          const next = [...departments];
                          next[idx] = {
                            ...next[idx],
                            code: e.target.value.toUpperCase(),
                          };
                          setDepartments(next);
                        }}
                        dir="ltr"
                        placeholder={t.deptCodePlaceholder}
                        className="w-28 sm:w-36 px-3.5 py-2 rounded-xl bg-slate-950 border border-slate-700 text-sm font-mono text-teal-300"
                      />
                      {departments.length > 1 && (
                        <button
                          type="button"
                          onClick={() =>
                            setDepartments(departments.filter((_, i) => i !== idx))
                          }
                          className="p-2 rounded-lg bg-slate-800 hover:bg-rose-950 text-slate-400 hover:text-rose-300"
                        >
                          <Trash2 className="w-4 h-4" />
                        </button>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}

          {step === 4 && (
            <div className="space-y-6">
              <div className="p-5 rounded-xl bg-slate-950 border border-slate-800 space-y-4">
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 text-sm">
                  <div>
                    <span className="text-xs text-slate-400 block">
                      {t.orgNameLabel}
                    </span>
                    <span className="font-bold text-white text-base">
                      {workspaceName}
                    </span>
                  </div>
                  <div>
                    <span className="text-xs text-slate-400 block">
                      {t.serverUrlLabel}
                    </span>
                    <span className="font-mono text-teal-300 text-sm" dir="ltr">
                      {serverUrl}
                    </span>
                  </div>
                  <div>
                    <span className="text-xs text-slate-400 block">
                      {t.step2Title}
                    </span>
                    <span className="font-semibold text-white">
                      {adminName} ({employeeNo} • {adminEmail})
                    </span>
                  </div>
                  <div>
                    <span className="text-xs text-slate-400 block">
                      {t.policyPresetLabel}
                    </span>
                    <span className="uppercase font-mono text-amber-300 font-semibold">
                      {policyPreset}
                    </span>
                  </div>
                </div>

                <div className="pt-3 border-t border-slate-800">
                  <span className="text-xs text-slate-400 block mb-2">
                    {t.initialDeptsLabel} ({departments.filter((d) => d.name && d.code).length})
                  </span>
                  <div className="flex flex-wrap gap-2">
                    {departments
                      .filter((d) => d.name && d.code)
                      .map((d, i) => (
                        <span
                          key={i}
                          className="px-3 py-1 rounded-lg bg-slate-900 border border-slate-700 text-xs text-slate-200"
                        >
                          {d.name} <strong className="text-teal-400 font-mono">[{d.code}]</strong>
                        </span>
                      ))}
                  </div>
                </div>
              </div>

              <div className="p-4 rounded-xl bg-teal-950/30 border border-teal-500/30 flex items-start gap-3 text-xs text-teal-200 leading-relaxed">
                <Lock className="w-5 h-5 text-teal-400 shrink-0 mt-0.5" />
                <div>
                  {locale === 'ar'
                    ? 'تنبيه أمني: بمجرد النقر على زر الاعتماد أدناه، سيتم قفل صفحة التسجيل الأولي نهائياً، وتوليد مفاتيح التوقيع Ed25519 لمساحة العمل، وتسجيل دخولك تلقائياً في لوحة التحكم مع رمز QR جاهز لالتحاق الموظفين.'
                    : 'Security Notice: Clicking Initialize below permanently locks this first-time setup page, generates your Ed25519 workspace signing keys, signs you in as SUPER_ADMIN, and prepares your Employee Enrollment QR Code.'}
                </div>
              </div>
            </div>
          )}

          {/* Navigation Buttons */}
          <div className="mt-8 pt-5 border-t border-slate-800 flex items-center justify-between gap-4">
            {step > 1 ? (
              <button
                type="button"
                onClick={() => setStep(step - 1)}
                disabled={submitting}
                className="px-5 py-2.5 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-200 text-sm font-semibold transition"
              >
                {t.prevStep}
              </button>
            ) : (
              <div />
            )}

            {step < 4 ? (
              <button
                type="button"
                onClick={() => {
                  if (validateStep(step)) setStep(step + 1);
                }}
                className="px-6 py-2.5 rounded-xl bg-teal-500 hover:bg-teal-400 text-slate-950 text-sm font-bold transition shadow-lg shadow-teal-950/50"
              >
                {t.nextStep}
              </button>
            ) : (
              <button
                type="button"
                onClick={handleFinishSetup}
                disabled={submitting}
                className="inline-flex items-center gap-2 px-6 py-3 rounded-xl bg-teal-500 hover:bg-teal-400 disabled:opacity-50 text-slate-950 text-sm font-bold transition shadow-lg shadow-teal-950/50"
              >
                <KeyRound className="w-4 h-4" />
                {submitting ? t.completingSetup : t.completeSetupBtn}
              </button>
            )}
          </div>
        </div>
      </main>
    </div>
  );
}
