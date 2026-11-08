'use client';

import React, { createContext, useContext, useEffect, useState } from 'react';

export type Locale = 'en' | 'ar';

export const translations = {
  en: {
    appTitle: 'Madar Sovereign Admin Console',
    appSubtitle: 'Isolated Control-Plane BFF • Zero Direct DB Access',
    switchLang: 'العربية (RTL)',
    isolatedBadge: 'Isolated BFF • HttpOnly + CSRF',
    logout: 'Sign Out',
    refresh: 'Refresh Data',
    loading: 'Loading Madar Control Plane...',

    // Setup Wizard (First-Time Boot Only)
    setupBadge: 'First-Time Self-Hosted Deployment Wizard',
    setupTitle: 'Register Your Organization & Initial Super-Admin',
    setupDesc:
      'Welcome to your self-hosted Madar Workspace! Because this server was just deployed, please complete this one-time registration to initialize your organization, create your primary SUPER_ADMIN account, and generate your Employee Onboarding QR Code. Once completed, this registration page is permanently locked.',
    step1Title: '1. Organization Identity',
    step2Title: '2. Initial Super-Admin',
    step3Title: '3. Departments & Security Preset',
    step4Title: '4. Review & Launch Workspace',
    orgNameLabel: 'Organization / Workspace Name',
    orgNamePlaceholder: 'e.g., Madar Sovereign Technologies',
    serverUrlLabel: 'Public / LAN Server URL (used by Madar Agent QR Codes)',
    serverUrlHelp:
      'Enter the URL employees will use from their phones/laptops to reach madar_server (port 5025).',
    primaryColorLabel: 'Brand Primary Color',
    defaultLocaleLabel: 'Default Workspace Language',
    timezoneLabel: 'Organization Timezone',
    adminEmpNoLabel: 'Admin Employee ID / Username',
    adminNameLabel: 'Super-Admin Full Name',
    adminEmailLabel: 'Official Work Email',
    adminTitleLabel: 'Job Title',
    adminPasswordLabel: 'Master Password (min 10 chars, upper/lower/number/symbol)',
    adminPasswordConfirmLabel: 'Confirm Master Password',
    policyPresetLabel: 'Security & Compliance Policy Preset',
    presetStandardTitle: 'Standard Enterprise (Recommended)',
    presetStandardDesc:
      'Balanced security for daily collaboration. MFA required for admins, up to 3 devices per employee, copy/paste allowed.',
    presetRegulatedTitle: 'Regulated / Government Entity',
    presetRegulatedDesc:
      'Strict DLP controls: mandatory MFA for all users, copy/paste & external sharing locked, dynamic screen watermark enabled.',
    presetDefenseTitle: 'High-Security / Sovereign Defense',
    presetDefenseDesc:
      'Maximum lockdown: hardware device attestation required, 1 device per user, message deletion disabled, voice notes disabled.',
    initialDeptsLabel: 'Initial Organizational Departments (Auto-creates Official Channels)',
    addDeptRow: '+ Add Another Department',
    deptNamePlaceholder: 'Department Name (e.g. Engineering)',
    deptCodePlaceholder: 'Code (e.g. ENG)',
    nextStep: 'Continue',
    prevStep: 'Back',
    completeSetupBtn: 'Initialize Organization & Launch Console',
    completingSetup: 'Initializing Workspace & Signing Keys...',
    setupSuccessBanner:
      'Organization initialized! You are now signed in as SUPER_ADMIN and your initial Employee Enrollment QR Code is ready.',

    // Login Page
    loginTitle: 'Sign In to Admin Console',
    loginSubtitle:
      'Organization setup is complete. Enter your administrative Employee ID or Email to manage your workspace.',
    identifierLabel: 'Employee ID or Work Email',
    identifierPlaceholder: 'ADM-001 or admin@organization.gov',
    passwordLabel: 'Password',
    totpLabel: '2FA / TOTP Code (if enabled)',
    totpPlaceholder: '6-digit code (optional)',
    signInBtn: 'Sign In Securely',
    signingIn: 'Authenticating...',
    firstTimeCompletedBadge: 'Workspace Registered & Locked Against Re-Initialization',

    // Navigation Tabs
    tabOverview: 'Overview & Guide',
    tabEmployees: 'Employees & Directory',
    tabDepartments: 'Departments & Channels',
    tabOnboarding: 'Agent Onboarding & QR',
    tabDevices: 'Devices & Security',
    tabPolicies: 'Policy Engine (28)',
    tabBroadcasts: 'Official Broadcasts',
    tabCompliance: 'Compliance & Audit',

    // Guided Journey Checklist
    journeyTitle: 'Self-Hosted Onboarding Roadmap: From Deployment to Employee Sign-In',
    journeySubtitle:
      'Follow these 4 clear steps so your employees can sign in to the Madar Agent app on Mobile, Desktop, or Web.',
    jStep1Title: '1. Organization & Super-Admin Registered',
    jStep1Desc: 'Workspace Ed25519 signing keys, security preset, and initial SUPER_ADMIN are active.',
    jStep2Title: '2. Create Organizational Departments',
    jStep2Desc: 'Each department automatically gets an official Department Channel for its members.',
    jStep2Action: 'Manage Departments →',
    jStep3Title: '3. Provision Employee Accounts',
    jStep3Desc: 'Add employees individually with an initial password or bulk-import via CSV.',
    jStep3Action: 'Add Employees →',
    jStep4Title: '4. Connect Employees in Madar Agent',
    jStep4Desc: 'Share the Enrollment QR Code or Server URL + Employee ID so staff can sign in.',
    jStep4Action: 'Open Agent QR & Guide →',

    // KPIs
    kpiActiveUsers: 'Active Employees',
    kpiActiveDevices: 'Enrolled Devices',
    kpiDepartments: 'Departments',
    kpiChannels: 'Active Channels',
    kpiBroadcasts: 'Official Broadcasts',
    kpiDecisions: 'Logged Decisions',
    kpiLegalHolds: 'Active Legal Holds',
    kpiAuditChain: 'SHA-256 Audit Chain',
    auditValid: 'Verified Intact',
    auditInvalid: 'Tamper Alert',

    // Agent Onboarding & QR Tab
    agentGuideTitle: 'How Employees Sign In to Madar Agent (Mobile / Desktop / Web)',
    agentMethodATitle: 'Method A: Instant QR Code Enrollment (Fastest)',
    agentMethodAStep1: '1. Open the Madar Agent app and tap "Join Organization / Scan QR Code".',
    agentMethodAStep2:
      '2. Scan the signed JWS QR Code generated below (or paste the madar://enroll link).',
    agentMethodAStep3:
      '3. Enter Employee ID (e.g., EMP-101) and password (if prompted) — the device binds its Ed25519 key and joins department channels automatically!',
    agentMethodBTitle: 'Method B: Server URL + Employee Credentials',
    agentMethodBStep1: '1. Open the Madar Agent app and choose "Sign In with Workspace Server".',
    agentMethodBStep2:
      '2. Enter the Workspace Server URL (Port 5025) shown below — the app automatically verifies /.well-known/madar-workspace.json.',
    agentMethodBStep3:
      '3. Sign in using Employee ID / Work Email and the password you created in the Employees tab.',
    qrGeneratorTitle: 'Generate Signed JWS Enrollment Token & QR Code',
    qrTargetEmployee: 'Target Employee (Optional)',
    qrMultiUseOption: 'General Multi-Employee Onboarding Token (Anyone with valid ID)',
    qrMaxUses: 'Max Allowed Enrollments',
    qrExpiresHours: 'Validity (Hours)',
    qrGenerateBtn: 'Generate Signed QR & Token',
    qrLatestBoxTitle: 'Active Enrollment QR Code & Link',
    copyQrUri: 'Copy madar://enroll Link',
    copyTokenOnly: 'Copy Token Code',
    copied: 'Copied!',
  },
  ar: {
    appTitle: 'لوحة تحكم مدار السيادية (Admin Console)',
    appSubtitle: 'بوابة مستوى تحكم معزولة (BFF) • صفر وصول مباشر لقاعدة البيانات',
    switchLang: 'English (LTR)',
    isolatedBadge: 'معزولة أمنياً • HttpOnly + CSRF',
    logout: 'تسجيل الخروج',
    refresh: 'تحديث البيانات',
    loading: 'جارٍ تحميل لوحة التحكم السيادية...',

    // Setup Wizard (First-Time Boot Only)
    setupBadge: 'معالج التهيئة الأولية للاستضافة الذاتية (يظهر لأول مرة فقط)',
    setupTitle: 'تسجيل مساحة العمل وإنشاء حساب المدير العام الأول (Super Admin)',
    setupDesc:
      'مرحباً بك في بيئة مدار ذاتية الاستضافة! بما أنك تفتح لوحة التحكم لأول مرة بعد عملية النشر، يرجى إكمال هذه الخطوات لتسجيل اسم مساحة العمل وإنشاء حساب SUPER_ADMIN البدائي وتوليد رمز QR لالتحاق الموظفين. بمجرد الإتمام لن تظهر هذه الصفحة مجدداً.',
    step1Title: '1. هوية مساحة العمل والخادم',
    step2Title: '2. حساب المدير العام (Super Admin)',
    step3Title: '3. الأقسام والقالب الأمني',
    step4Title: '4. المراجعة وتدشين المنصة',
    orgNameLabel: 'اسم مساحة العمل',
    orgNamePlaceholder: 'مثال: شركة مدار للتقنيات السيادية',
    serverUrlLabel: 'رابط الخادم الرئيسي للموظفين (يُستخدم في رمز QR لتطبيق الموظفين)',
    serverUrlHelp:
      'أدخل عنوان خادم مدار (المنفذ 5025) الذي ستتصل به تطبيقات الموظفين (Madar Agent).',
    primaryColorLabel: 'اللون الرئيسي لمساحة العمل',
    defaultLocaleLabel: 'اللغة الافتراضية لمساحة العمل',
    timezoneLabel: 'المنطقة الزمنية',
    adminEmpNoLabel: 'الرقم الوظيفي / اسم المستخدم للمدير العام',
    adminNameLabel: 'الاسم الكامل للمدير العام',
    adminEmailLabel: 'البريد الإلكتروني الرسمي',
    adminTitleLabel: 'المسمى الوظيفي',
    adminPasswordLabel: 'كلمة المرور الرئيسية (10 خانات على الأقل تشمل حروفاً كبيرة وصغيرة ورقماً ورمزاً)',
    adminPasswordConfirmLabel: 'تأكيد كلمة المرور الرئيسية',
    policyPresetLabel: 'قالب السياسات الأمنية والامتثال الافتراضي',
    presetStandardTitle: 'قياسي لمساحات العمل (موصى به للبداية)',
    presetStandardDesc:
      'توازن مرن للعمل اليومي: تحقق ثنائي للمشرفين، حتى 3 أجهزة لكل موظف، السماح بالنسخ واللصق.',
    presetRegulatedTitle: 'جهات حكومية وتنظيمية (Regulated)',
    presetRegulatedDesc:
      'حماية صارمة من تسرب البيانات (DLP): تحقق ثنائي إلزامي للجميع، منع النسخ واللصق والمشاركة الخارجية، وتفعيل العلامة المائية.',
    presetDefenseTitle: 'أمن سيادي عالي الحساسية (Defense)',
    presetDefenseDesc:
      'أقصى درجات التقييد: اشتراط التحقق العتادي للجهاز، جهاز واحد فقط لكل موظف، منع حذف الرسائل ومنع الملاحظات الصوتية.',
    initialDeptsLabel: 'الأقسام والإدارات الأولية (يتم إنشاء قناة رسمية لكل قسم تلقائياً)',
    addDeptRow: '+ إضافة قسم آخر',
    deptNamePlaceholder: 'اسم القسم (مثال: إدارة تقنية المعلومات)',
    deptCodePlaceholder: 'الرمز (مثال: IT)',
    nextStep: 'الخطوة التالية',
    prevStep: 'السابق',
    completeSetupBtn: 'اعتماد تسجيل مساحة العمل وفتح لوحة التحكم',
    completingSetup: 'جارٍ تهيئة مساحة العمل وتوليد مفاتيح التوقيع...',
    setupSuccessBanner:
      'تم تسجيل مساحة العمل بنجاح! تم تسجيل دخولك تلقائياً بصلاحية SUPER_ADMIN وتجهيز رمز QR الأول لالتحاق الموظفين.',

    // Login Page
    loginTitle: 'تسجيل الدخول إلى لوحة تحكم مساحة العمل',
    loginSubtitle:
      'تم تسجيل مساحة العمل مسبقاً. أدخل الرقم الوظيفي أو البريد الإلكتروني لحساب المشرف لإدارة المنصة.',
    identifierLabel: 'الرقم الوظيفي أو البريد الإلكتروني',
    identifierPlaceholder: 'ADM-001 أو admin@organization.gov',
    passwordLabel: 'كلمة المرور',
    totpLabel: 'رمز التحقق الثنائي TOTP (إن كان مفعلاً)',
    totpPlaceholder: 'رمز من 6 أرقام (اختياري)',
    signInBtn: 'تسجيل الدخول الآمن',
    signingIn: 'جارٍ التحقق من الهوية...',
    firstTimeCompletedBadge: 'مساحة العمل مسجلة ومحمية ضد إعادة التهيئة العشوائية',

    // Navigation Tabs
    tabOverview: 'النظرة العامة ودليل التشغيل',
    tabEmployees: 'الموظفون ودليل مساحة العمل',
    tabDepartments: 'الأقسام والقنوات',
    tabOnboarding: 'ربط تطبيق الموظفين (QR)',
    tabDevices: 'الأجهزة والأمان',
    tabPolicies: 'محرك السياسات (28)',
    tabBroadcasts: 'التعاميم الرسمية',
    tabCompliance: 'الامتثال وسجل التدقيق',

    // Guided Journey Checklist
    journeyTitle: 'خارطة طريق جاهزية مساحة العمل: من الاستضافة الذاتية حتى دخول الموظفين في التطبيق',
    journeySubtitle:
      'اتبع هذه الخطوات الأربع المبسطة لتجهيز بيئة عملك وتمكين الموظفين من التسجيل في تطبيق Madar Agent.',
    jStep1Title: '1. تسجيل مساحة العمل وحساب Super Admin',
    jStep1Desc: 'مفاتيح التوقيع Ed25519 والقالب الأمني وحساب المدير العام مفعّلة وجاهزة.',
    jStep2Title: '2. إنشاء الأقسام والهيكل التنظيمي',
    jStep2Desc: 'كل قسم تنشئه يحصل تلقائياً على قناة رسمية ينضم إليها موظفو القسم.',
    jStep2Action: 'إدارة الأقسام ←',
    jStep3Title: '3. إضافة حسابات الموظفين',
    jStep3Desc: 'أضف الموظفين فردياً مع كلمة مرور أو استوردهم دفعة واحدة عبر ملف CSV.',
    jStep3Action: 'إضافة الموظفين ←',
    jStep4Title: '4. تسجيل دخول الموظفين في Madar Agent',
    jStep4Desc: 'شارك رمز QR أو رابط الخادم مع الموظفين لربط أجهزتهم والبدء بالتواصل.',
    jStep4Action: 'فتح رمز QR وتعليمات الموظفين ←',

    // KPIs
    kpiActiveUsers: 'الموظفون النشطون',
    kpiActiveDevices: 'الأجهزة المسجلة',
    kpiDepartments: 'الأقسام الإدارية',
    kpiChannels: 'القنوات النشطة',
    kpiBroadcasts: 'التعاميم المنشورة',
    kpiDecisions: 'القرارات الموثقة',
    kpiLegalHolds: 'أوامر التحفظ القانوني',
    kpiAuditChain: 'سلسلة التدقيق SHA-256',
    auditValid: 'سليمة وموثقة',
    auditInvalid: 'تنبيه تلاعب',

    // Agent Onboarding & QR Tab
    agentGuideTitle: 'كيف يسجل الموظفون دخولهم في تطبيق Madar Agent؟',
    agentMethodATitle: 'الطريقة الأولى: الالتحاق السريع عبر مسح رمز QR (الأسهل للموظفين)',
    agentMethodAStep1: '1. يفتح الموظف تطبيق Madar Agent ويختار "الالتحاق بمساحة عمل / مسح رمز QR".',
    agentMethodAStep2: '2. يمسح رمز QR الموقّع رقمياً أدناه (أو يلصق رابط madar://enroll).',
    agentMethodAStep3:
      '3. يدخل رقمه الوظيفي (مثل EMP-101) وكلمة المرور — فيتم توثيق الجهاز وانضمامه لقناة قسمه تلقائياً!',
    agentMethodBTitle: 'الطريقة الثانية: إدخال رابط الخادم + بيانات دخول مساحة العمل',
    agentMethodBStep1: '1. يفتح الموظف تطبيق Madar Agent ويختار "تسجيل الدخول عبر خادم مساحة العمل".',
    agentMethodBStep2:
      '2. يدخل رابط الخادم الرئيسي (المنفذ 5025) الموضح أدناه — يتحقق التطبيق تلقائياً من هوية مساحة العمل.',
    agentMethodBStep3:
      '3. يسجل الدخول برقمه الوظيفي أو بريده الإلكتروني وكلمة المرور المحددة له في تبويب الموظفين.',
    qrGeneratorTitle: 'إصدار رمز التحاق موقّع (JWS) وتوليد رمز QR للموظفين',
    qrTargetEmployee: 'تخصيص لموظف محدد (اختياري)',
    qrMultiUseOption: 'رمز التحاق عام لمساحة العمل (متعدد الاستخدام للموظفين)',
    qrMaxUses: 'الحد الأقصى لعدد الأجهزة/الموظفين',
    qrExpiresHours: 'مدة الصلاحية (بالساعات)',
    qrGenerateBtn: 'توليد رمز QR ورابط الالتحاق',
    qrLatestBoxTitle: 'رمز QR ورابط الالتحاق الجاهز للمشاركة مع الموظفين',
    copyQrUri: 'نسخ رابط madar://enroll',
    copyTokenOnly: 'نسخ رمز التوكن فقط',
    copied: 'تم النسخ!',
  },
} as const;

export type TranslationDict = {
  [K in keyof (typeof translations)['en']]: string;
};

interface I18nContextValue {
  locale: Locale;
  dir: 'ltr' | 'rtl';
  setLocale: (loc: Locale) => void;
  toggleLocale: () => void;
  t: TranslationDict;
}

const I18nContext = createContext<I18nContextValue>({
  locale: 'en',
  dir: 'ltr',
  setLocale: () => {},
  toggleLocale: () => {},
  t: translations.en,
});

export function I18nProvider({ children }: { children: React.ReactNode }) {
  // Default language is English ('en') as requested
  const [locale, setLocaleState] = useState<Locale>('en');

  useEffect(() => {
    const saved = typeof window !== 'undefined' ? window.localStorage.getItem('madar_admin_locale') : null;
    if (saved === 'ar' || saved === 'en') {
      setLocaleState(saved);
    }
  }, []);

  useEffect(() => {
    const dir = locale === 'ar' ? 'rtl' : 'ltr';
    if (typeof document !== 'undefined') {
      document.documentElement.lang = locale;
      document.documentElement.dir = dir;
    }
    if (typeof window !== 'undefined') {
      window.localStorage.setItem('madar_admin_locale', locale);
    }
  }, [locale]);

  const setLocale = (loc: Locale) => setLocaleState(loc);
  const toggleLocale = () => setLocaleState((prev) => (prev === 'en' ? 'ar' : 'en'));

  return (
    <I18nContext.Provider
      value={{
        locale,
        dir: locale === 'ar' ? 'rtl' : 'ltr',
        setLocale,
        toggleLocale,
        t: translations[locale],
      }}
    >
      {children}
    </I18nContext.Provider>
  );
}

export function useI18n() {
  return useContext(I18nContext);
}
