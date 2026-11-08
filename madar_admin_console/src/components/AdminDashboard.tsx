'use client';

import React, { useCallback, useEffect, useState } from 'react';
import { useI18n } from '@/lib/i18n';
import { bffFetch } from '@/lib/api-client';

interface AdminDashboardProps {
  currentUser: any;
  initialEnrollment?: {
    enrollment_token?: string;
    qr_uri?: string;
    server_url?: string;
    expires_at?: string;
    max_uses?: number;
  } | null;
  justCompletedSetup?: boolean;
  onLogout: () => void;
}

type TabKey =
  | 'overview'
  | 'employees'
  | 'departments'
  | 'onboarding'
  | 'devices'
  | 'policies'
  | 'broadcasts'
  | 'compliance'
  | 'cloud';

export function AdminDashboard({
  currentUser,
  initialEnrollment,
  justCompletedSetup = false,
  onLogout,
}: AdminDashboardProps) {
  const { t, locale, toggleLocale } = useI18n();
  const [activeTab, setActiveTab] = useState<TabKey>('overview');
  const [loading, setLoading] = useState(true);
  const [toast, setToast] = useState<{ type: 'success' | 'error'; text: string } | null>(null);

  // Dashboard state from madar_server via BFF
  const [overview, setOverview] = useState<any>(null);
  const [users, setUsers] = useState<any[]>([]);
  const [departments, setDepartments] = useState<any[]>([]);
  const [devices, setDevices] = useState<any[]>([]);
  const [policyCatalog, setPolicyCatalog] = useState<any[]>([]);
  const [policyValues, setPolicyValues] = useState<Record<string, any>>({});
  const [broadcasts, setBroadcasts] = useState<any[]>([]);
  const [legalHolds, setLegalHolds] = useState<any[]>([]);
  const [auditLogs, setAuditLogs] = useState<any[]>([]);
  const [auditVerification, setAuditVerification] = useState<any>(null);
  const [enrollmentTokens, setEnrollmentTokens] = useState<any[]>([]);
  const [channels, setChannels] = useState<any[]>([]);

  // Active QR state
  const [serverUrl, setServerUrl] = useState<string>('http://localhost:5025');
  const [activeQrUri, setActiveQrUri] = useState<string>(initialEnrollment?.qr_uri || '');
  const [activeTokenCode, setActiveTokenCode] = useState<string>(
    initialEnrollment?.enrollment_token || '',
  );
  const [copiedField, setCopiedField] = useState<string | null>(null);

  // Forms: Create Employee
  const [empNo, setEmpNo] = useState('');
  const [empName, setEmpName] = useState('');
  const [empEmail, setEmpEmail] = useState('');
  const [empTitle, setEmpTitle] = useState('');
  const [empDeptId, setEmpDeptId] = useState('');
  const [empRole, setEmpRole] = useState('MEMBER');
  const [empPassword, setEmpPassword] = useState('Employee@Madar2026!');
  const [csvUsersText, setCsvUsersText] = useState('');

  // Employee Edit & Password Reset state
  const [editingUser, setEditingUser] = useState<any | null>(null);
  const [editUserName, setEditUserName] = useState('');
  const [editUserEmail, setEditUserEmail] = useState('');
  const [editUserTitle, setEditUserTitle] = useState('');
  const [editUserDeptId, setEditUserDeptId] = useState('');
  const [editUserRole, setEditUserRole] = useState('MEMBER');
  const [resetPwdUser, setResetPwdUser] = useState<any | null>(null);
  const [resetPwdValue, setResetPwdValue] = useState('Employee@Madar2026!');

  // Forms: Create Department & Channel
  const [deptName, setDeptName] = useState('');
  const [deptCode, setDeptCode] = useState('');
  const [channelName, setChannelName] = useState('');
  const [channelDesc, setChannelDesc] = useState('');
  const [channelKind, setChannelKind] = useState<
    'project' | 'department' | 'cross_dept' | 'announcement'
  >('project');
  const [channelDeptId, setChannelDeptId] = useState('');
  const [channelAutoJoinAll, setChannelAutoJoinAll] = useState(true);

  // Forms: Generate QR Token
  const [qrTargetUserId, setQrTargetUserId] = useState('');
  const [qrMaxUses, setQrMaxUses] = useState(50);
  const [qrExpiresHours, setQrExpiresHours] = useState(72);

  // Forms: Official Broadcast
  const [bcTitle, setBcTitle] = useState('');
  const [bcBody, setBcBody] = useState('');
  const [bcAckRequired, setBcAckRequired] = useState(true);

  // Forms: Legal Hold & Audit Export
  const [lhName, setLhName] = useState('');
  const [lhReason, setLhReason] = useState('');
  const [ediscoveryResult, setEdiscoveryResult] = useState<string | null>(null);

  // Cloud Services & Enterprise Identity Providers (ADM-02, ENR-06, AUTH-01, AUTH-06)
  const [cloudServices, setCloudServices] = useState<any>(null);
  const [officialDomain, setOfficialDomain] = useState('');
  const [relayUrl, setRelayUrl] = useState('https://relay.madar.sa');
  const [pushRelayEnabled, setPushRelayEnabled] = useState(true);
  const [tenantToken, setTenantToken] = useState('');
  const [smsProvider, setSmsProvider] = useState<'madar_relay' | 'webhook' | 'console' | 'none'>('madar_relay');
  const [smsWebhookUrl, setSmsWebhookUrl] = useState('');
  const [authProviders, setAuthProviders] = useState<any[]>([]);
  const [idpKind, setIdpKind] = useState<'ldap' | 'oidc' | 'saml'>('ldap');
  const [idpName, setIdpName] = useState('Active Directory — مساحة العمل');
  const [idpConfigText, setIdpConfigText] = useState(
    '{\n  "ldap_url": "ldaps://ad.corp.local:636",\n  "base_dn": "dc=corp,dc=local",\n  "directory_entries": []\n}',
  );

  function extractErrorMsg(data: any, fallback: string): string {
    if (!data) return fallback;
    if (typeof data.error === 'string') return data.error;
    if (typeof data.error?.message === 'string') return data.error.message;
    if (typeof data.message === 'string') return data.message;
    return fallback;
  }

  function showMessage(type: 'success' | 'error', text: string) {
    setToast({ type, text });
    setTimeout(() => {
      setToast((prev) => (prev?.text === text ? null : prev));
    }, 5000);
  }

  useEffect(() => {
    if (typeof window !== 'undefined') {
      const host = window.location.hostname || 'localhost';
      const protocol = window.location.protocol || 'http:';
      setServerUrl(initialEnrollment?.server_url || `${protocol}//${host}:5025`);
    }
  }, [initialEnrollment]);

  const loadAllData = useCallback(async () => {
    setLoading(true);
    try {
      const [
        ovRes,
        usrRes,
        deptRes,
        chRes,
        devRes,
        polRes,
        bcRes,
        lhRes,
        audRes,
        verRes,
        tokRes,
      ] = await Promise.all([
        bffFetch('/admin-api/proxy/overview'),
        bffFetch('/admin-api/proxy/users'),
        bffFetch('/admin-api/proxy/departments'),
        bffFetch('/admin-api/proxy/admin/channels'),
        bffFetch('/admin-api/proxy/devices'),
        bffFetch('/admin-api/proxy/policies'),
        bffFetch('/admin-api/proxy/broadcasts'),
        bffFetch('/admin-api/proxy/legal-holds'),
        bffFetch('/admin-api/proxy/audit-log?limit=40'),
        bffFetch('/admin-api/proxy/audit-log/verify'),
        bffFetch('/admin-api/proxy/enrollment-tokens'),
      ]);

      if (ovRes.ok) setOverview(ovRes.data);
      if (usrRes.ok) setUsers(usrRes.data?.users || []);
      if (deptRes.ok) setDepartments(deptRes.data?.departments || []);
      if (chRes.ok) setChannels(chRes.data?.channels || []);
      if (devRes.ok) setDevices(devRes.data?.devices || []);
      if (polRes.ok) {
        const cat = Array.isArray(polRes.data?.catalog) ? polRes.data.catalog : [];
        const entries = Array.isArray(polRes.data?.entries) ? polRes.data.entries : [];
        setPolicyCatalog(cat);
        const merged: Record<string, any> = {};
        for (const item of cat) {
          merged[item.key] = item.defaultValue;
        }
        for (const ent of entries) {
          if (ent.scope_type === 'workspace') {
            merged[ent.key] = ent.value_json;
          }
        }
        setPolicyValues(merged);
      }
      if (bcRes.ok) setBroadcasts(bcRes.data?.broadcasts || []);
      if (lhRes.ok) setLegalHolds(lhRes.data?.legal_holds || []);
      if (audRes.ok) setAuditLogs(audRes.data?.entries || audRes.data?.audit_logs || []);
      if (verRes.ok) setAuditVerification(verRes.data?.verification || verRes.data);
      if (tokRes.ok) {
        setEnrollmentTokens(tokRes.data?.enrollment_tokens || tokRes.data?.tokens || []);
      }
      const [csRes, idpRes] = await Promise.all([
        bffFetch('/admin-api/proxy/cloud-services'),
        bffFetch('/admin-api/proxy/auth-providers'),
      ]);
      if (csRes.ok && csRes.data?.cloud_services) {
        const cs = csRes.data.cloud_services;
        setCloudServices(cs);
        setOfficialDomain(cs.official_domain || '');
        setRelayUrl(cs.relay_url || 'https://relay.madar.sa');
        setPushRelayEnabled(Boolean(cs.push_relay_enabled));
        setSmsProvider(cs.sms_provider || 'console');
        setSmsWebhookUrl(cs.sms_webhook_url || '');
      }
      if (idpRes.ok && Array.isArray(idpRes.data?.providers)) {
        setAuthProviders(idpRes.data.providers);
      }
    } catch (err: any) {
      showMessage('error', err?.message || 'Failed to load control-plane telemetry');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadAllData();
  }, [loadAllData]);

  const handleGenerateQr = async (overrideUserId?: string) => {
    const targetUser = overrideUserId !== undefined ? overrideUserId : qrTargetUserId;
    const res = await bffFetch('/admin-api/proxy/enrollment-tokens', {
      method: 'POST',
      body: {
        target_user_id: targetUser ? Number(targetUser) : null,
        max_uses: targetUser ? 1 : Number(qrMaxUses) || 50,
        expires_in_hours: Number(qrExpiresHours) || 72,
        server_url: serverUrl.trim(),
      },
    });

    if (!res.ok) {
      showMessage('error', extractErrorMsg(res.data, 'Failed to generate enrollment QR token'));
      return;
    }

    setActiveQrUri(res.data.qr_uri);
    setActiveTokenCode(res.data.enrollment_token);
    showMessage(
      'success',
      locale === 'ar'
        ? 'تم إصدار رمز QR الموقّع لالتحاق الموظفين بنجاح!'
        : 'Signed Employee Enrollment QR Code generated!',
    );
    loadAllData();
  };

  const handleCopy = (key: string, value: string) => {
    if (!value) return;
    navigator.clipboard.writeText(value);
    setCopiedField(key);
    setTimeout(() => setCopiedField(null), 2000);
  };

  const handleCreateDepartment = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!deptName.trim() || !deptCode.trim()) return;
    const res = await bffFetch('/admin-api/proxy/departments', {
      method: 'POST',
      body: {
        name: deptName.trim(),
        code: deptCode.trim().toUpperCase(),
      },
    });
    if (!res.ok) {
      showMessage('error', extractErrorMsg(res.data, 'Failed to create department'));
      return;
    }
    setDeptName('');
    setDeptCode('');
    showMessage(
      'success',
      locale === 'ar'
        ? 'تم إنشاء القسم وقناته الرسمية بنجاح!'
        : 'Department and its official channel created!',
    );
    loadAllData();
  };

  const handleDeleteDepartment = async (deptId: string, name: string) => {
    const res = await bffFetch(`/admin-api/proxy/departments/${deptId}`, {
      method: 'DELETE',
    });
    if (!res.ok) {
      showMessage('error', extractErrorMsg(res.data, 'Failed to delete department'));
      return;
    }
    showMessage(
      'success',
      locale === 'ar'
        ? `تم حذف القسم (${name}) وأرشفة قناته بنجاح`
        : `Department (${name}) deleted and channel archived`,
    );
    loadAllData();
  };

  const handleCreateChannel = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!channelName.trim()) return;
    const res = await bffFetch('/admin-api/proxy/admin/channels', {
      method: 'POST',
      body: {
        name: channelName.trim(),
        description: channelDesc.trim(),
        kind: channelKind,
        department_id: channelDeptId || null,
        auto_join_all: channelAutoJoinAll,
      },
    });
    if (!res.ok) {
      showMessage('error', extractErrorMsg(res.data, 'Failed to create channel'));
      return;
    }
    setChannelName('');
    setChannelDesc('');
    showMessage(
      'success',
      locale === 'ar'
        ? 'تم إنشاء قناة مساحة العمل بنجاح!'
        : 'Organizational channel created!',
    );
    loadAllData();
  };

  const handleToggleArchiveChannel = async (ch: any) => {
    const nextArchived = !ch.is_archived;
    const res = await bffFetch(`/admin-api/proxy/admin/channels/${ch.id}`, {
      method: 'PATCH',
      body: {
        is_archived: nextArchived,
      },
    });
    if (!res.ok) {
      showMessage('error', extractErrorMsg(res.data, 'Failed to update channel state'));
      return;
    }
    showMessage(
      'success',
      locale === 'ar'
        ? nextArchived
          ? `تمت أرشفة القناة (${ch.name})`
          : `تمت استعادة القناة (${ch.name})`
        : nextArchived
        ? `Channel (${ch.name}) archived`
        : `Channel (${ch.name}) restored`,
    );
    loadAllData();
  };

  const handleCreateEmployee = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!empNo.trim() || !empName.trim() || !empPassword) return;
    const res = await bffFetch('/admin-api/proxy/users', {
      method: 'POST',
      body: {
        employee_no: empNo.trim(),
        name: empName.trim(),
        email: empEmail.trim() || undefined,
        title: empTitle.trim() || 'Specialist',
        department_id: empDeptId || null,
        roles: [empRole],
        password: empPassword,
      },
    });
    if (!res.ok) {
      showMessage('error', extractErrorMsg(res.data, 'Failed to create employee account'));
      return;
    }
    setEmpNo('');
    setEmpName('');
    setEmpEmail('');
    setEmpTitle('');
    showMessage(
      'success',
      locale === 'ar'
        ? `تم إنشاء حساب الموظف (${res.data?.user?.employee_no}) وإضافته لقناة قسمه!`
        : `Employee (${res.data?.user?.employee_no}) provisioned and added to department channel!`,
    );
    loadAllData();
  };

  const handleCsvBulkImport = async () => {
    const lines = csvUsersText
      .split('\n')
      .map((l) => l.trim())
      .filter(Boolean);
    if (lines.length === 0) return;

    const parsed = lines.map((line, idx) => {
      const [employee_no, name, email, title, department_code, password] = line
        .split(',')
        .map((s) => s.trim());
      return {
        employee_no: employee_no || `EMP-${100 + idx}`,
        name: name || `Employee ${idx + 1}`,
        email: email || `emp${100 + idx}@madar.local`,
        title: title || 'Member',
        department_code: department_code || undefined,
        role: 'MEMBER',
        password: password || 'Employee@Madar2026!',
      };
    });

    const res = await bffFetch('/admin-api/proxy/users/import-csv', {
      method: 'POST',
      body: { users: parsed },
    });
    if (!res.ok) {
      showMessage('error', extractErrorMsg(res.data, 'Bulk import failed'));
      return;
    }
    setCsvUsersText('');
    showMessage(
      'success',
      locale === 'ar'
        ? `تم استيراد ${res.data?.imported_count || 0} موظف بنجاح!`
        : `Bulk imported ${res.data?.imported_count || 0} employees!`,
    );
    loadAllData();
  };

  const handleOpenEditUser = (u: any) => {
    setEditingUser(u);
    setEditUserName(u.name || u.full_name || '');
    setEditUserEmail(u.email || '');
    setEditUserTitle(u.title || 'Specialist');
    setEditUserDeptId(u.department_id || '');
    const firstRole = Array.isArray(u.roles) && u.roles.length > 0 ? u.roles[0] : u.role || 'MEMBER';
    setEditUserRole(firstRole);
  };

  const handleSaveUserEdit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!editingUser) return;
    const res = await bffFetch(`/admin-api/proxy/users/${editingUser.id}`, {
      method: 'PATCH',
      body: {
        name: editUserName.trim(),
        email: editUserEmail.trim() || null,
        title: editUserTitle.trim(),
        department_id: editUserDeptId || null,
        roles: [editUserRole],
      },
    });
    if (!res.ok) {
      showMessage('error', extractErrorMsg(res.data, 'Failed to update employee profile'));
      return;
    }
    setEditingUser(null);
    showMessage(
      'success',
      locale === 'ar'
        ? 'تم تحديث بيانات الموظف وصلاحياته بنجاح!'
        : 'Employee profile & department updated!',
    );
    loadAllData();
  };

  const handleResetUserPassword = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!resetPwdUser || !resetPwdValue.trim()) return;
    const res = await bffFetch(`/admin-api/proxy/users/${resetPwdUser.id}/reset-password`, {
      method: 'POST',
      body: {
        new_password: resetPwdValue.trim(),
      },
    });
    if (!res.ok) {
      showMessage('error', extractErrorMsg(res.data, 'Failed to reset employee password'));
      return;
    }
    setResetPwdUser(null);
    showMessage(
      'success',
      locale === 'ar'
        ? 'تم تعيين كلمة المرور الجديدة وإبطال الجلسات القديمة للموظف!'
        : 'Employee password reset and prior tokens invalidated!',
    );
    loadAllData();
  };

  const handleToggleUserStatus = async (u: any) => {
    const currentStatus = String(u.account_status || u.status || 'active').toLowerCase();
    const nextStatus = currentStatus === 'active' ? 'suspended' : 'active';
    const res = await bffFetch(`/admin-api/proxy/users/${u.id}`, {
      method: 'PATCH',
      body: {
        account_status: nextStatus,
      },
    });
    if (!res.ok) {
      showMessage('error', extractErrorMsg(res.data, 'Failed to update employee account status'));
      return;
    }
    showMessage(
      'success',
      locale === 'ar'
        ? nextStatus === 'suspended'
          ? 'تم تعليق حساب الموظف وإغلاق جلساته الفورية'
          : 'تم تفعيل حساب الموظف بنجاح'
        : nextStatus === 'suspended'
        ? 'Employee account suspended & active sessions revoked'
        : 'Employee account re-activated',
    );
    loadAllData();
  };

  const handleOffboardUser = async (userId: number) => {
    const res = await bffFetch(`/admin-api/proxy/users/${userId}/offboard`, {
      method: 'POST',
      body: { reason: 'Offboarded via Admin Console' },
    });
    if (!res.ok) {
      showMessage('error', extractErrorMsg(res.data, 'Failed to offboard employee'));
      return;
    }
    showMessage('success', 'Employee offboarded, sessions revoked, and devices marked for wipe');
    loadAllData();
  };

  const handleRevokeDevice = async (deviceId: string) => {
    const res = await bffFetch(`/admin-api/proxy/devices/${deviceId}/revoke`, {
      method: 'POST',
      body: { reason: 'Revoked by administrator via Admin Console' },
    });
    if (!res.ok) {
      showMessage('error', extractErrorMsg(res.data, 'Failed to revoke device'));
      return;
    }
    showMessage('success', 'Device session & key revoked immediately');
    loadAllData();
  };

  const handleWipeDevice = async (deviceId: string) => {
    const res = await bffFetch(`/admin-api/proxy/devices/${deviceId}/wipe`, {
      method: 'POST',
      body: { reason: 'Remote selective wipe issued via Admin Console' },
    });
    if (!res.ok) {
      showMessage('error', extractErrorMsg(res.data, 'Failed to issue remote wipe'));
      return;
    }
    showMessage('success', `Remote wipe command (${res.data?.wipe_command_id}) dispatched`);
    loadAllData();
  };

  const handlePublishPolicyChange = async (key: string, nextValue: any) => {
    const res = await bffFetch('/admin-api/proxy/policies', {
      method: 'PUT',
      body: {
        scope_type: 'workspace',
        reason: `Updated ${key} via Admin Console`,
        changes: [{ key, value: nextValue, locked: false }],
      },
    });
    if (!res.ok) {
      showMessage('error', extractErrorMsg(res.data, 'Failed to publish policy update'));
      return;
    }
    setPolicyValues((prev) => ({ ...prev, [key]: nextValue }));
    showMessage(
      'success',
      locale === 'ar'
        ? `تم نشر السياسة وتوقيعها (الإصدار v${res.data?.version}): ${key}`
        : `Published & signed policy v${res.data?.version}: ${key}`,
    );
  };

  const handlePublishBroadcast = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!bcTitle.trim() || !bcBody.trim()) return;
    const res = await bffFetch('/admin-api/proxy/broadcasts', {
      method: 'POST',
      body: {
        title: bcTitle.trim(),
        body: bcBody.trim(),
        ack_required: bcAckRequired,
        priority: 'high',
        target_spec: { scope: 'all' },
      },
    });
    if (!res.ok) {
      showMessage('error', extractErrorMsg(res.data, 'Failed to publish broadcast'));
      return;
    }
    setBcTitle('');
    setBcBody('');
    showMessage(
      'success',
      locale === 'ar' ? 'تم نشر التعميم الرسمي بنجاح!' : 'Official Broadcast published!',
    );
    loadAllData();
  };

  const handleCreateLegalHold = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!lhName.trim() || !lhReason.trim()) return;
    const res = await bffFetch('/admin-api/proxy/legal-holds', {
      method: 'POST',
      body: {
        scope_type: 'user',
        scope_id: String(currentUser?.id || 1),
        matter_ref: lhName.trim(),
        reason: lhReason.trim(),
      },
    });
    if (!res.ok) {
      showMessage('error', extractErrorMsg(res.data, 'Failed to create Legal Hold'));
      return;
    }
    setLhName('');
    setLhReason('');
    showMessage('success', 'Sovereign Legal Hold activated');
    loadAllData();
  };

  const handleExportAuditBundle = async (format: 'json' | 'csv') => {
    const res = await bffFetch(`/admin-api/proxy/audit-log/export?format=${format}`);
    if (!res.ok) {
      showMessage('error', extractErrorMsg(res.data, 'Failed to export audit bundle'));
      return;
    }
    setEdiscoveryResult(
      typeof res.data === 'string' ? res.data : JSON.stringify(res.data, null, 2),
    );
    showMessage('success', `Exported tamper-evident ${format.toUpperCase()} audit bundle`);
  };

  const handleSaveCloudServices = async (e: React.FormEvent) => {
    e.preventDefault();
    const res = await bffFetch('/admin-api/proxy/cloud-services', {
      method: 'PUT',
      body: {
        official_domain: officialDomain.trim(),
        push_relay_enabled: pushRelayEnabled,
        relay_url: relayUrl.trim(),
        ...(tenantToken.trim() ? { tenant_token: tenantToken.trim() } : {}),
        sms_provider: smsProvider,
        sms_webhook_url: smsWebhookUrl.trim(),
      },
    });
    if (!res.ok) {
      showMessage('error', extractErrorMsg(res.data, 'Failed to update cloud services'));
      return;
    }
    setTenantToken('');
    showMessage(
      'success',
      locale === 'ar'
        ? 'تم حفظ إعدادات السحابة الوسيطة (madar-relay) والنطاق الرسمي بنجاح!'
        : 'Cloud Relay & Domain settings saved!',
    );
    loadAllData();
  };

  const handleVerifyDomain = async () => {
    const res = await bffFetch('/admin-api/proxy/cloud-services/verify-domain', {
      method: 'POST',
      body: {
        simulated_txt_record: cloudServices?.dns_txt_expected,
      },
    });
    if (!res.ok) {
      showMessage('error', extractErrorMsg(res.data, 'Domain verification failed'));
      return;
    }
    showMessage(
      'success',
      locale === 'ar'
        ? 'تم التحقق من ملكية النطاق الرسمي عبر DNS TXT بنجاح!'
        : 'Official domain verified via DNS TXT!',
    );
    loadAllData();
  };

  const handleCreateAuthProvider = async (e: React.FormEvent) => {
    e.preventDefault();
    let parsedConfig: Record<string, any> = {};
    try {
      parsedConfig = JSON.parse(idpConfigText || '{}');
    } catch {
      showMessage('error', 'صيغة JSON لإعدادات مزود الهوية غير صالحة');
      return;
    }
    const res = await bffFetch('/admin-api/proxy/auth-providers', {
      method: 'POST',
      body: {
        kind: idpKind,
        name: idpName.trim(),
        enabled: true,
        sync_interval_minutes: 15,
        config: parsedConfig,
      },
    });
    if (!res.ok) {
      showMessage('error', extractErrorMsg(res.data, 'Failed to create Identity Provider'));
      return;
    }
    showMessage(
      'success',
      locale === 'ar'
        ? 'تم ربط مزود هوية مساحة العمل (OIDC / SAML / LDAP) بنجاح!'
        : 'Enterprise Identity Provider registered!',
    );
    loadAllData();
  };

  const handleSyncAuthProvider = async (providerId: string) => {
    const res = await bffFetch(`/admin-api/proxy/auth-providers/${providerId}/sync`, {
      method: 'POST',
      body: {},
    });
    if (!res.ok) {
      showMessage('error', extractErrorMsg(res.data, 'Directory sync failed'));
      return;
    }
    showMessage(
      'success',
      locale === 'ar'
        ? `تمت مزامنة الدليل النشط بنجاح (جدد: ${res.data?.sync?.provisioned_count ?? 0}، معطل: ${res.data?.sync?.disabled_count ?? 0})`
        : 'Directory synchronization completed!',
    );
    loadAllData();
  };

  const hasDepartments = departments.length > 0;
  const hasEmployees = users.length > 1;
  const hasEnrolledQrOrDevice =
    Boolean(activeQrUri) || enrollmentTokens.length > 0 || devices.length > 1;

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col">
      {/* Top Sovereign Bar */}
      <header className="sticky top-0 z-30 border-b border-slate-800 bg-slate-900/90 backdrop-blur px-6 py-3.5 flex flex-wrap items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <div
            className="w-10 h-10 rounded-xl flex items-center justify-center font-bold text-white shadow-lg"
            style={{ backgroundColor: overview?.workspace?.primary_color || '#14b8a6' }}
          >
            M
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h1 className="font-bold text-base text-white">
                {overview?.workspace?.name || t.appTitle}
              </h1>
              <span className="px-2 py-0.5 rounded-md text-[10px] font-bold bg-teal-500/15 text-teal-300 border border-teal-500/30">
                {(currentUser?.roles && currentUser.roles[0]) || currentUser?.role || 'SUPER_ADMIN'}
              </span>
            </div>
            <p className="text-xs text-slate-400">
              {currentUser?.name || currentUser?.full_name} (
              {currentUser?.employee_no || currentUser?.employee_number || 'ADMIN'}) •{' '}
              {t.isolatedBadge}
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2.5">
          <button
            type="button"
            onClick={loadAllData}
            className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 border border-slate-700 text-xs font-medium text-slate-200 transition"
          >
            ↻ {t.refresh}
          </button>
          <button
            type="button"
            onClick={toggleLocale}
            className="px-3.5 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 border border-slate-700 text-xs font-semibold text-teal-300 transition"
          >
            {t.switchLang}
          </button>
          <button
            type="button"
            onClick={onLogout}
            className="px-3.5 py-1.5 rounded-lg bg-rose-500/15 hover:bg-rose-500/25 border border-rose-500/30 text-xs font-semibold text-rose-300 transition"
          >
            {t.logout}
          </button>
        </div>
      </header>

      {/* Toast Notification */}
      {toast && (
        <div className="mx-6 mt-4">
          <div
            className={`px-4 py-3 rounded-xl text-xs font-semibold border flex items-center justify-between ${
              toast.type === 'success'
                ? 'bg-emerald-500/15 border-emerald-500/40 text-emerald-200'
                : 'bg-rose-500/15 border-rose-500/40 text-rose-200'
            }`}
          >
            <span>{toast.text}</span>
            <button onClick={() => setToast(null)} className="text-slate-400 hover:text-white">
              ✕
            </button>
          </div>
        </div>
      )}

      {/* Celebratory Banner right after completing First-Time Setup */}
      {justCompletedSetup && (
        <div className="mx-6 mt-4 p-4 rounded-2xl bg-gradient-to-r from-teal-500/20 via-emerald-500/15 to-slate-900 border border-teal-500/40 flex flex-wrap items-center justify-between gap-4">
          <div className="space-y-1">
            <span className="inline-flex items-center gap-1.5 text-xs font-bold text-teal-300">
              ★ {t.setupSuccessBanner}
            </span>
            <p className="text-xs text-slate-300">
              {locale === 'ar'
                ? 'اتبع خارطة الطريق أدناه لإضافة الأقسام والموظفين ومشاركة رمز QR لتسجيل دخولهم في تطبيق Madar Agent.'
                : 'Follow the interactive roadmap below to add departments, provision employees, and share the QR code for Madar Agent sign-in.'}
            </p>
          </div>
          <button
            type="button"
            onClick={() => setActiveTab('onboarding')}
            className="px-4 py-2 rounded-xl bg-teal-500 hover:bg-teal-400 text-slate-950 font-bold text-xs transition"
          >
            {t.jStep4Action}
          </button>
        </div>
      )}

      {/* Navigation Tabs */}
      <nav className="px-6 pt-4 border-b border-slate-800 bg-slate-900/40 flex items-center gap-2 overflow-x-auto">
        {(
          [
            { id: 'overview', label: t.tabOverview },
            { id: 'departments', label: `${t.tabDepartments} (${departments.length})` },
            { id: 'employees', label: `${t.tabEmployees} (${users.length})` },
            { id: 'onboarding', label: `★ ${t.tabOnboarding}` },
            { id: 'devices', label: `${t.tabDevices} (${devices.length})` },
            { id: 'policies', label: t.tabPolicies },
            { id: 'broadcasts', label: `${t.tabBroadcasts} (${broadcasts.length})` },
            { id: 'compliance', label: t.tabCompliance },
            {
              id: 'cloud',
              label: locale === 'ar' ? '☁ الخدمات السحابية والهوية' : '☁ Cloud Relay & SSO',
            },
          ] as { id: TabKey; label: string }[]
        ).map((tab) => {
          const isActive = activeTab === tab.id;
          return (
            <button
              key={tab.id}
              type="button"
              onClick={() => setActiveTab(tab.id)}
              className={`px-4 py-2.5 text-xs font-semibold rounded-t-xl border-b-2 whitespace-nowrap transition ${
                isActive
                  ? 'border-teal-400 text-teal-300 bg-slate-900'
                  : 'border-transparent text-slate-400 hover:text-slate-200 hover:bg-slate-900/50'
              }`}
            >
              {tab.label}
            </button>
          );
        })}
      </nav>

      {/* Main Content Area */}
      <main className="flex-1 p-6 max-w-7xl w-full mx-auto space-y-6">
        {/* TAB 1: OVERVIEW & INTERACTIVE SELF-HOSTED ONBOARDING ROADMAP */}
        {activeTab === 'overview' && (
          <div className="space-y-6">
            <section className="bg-slate-900 border border-slate-800 rounded-2xl p-6 shadow-xl">
              <div className="flex flex-wrap items-center justify-between gap-4 mb-5">
                <div>
                  <h2 className="text-lg font-bold text-white">{t.journeyTitle}</h2>
                  <p className="text-xs text-slate-400 mt-1">{t.journeySubtitle}</p>
                </div>
                <span className="px-3 py-1 rounded-full text-xs font-semibold bg-teal-500/15 text-teal-300 border border-teal-500/30">
                  {[true, hasDepartments, hasEmployees, hasEnrolledQrOrDevice].filter(Boolean)
                    .length}{' '}
                  / 4 {locale === 'ar' ? 'خطوات مكتملة' : 'Steps Ready'}
                </span>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
                {/* Step 1: Organization Registered */}
                <div className="p-4 rounded-xl bg-slate-950/80 border border-emerald-500/40 flex flex-col justify-between">
                  <div>
                    <div className="flex items-center justify-between mb-2">
                      <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-500/20 text-emerald-300">
                        ✓ {locale === 'ar' ? 'مكتمل' : 'Completed'}
                      </span>
                      <span className="text-xs font-mono text-slate-500">STEP 01</span>
                    </div>
                    <h3 className="font-bold text-sm text-white">{t.jStep1Title}</h3>
                    <p className="text-xs text-slate-400 mt-1.5 leading-relaxed">{t.jStep1Desc}</p>
                  </div>
                  <div className="mt-4 pt-3 border-t border-slate-800/80 text-[11px] text-emerald-400 font-medium">
                    {overview?.workspace?.name || 'Workspace Active'}
                  </div>
                </div>

                {/* Step 2: Create Departments */}
                <div
                  className={`p-4 rounded-xl bg-slate-950/80 border flex flex-col justify-between ${
                    hasDepartments ? 'border-emerald-500/40' : 'border-amber-500/40'
                  }`}
                >
                  <div>
                    <div className="flex items-center justify-between mb-2">
                      <span
                        className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                          hasDepartments
                            ? 'bg-emerald-500/20 text-emerald-300'
                            : 'bg-amber-500/20 text-amber-300'
                        }`}
                      >
                        {hasDepartments
                          ? `✓ ${departments.length} ${locale === 'ar' ? 'أقسام' : 'Depts'}`
                          : locale === 'ar'
                            ? 'الخطوة التالية'
                            : 'Action Recommended'}
                      </span>
                      <span className="text-xs font-mono text-slate-500">STEP 02</span>
                    </div>
                    <h3 className="font-bold text-sm text-white">{t.jStep2Title}</h3>
                    <p className="text-xs text-slate-400 mt-1.5 leading-relaxed">{t.jStep2Desc}</p>
                  </div>
                  <button
                    type="button"
                    onClick={() => setActiveTab('departments')}
                    className="mt-4 w-full py-2 px-3 rounded-lg bg-slate-800 hover:bg-slate-700 text-teal-300 text-xs font-semibold transition text-center"
                  >
                    {t.jStep2Action}
                  </button>
                </div>

                {/* Step 3: Add Employees */}
                <div
                  className={`p-4 rounded-xl bg-slate-950/80 border flex flex-col justify-between ${
                    hasEmployees ? 'border-emerald-500/40' : 'border-amber-500/40'
                  }`}
                >
                  <div>
                    <div className="flex items-center justify-between mb-2">
                      <span
                        className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                          hasEmployees
                            ? 'bg-emerald-500/20 text-emerald-300'
                            : 'bg-amber-500/20 text-amber-300'
                        }`}
                      >
                        {hasEmployees
                          ? `✓ ${users.length} ${locale === 'ar' ? 'حسابات' : 'Users'}`
                          : locale === 'ar'
                            ? 'أضف الموظفين'
                            : 'Add Staff'}
                      </span>
                      <span className="text-xs font-mono text-slate-500">STEP 03</span>
                    </div>
                    <h3 className="font-bold text-sm text-white">{t.jStep3Title}</h3>
                    <p className="text-xs text-slate-400 mt-1.5 leading-relaxed">{t.jStep3Desc}</p>
                  </div>
                  <button
                    type="button"
                    onClick={() => setActiveTab('employees')}
                    className="mt-4 w-full py-2 px-3 rounded-lg bg-slate-800 hover:bg-slate-700 text-teal-300 text-xs font-semibold transition text-center"
                  >
                    {t.jStep3Action}
                  </button>
                </div>

                {/* Step 4: Employee Sign-In to Madar Agent */}
                <div className="p-4 rounded-xl bg-slate-950/80 border border-teal-500/40 flex flex-col justify-between">
                  <div>
                    <div className="flex items-center justify-between mb-2">
                      <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-teal-500/20 text-teal-300">
                        ★ {locale === 'ar' ? 'جاهز للموظفين' : 'Ready for Agent'}
                      </span>
                      <span className="text-xs font-mono text-slate-500">STEP 04</span>
                    </div>
                    <h3 className="font-bold text-sm text-white">{t.jStep4Title}</h3>
                    <p className="text-xs text-slate-400 mt-1.5 leading-relaxed">{t.jStep4Desc}</p>
                  </div>
                  <button
                    type="button"
                    onClick={() => setActiveTab('onboarding')}
                    className="mt-4 w-full py-2 px-3 rounded-lg bg-teal-500 hover:bg-teal-400 text-slate-950 text-xs font-bold transition text-center"
                  >
                    {t.jStep4Action}
                  </button>
                </div>
              </div>
            </section>

            {/* KPI Grid */}
            <section className="grid grid-cols-2 sm:grid-cols-4 gap-4">
              {[
                { label: t.kpiActiveUsers, value: overview?.kpis?.active_users ?? users.length },
                {
                  label: t.kpiActiveDevices,
                  value: overview?.kpis?.active_devices ?? devices.length,
                },
                {
                  label: t.kpiDepartments,
                  value: overview?.kpis?.departments ?? departments.length,
                },
                { label: t.kpiChannels, value: overview?.kpis?.active_channels ?? 0 },
                {
                  label: t.kpiBroadcasts,
                  value: overview?.kpis?.broadcasts ?? broadcasts.length,
                },
                { label: t.kpiDecisions, value: overview?.kpis?.active_decisions ?? 0 },
                {
                  label: t.kpiLegalHolds,
                  value: overview?.kpis?.active_legal_holds ?? legalHolds.length,
                },
                {
                  label: t.kpiAuditChain,
                  value:
                    auditVerification?.valid !== false ? `✓ ${t.auditValid}` : `⚠ ${t.auditInvalid}`,
                  highlight: auditVerification?.valid !== false ? 'text-emerald-400' : 'text-rose-400',
                },
              ].map((kpi, idx) => (
                <div
                  key={idx}
                  className="bg-slate-900 border border-slate-800 rounded-2xl p-4 shadow"
                >
                  <div className="text-xs text-slate-400">{kpi.label}</div>
                  <div className={`text-2xl font-bold mt-1.5 ${kpi.highlight || 'text-white'}`}>
                    {loading && overview === null ? '...' : kpi.value}
                  </div>
                </div>
              ))}
            </section>
          </div>
        )}

        {/* TAB 2: DEPARTMENTS & OFFICIAL CHANNELS */}
        {activeTab === 'departments' && (
          <div className="space-y-6">
            {/* Row 1: Departments Management */}
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
              <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6">
                <h3 className="font-bold text-base text-white mb-1">
                  {locale === 'ar' ? 'إنشاء قسم تنظيمي جديد' : 'Create Organizational Department'}
                </h3>
                <p className="text-xs text-slate-400 mb-4">
                  {locale === 'ar'
                    ? 'يتم تلقائياً إنشاء قناة رسمية للقسم وإضافة موظفي القسم إليها.'
                    : 'Automatically provisions an official Department Channel for its members.'}
                </p>
                <form onSubmit={handleCreateDepartment} className="space-y-4">
                  <div>
                    <label className="block text-xs font-semibold text-slate-300 mb-1">
                      {t.deptNamePlaceholder}
                    </label>
                    <input
                      type="text"
                      value={deptName}
                      onChange={(e) => setDeptName(e.target.value)}
                      placeholder={t.deptNamePlaceholder}
                      className="w-full px-3.5 py-2 rounded-xl bg-slate-950 border border-slate-800 text-sm text-white"
                    />
                  </div>
                  <div>
                    <label className="block text-xs font-semibold text-slate-300 mb-1">
                      {t.deptCodePlaceholder}
                    </label>
                    <input
                      type="text"
                      value={deptCode}
                      onChange={(e) => setDeptCode(e.target.value.toUpperCase())}
                      placeholder="ENG / IT / HR / FIN"
                      className="w-full px-3.5 py-2 rounded-xl bg-slate-950 border border-slate-800 text-sm font-mono text-white"
                    />
                  </div>
                  <button
                    type="submit"
                    className="w-full py-2.5 rounded-xl bg-teal-500 hover:bg-teal-400 text-slate-950 font-bold text-xs transition"
                  >
                    + {locale === 'ar' ? 'إنشاء القسم والقناة الرسمية' : 'Create Department & Channel'}
                  </button>
                </form>
              </div>

              <div className="lg:col-span-2 bg-slate-900 border border-slate-800 rounded-2xl p-6">
                <h3 className="font-bold text-base text-white mb-4">
                  {locale === 'ar' ? 'الأقسام الإدارية المسجلة' : 'Registered Departments'} (
                  {departments.length})
                </h3>
                <div className="overflow-x-auto">
                  <table className="w-full text-xs">
                    <thead>
                      <tr className="border-b border-slate-800 text-slate-400">
                        <th className="py-2.5 px-3 text-start">Code</th>
                        <th className="py-2.5 px-3 text-start">Department Name</th>
                        <th className="py-2.5 px-3 text-start">Members</th>
                        <th className="py-2.5 px-3 text-start">Official Channel ID</th>
                        <th className="py-2.5 px-3 text-end">Actions</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800/60">
                      {departments.map((d) => (
                        <tr key={d.id}>
                          <td className="py-3 px-3 font-mono font-bold text-teal-300">{d.code}</td>
                          <td className="py-3 px-3 font-semibold text-white">{d.name}</td>
                          <td className="py-3 px-3 text-slate-300">{d.member_count ?? 0}</td>
                          <td className="py-3 px-3 font-mono text-[11px] text-slate-400">
                            {d.channel_id || '—'}
                          </td>
                          <td className="py-3 px-3 text-end">
                            <button
                              type="button"
                              onClick={() => handleDeleteDepartment(d.id, d.name)}
                              className="px-2.5 py-1 rounded-lg bg-rose-500/15 hover:bg-rose-500/25 text-rose-300 font-semibold text-[11px]"
                            >
                              {locale === 'ar' ? 'حذف القسم' : 'Delete'}
                            </button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>

            {/* Row 2: Organizational Channels Management */}
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
              <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6">
                <h3 className="font-bold text-base text-white mb-1">
                  {locale === 'ar'
                    ? 'إنشاء قناة تواصل رسمية'
                    : 'Create Organizational Channel'}
                </h3>
                <p className="text-xs text-slate-400 mb-4">
                  {locale === 'ar'
                    ? 'أنشئ قنوات للمشاريع أو اللجان المشتركة أو الإعلانات مع إمكانية ضم كافة الموظفين تلقائياً.'
                    : 'Provision project, cross-department, or announcement channels for your workspace.'}
                </p>
                <form onSubmit={handleCreateChannel} className="space-y-3.5">
                  <div>
                    <label className="block text-xs font-semibold text-slate-300 mb-1">
                      {locale === 'ar' ? 'اسم القناة *' : 'Channel Name *'}
                    </label>
                    <input
                      type="text"
                      value={channelName}
                      onChange={(e) => setChannelName(e.target.value)}
                      placeholder={
                        locale === 'ar'
                          ? 'غرفة عمليات الإطلاق / لجنة الأمن السيبراني'
                          : 'Security Operations / Project Alpha'
                      }
                      className="w-full px-3.5 py-2 rounded-xl bg-slate-950 border border-slate-800 text-xs text-white"
                    />
                  </div>
                  <div>
                    <label className="block text-xs font-semibold text-slate-300 mb-1">
                      {locale === 'ar' ? 'وصف القناة' : 'Description'}
                    </label>
                    <input
                      type="text"
                      value={channelDesc}
                      onChange={(e) => setChannelDesc(e.target.value)}
                      placeholder={
                        locale === 'ar'
                          ? 'مناقشة القرارات والمتابعات التنفيذية'
                          : 'Decisions, follow-ups, and operational updates'
                      }
                      className="w-full px-3.5 py-2 rounded-xl bg-slate-950 border border-slate-800 text-xs text-white"
                    />
                  </div>
                  <div className="grid grid-cols-2 gap-3">
                    <div>
                      <label className="block text-xs font-semibold text-slate-300 mb-1">
                        {locale === 'ar' ? 'نوع القناة' : 'Channel Kind'}
                      </label>
                      <select
                        value={channelKind}
                        onChange={(e) => setChannelKind(e.target.value as any)}
                        className="w-full px-3 py-2 rounded-xl bg-slate-950 border border-slate-800 text-xs text-white"
                      >
                        <option value="project">Project (مشروع)</option>
                        <option value="cross_dept">Cross-Dept (مشتركة)</option>
                        <option value="department">Department (قسم)</option>
                        <option value="announcement">Announcement (إعلانات)</option>
                      </select>
                    </div>
                    <div>
                      <label className="block text-xs font-semibold text-slate-300 mb-1">
                        {locale === 'ar' ? 'القسم المرتبط (اختياري)' : 'Department (Optional)'}
                      </label>
                      <select
                        value={channelDeptId}
                        onChange={(e) => setChannelDeptId(e.target.value)}
                        className="w-full px-3 py-2 rounded-xl bg-slate-950 border border-slate-800 text-xs text-white"
                      >
                        <option value="">{locale === 'ar' ? 'عام لمساحة العمل' : 'Workspace-wide'}</option>
                        {departments.map((d) => (
                          <option key={d.id} value={d.id}>
                            {d.name} ({d.code})
                          </option>
                        ))}
                      </select>
                    </div>
                  </div>
                  <label className="flex items-center gap-2 text-xs text-slate-300 cursor-pointer pt-1">
                    <input
                      type="checkbox"
                      checked={channelAutoJoinAll}
                      onChange={(e) => setChannelAutoJoinAll(e.target.checked)}
                      className="rounded border-slate-700 bg-slate-950 text-teal-500"
                    />
                    <span>
                      {locale === 'ar'
                        ? 'إضافة جميع موظفي مساحة العمل النشطين تلقائياً'
                        : 'Auto-join all active workspace employees'}
                    </span>
                  </label>
                  <button
                    type="submit"
                    className="w-full py-2.5 rounded-xl bg-indigo-500 hover:bg-indigo-400 text-white font-bold text-xs transition"
                  >
                    + {locale === 'ar' ? 'إنشاء قناة مساحة العمل' : 'Create Organizational Channel'}
                  </button>
                </form>
              </div>

              <div className="lg:col-span-2 bg-slate-900 border border-slate-800 rounded-2xl p-6">
                <h3 className="font-bold text-base text-white mb-4">
                  {locale === 'ar' ? 'قنوات مساحة العمل النشطة والمؤرشفة' : 'Workspace Channels'} (
                  {channels.length})
                </h3>
                <div className="overflow-x-auto">
                  <table className="w-full text-xs">
                    <thead>
                      <tr className="border-b border-slate-800 text-slate-400">
                        <th className="py-2.5 px-3 text-start">Channel Name</th>
                        <th className="py-2.5 px-3 text-start">Kind</th>
                        <th className="py-2.5 px-3 text-start">Members</th>
                        <th className="py-2.5 px-3 text-start">Decisions / Follow-ups</th>
                        <th className="py-2.5 px-3 text-start">State</th>
                        <th className="py-2.5 px-3 text-end">Actions</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800/60">
                      {channels.map((ch) => (
                        <tr key={ch.id}>
                          <td className="py-3 px-3">
                            <div className="font-semibold text-white"># {ch.name}</div>
                            {ch.description && (
                              <div className="text-[11px] text-slate-400">{ch.description}</div>
                            )}
                          </td>
                          <td className="py-3 px-3 font-mono text-[11px] text-teal-300">
                            {String(ch.kind || 'project').toUpperCase()}
                          </td>
                          <td className="py-3 px-3 text-slate-300">{ch.member_count ?? 0}</td>
                          <td className="py-3 px-3 text-slate-300">
                            {ch.decision_count ?? 0} decisions • {ch.open_followup_count ?? 0} tasks
                          </td>
                          <td className="py-3 px-3">
                            <span
                              className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                                ch.is_archived
                                  ? 'bg-amber-500/20 text-amber-300'
                                  : 'bg-emerald-500/20 text-emerald-300'
                              }`}
                            >
                              {ch.is_archived ? 'ARCHIVED' : 'ACTIVE'}
                            </span>
                          </td>
                          <td className="py-3 px-3 text-end">
                            <button
                              type="button"
                              onClick={() => handleToggleArchiveChannel(ch)}
                              className="px-2.5 py-1 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 font-semibold text-[11px]"
                            >
                              {ch.is_archived
                                ? locale === 'ar'
                                  ? 'استعادة'
                                  : 'Restore'
                                : locale === 'ar'
                                ? 'أرشفة'
                                : 'Archive'}
                            </button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* TAB 3: EMPLOYEES & DIRECTORY */}
        {activeTab === 'employees' && (
          <div className="space-y-6">
            {/* Edit Employee Modal / Inline Drawer */}
            {editingUser && (
              <div className="bg-slate-900 border-2 border-teal-500/50 rounded-2xl p-6 shadow-xl">
                <div className="flex items-center justify-between mb-4">
                  <h3 className="font-bold text-base text-teal-300">
                    {locale === 'ar'
                      ? `تعديل ملف الموظف: ${editingUser.employee_no || editingUser.employee_number}`
                      : `Edit Employee Profile: ${editingUser.employee_no || editingUser.employee_number}`}
                  </h3>
                  <button
                    type="button"
                    onClick={() => setEditingUser(null)}
                    className="text-xs text-slate-400 hover:text-white"
                  >
                    ✕ {locale === 'ar' ? 'إغلاق' : 'Close'}
                  </button>
                </div>
                <form
                  onSubmit={handleSaveUserEdit}
                  className="grid grid-cols-1 sm:grid-cols-3 lg:grid-cols-5 gap-3.5 items-end"
                >
                  <div>
                    <label className="block text-xs text-slate-300 mb-1">Full Name</label>
                    <input
                      type="text"
                      value={editUserName}
                      onChange={(e) => setEditUserName(e.target.value)}
                      className="w-full px-3 py-2 rounded-xl bg-slate-950 border border-slate-800 text-xs text-white"
                    />
                  </div>
                  <div>
                    <label className="block text-xs text-slate-300 mb-1">Email</label>
                    <input
                      type="email"
                      value={editUserEmail}
                      onChange={(e) => setEditUserEmail(e.target.value)}
                      className="w-full px-3 py-2 rounded-xl bg-slate-950 border border-slate-800 text-xs text-white"
                    />
                  </div>
                  <div>
                    <label className="block text-xs text-slate-300 mb-1">Job Title</label>
                    <input
                      type="text"
                      value={editUserTitle}
                      onChange={(e) => setEditUserTitle(e.target.value)}
                      className="w-full px-3 py-2 rounded-xl bg-slate-950 border border-slate-800 text-xs text-white"
                    />
                  </div>
                  <div>
                    <label className="block text-xs text-slate-300 mb-1">Department</label>
                    <select
                      value={editUserDeptId}
                      onChange={(e) => setEditUserDeptId(e.target.value)}
                      className="w-full px-3 py-2 rounded-xl bg-slate-950 border border-slate-800 text-xs text-white"
                    >
                      <option value="">-- Unassigned --</option>
                      {departments.map((d) => (
                        <option key={d.id} value={d.id}>
                          {d.name} ({d.code})
                        </option>
                      ))}
                    </select>
                  </div>
                  <div className="flex gap-2">
                    <div className="flex-1">
                      <label className="block text-xs text-slate-300 mb-1">Role</label>
                      <select
                        value={editUserRole}
                        onChange={(e) => setEditUserRole(e.target.value)}
                        className="w-full px-3 py-2 rounded-xl bg-slate-950 border border-slate-800 text-xs text-white"
                      >
                        <option value="MEMBER">MEMBER</option>
                        <option value="DEPT_HEAD">DEPT_HEAD</option>
                        <option value="BROADCASTER">BROADCASTER</option>
                        <option value="IT_ADMIN">IT_ADMIN</option>
                        <option value="COMPLIANCE_OFFICER">COMPLIANCE_OFFICER</option>
                        <option value="SUPER_ADMIN">SUPER_ADMIN</option>
                      </select>
                    </div>
                    <button
                      type="submit"
                      className="px-4 py-2 rounded-xl bg-teal-500 hover:bg-teal-400 text-slate-950 font-bold text-xs"
                    >
                      {locale === 'ar' ? 'حفظ' : 'Save'}
                    </button>
                  </div>
                </form>
              </div>
            )}

            {/* Reset Password Modal / Inline Drawer */}
            {resetPwdUser && (
              <div className="bg-slate-900 border-2 border-amber-500/50 rounded-2xl p-6 shadow-xl">
                <div className="flex items-center justify-between mb-3">
                  <h3 className="font-bold text-base text-amber-300">
                    {locale === 'ar'
                      ? `إعادة تعيين كلمة مرور الموظف: ${resetPwdUser.name || resetPwdUser.full_name} (${resetPwdUser.employee_no || resetPwdUser.employee_number})`
                      : `Reset Password for ${resetPwdUser.name || resetPwdUser.full_name} (${resetPwdUser.employee_no || resetPwdUser.employee_number})`}
                  </h3>
                  <button
                    type="button"
                    onClick={() => setResetPwdUser(null)}
                    className="text-xs text-slate-400 hover:text-white"
                  >
                    ✕ {locale === 'ar' ? 'إغلاق' : 'Close'}
                  </button>
                </div>
                <form onSubmit={handleResetUserPassword} className="flex flex-wrap gap-3 items-end">
                  <div className="flex-1 min-w-[240px]">
                    <label className="block text-xs text-slate-300 mb-1">
                      {locale === 'ar'
                        ? 'كلمة المرور الجديدة (8 أحرف على الأقل)'
                        : 'New Password (minimum 8 characters)'}
                    </label>
                    <input
                      type="text"
                      value={resetPwdValue}
                      onChange={(e) => setResetPwdValue(e.target.value)}
                      className="w-full px-3.5 py-2 rounded-xl bg-slate-950 border border-slate-800 text-xs font-mono text-white"
                    />
                  </div>
                  <button
                    type="submit"
                    className="px-5 py-2 rounded-xl bg-amber-500 hover:bg-amber-400 text-slate-950 font-bold text-xs"
                  >
                    {locale === 'ar' ? 'اعتماد كلمة المرور الجديدة' : 'Confirm Password Reset'}
                  </button>
                </form>
              </div>
            )}

            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              {/* Single Employee Creation */}
              <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6">
                <h3 className="font-bold text-base text-white mb-1">
                  {locale === 'ar' ? 'إضافة حساب موظف جديد' : 'Provision New Employee Account'}
                </h3>
                <p className="text-xs text-slate-400 mb-4">
                  {locale === 'ar'
                    ? 'أنشئ حساب الموظف ثم شارك معه رمز QR أو بيانات الدخول لتطبيق Madar Agent.'
                    : 'Create an employee identity so they can sign in to the Madar Agent app.'}
                </p>
                <form onSubmit={handleCreateEmployee} className="grid grid-cols-1 sm:grid-cols-2 gap-3.5">
                  <div>
                    <label className="block text-xs text-slate-300 mb-1">Employee ID *</label>
                    <input
                      type="text"
                      value={empNo}
                      onChange={(e) => setEmpNo(e.target.value)}
                      placeholder="EMP-101"
                      className="w-full px-3 py-2 rounded-xl bg-slate-950 border border-slate-800 text-xs font-mono text-white"
                    />
                  </div>
                  <div>
                    <label className="block text-xs text-slate-300 mb-1">Full Name *</label>
                    <input
                      type="text"
                      value={empName}
                      onChange={(e) => setEmpName(e.target.value)}
                      placeholder="Sara Al-Mansoor"
                      className="w-full px-3 py-2 rounded-xl bg-slate-950 border border-slate-800 text-xs text-white"
                    />
                  </div>
                  <div>
                    <label className="block text-xs text-slate-300 mb-1">Work Email</label>
                    <input
                      type="email"
                      value={empEmail}
                      onChange={(e) => setEmpEmail(e.target.value)}
                      placeholder="sara@organization.gov"
                      className="w-full px-3 py-2 rounded-xl bg-slate-950 border border-slate-800 text-xs text-white"
                    />
                  </div>
                  <div>
                    <label className="block text-xs text-slate-300 mb-1">Job Title</label>
                    <input
                      type="text"
                      value={empTitle}
                      onChange={(e) => setEmpTitle(e.target.value)}
                      placeholder="Security Engineer"
                      className="w-full px-3 py-2 rounded-xl bg-slate-950 border border-slate-800 text-xs text-white"
                    />
                  </div>
                  <div>
                    <label className="block text-xs text-slate-300 mb-1">Department</label>
                    <select
                      value={empDeptId}
                      onChange={(e) => setEmpDeptId(e.target.value)}
                      className="w-full px-3 py-2 rounded-xl bg-slate-950 border border-slate-800 text-xs text-white"
                    >
                      <option value="">-- Select Department --</option>
                      {departments.map((d) => (
                        <option key={d.id} value={d.id}>
                          {d.name} ({d.code})
                        </option>
                      ))}
                    </select>
                  </div>
                  <div>
                    <label className="block text-xs text-slate-300 mb-1">Role</label>
                    <select
                      value={empRole}
                      onChange={(e) => setEmpRole(e.target.value)}
                      className="w-full px-3 py-2 rounded-xl bg-slate-950 border border-slate-800 text-xs text-white"
                    >
                      <option value="MEMBER">MEMBER (Employee)</option>
                      <option value="DEPT_HEAD">DEPT_HEAD</option>
                      <option value="BROADCASTER">BROADCASTER</option>
                      <option value="IT_ADMIN">IT_ADMIN</option>
                      <option value="COMPLIANCE_OFFICER">COMPLIANCE_OFFICER</option>
                      <option value="SUPER_ADMIN">SUPER_ADMIN</option>
                    </select>
                  </div>
                  <div className="sm:col-span-2">
                    <label className="block text-xs text-slate-300 mb-1">Initial Password *</label>
                    <input
                      type="text"
                      value={empPassword}
                      onChange={(e) => setEmpPassword(e.target.value)}
                      className="w-full px-3 py-2 rounded-xl bg-slate-950 border border-slate-800 text-xs font-mono text-white"
                    />
                  </div>
                  <div className="sm:col-span-2">
                    <button
                      type="submit"
                      className="w-full py-2.5 rounded-xl bg-teal-500 hover:bg-teal-400 text-slate-950 font-bold text-xs transition"
                    >
                      + {locale === 'ar' ? 'إنشاء حساب الموظف' : 'Create Employee Account'}
                    </button>
                  </div>
                </form>
              </div>

              {/* Bulk CSV Import */}
              <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 flex flex-col justify-between">
                <div>
                  <h3 className="font-bold text-base text-white mb-1">
                    {locale === 'ar'
                      ? 'استيراد جماعي للموظفين (CSV)'
                      : 'Bulk Employee Import (CSV)'}
                  </h3>
                  <p className="text-xs text-slate-400 mb-3">
                    Format:{' '}
                    <code className="text-teal-300">
                      employee_no, name, email, title, department_code, password
                    </code>
                  </p>
                  <textarea
                    rows={6}
                    value={csvUsersText}
                    onChange={(e) => setCsvUsersText(e.target.value)}
                    placeholder={
                      'EMP-101, Sara Al-Mansoor, sara@org.local, Analyst, IT, Employee@Madar2026!\nEMP-102, Omar Khalid, omar@org.local, Engineer, OPS, Employee@Madar2026!'
                    }
                    className="w-full p-3 rounded-xl bg-slate-950 border border-slate-800 text-xs font-mono text-white"
                  />
                </div>
                <button
                  type="button"
                  onClick={handleCsvBulkImport}
                  className="mt-4 w-full py-2.5 rounded-xl bg-slate-800 hover:bg-slate-700 border border-slate-700 text-teal-300 font-bold text-xs transition"
                >
                  {locale === 'ar' ? 'تنفيذ الاستيراد الجماعي' : 'Run Bulk CSV Provisioning'}
                </button>
              </div>
            </div>

            {/* Employee Directory Table */}
            <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6">
              <h3 className="font-bold text-base text-white mb-4">
                {locale === 'ar' ? 'دليل الموظفين والحسابات' : 'Organization Employee Directory'} (
                {users.length})
              </h3>
              <div className="overflow-x-auto">
                <table className="w-full text-xs">
                  <thead>
                    <tr className="border-b border-slate-800 text-slate-400">
                      <th className="py-2.5 px-3 text-start">Employee ID</th>
                      <th className="py-2.5 px-3 text-start">Full Name</th>
                      <th className="py-2.5 px-3 text-start">Email</th>
                      <th className="py-2.5 px-3 text-start">Department</th>
                      <th className="py-2.5 px-3 text-start">Roles</th>
                      <th className="py-2.5 px-3 text-start">Status</th>
                      <th className="py-2.5 px-3 text-end">Actions</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/60">
                    {users.map((u) => {
                      const empNumber = u.employee_no || u.employee_number;
                      const fullName = u.name || u.full_name;
                      const status = String(u.account_status || u.status || 'active').toUpperCase();
                      const rolesList = Array.isArray(u.roles) ? u.roles.join(', ') : u.role || 'MEMBER';
                      return (
                        <tr key={u.id}>
                          <td className="py-3 px-3 font-mono font-bold text-teal-300">
                            {empNumber}
                          </td>
                          <td className="py-3 px-3 font-semibold text-white">{fullName}</td>
                          <td className="py-3 px-3 text-slate-300">{u.email || '—'}</td>
                          <td className="py-3 px-3 text-slate-300">{u.department_name || '—'}</td>
                          <td className="py-3 px-3 font-mono text-[11px] text-slate-300">
                            {rolesList}
                          </td>
                          <td className="py-3 px-3">
                            <span
                              className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                                status === 'ACTIVE'
                                  ? 'bg-emerald-500/20 text-emerald-300'
                                  : status === 'SUSPENDED'
                                  ? 'bg-amber-500/20 text-amber-300'
                                  : 'bg-rose-500/20 text-rose-300'
                              }`}
                            >
                              {status}
                            </span>
                          </td>
                          <td className="py-3 px-3 text-end space-x-1.5 rtl:space-x-reverse">
                            <button
                              type="button"
                              onClick={() => {
                                setQrTargetUserId(String(u.id));
                                setActiveTab('onboarding');
                                handleGenerateQr(String(u.id));
                              }}
                              className="px-2 py-1 rounded-lg bg-teal-500/15 hover:bg-teal-500/25 text-teal-300 font-semibold text-[11px]"
                            >
                              QR
                            </button>
                            <button
                              type="button"
                              onClick={() => handleOpenEditUser(u)}
                              className="px-2 py-1 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 font-semibold text-[11px]"
                            >
                              {locale === 'ar' ? 'تعديل' : 'Edit'}
                            </button>
                            <button
                              type="button"
                              onClick={() => {
                                setResetPwdUser(u);
                                setResetPwdValue('Employee@Madar2026!');
                              }}
                              className="px-2 py-1 rounded-lg bg-amber-500/15 hover:bg-amber-500/25 text-amber-300 font-semibold text-[11px]"
                            >
                              {locale === 'ar' ? 'كلمة المرور' : 'Password'}
                            </button>
                            {u.id !== currentUser?.id && status !== 'OFFBOARDED' && (
                              <button
                                type="button"
                                onClick={() => handleToggleUserStatus(u)}
                                className="px-2 py-1 rounded-lg bg-indigo-500/15 hover:bg-indigo-500/25 text-indigo-300 font-semibold text-[11px]"
                              >
                                {status === 'ACTIVE'
                                  ? locale === 'ar'
                                    ? 'تعليق'
                                    : 'Suspend'
                                  : locale === 'ar'
                                  ? 'تفعيل'
                                  : 'Activate'}
                              </button>
                            )}
                            {status === 'ACTIVE' && u.id !== currentUser?.id && (
                              <button
                                type="button"
                                onClick={() => handleOffboardUser(u.id)}
                                className="px-2 py-1 rounded-lg bg-rose-500/15 hover:bg-rose-500/25 text-rose-300 font-semibold text-[11px]"
                              >
                                {locale === 'ar' ? 'إنهاء ومسح' : 'Offboard & Wipe'}
                              </button>
                            )}
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        )}

        {/* TAB 4: AGENT ONBOARDING & QR CODE */}
        {activeTab === 'onboarding' && (
          <div className="space-y-6">
            <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6">
              <h2 className="text-lg font-bold text-white mb-4">{t.agentGuideTitle}</h2>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
                <div className="p-5 rounded-xl bg-slate-950 border border-teal-500/30 space-y-2.5">
                  <div className="text-sm font-bold text-teal-300">{t.agentMethodATitle}</div>
                  <p className="text-xs text-slate-300 leading-relaxed">{t.agentMethodAStep1}</p>
                  <p className="text-xs text-slate-300 leading-relaxed">{t.agentMethodAStep2}</p>
                  <p className="text-xs text-slate-300 leading-relaxed">{t.agentMethodAStep3}</p>
                </div>

                <div className="p-5 rounded-xl bg-slate-950 border border-slate-800 space-y-2.5">
                  <div className="text-sm font-bold text-indigo-300">{t.agentMethodBTitle}</div>
                  <p className="text-xs text-slate-300 leading-relaxed">{t.agentMethodBStep1}</p>
                  <p className="text-xs text-slate-300 leading-relaxed">{t.agentMethodBStep2}</p>
                  <p className="text-xs text-slate-300 leading-relaxed">{t.agentMethodBStep3}</p>
                </div>
              </div>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 space-y-4">
                <h3 className="font-bold text-base text-white">{t.qrGeneratorTitle}</h3>

                <div>
                  <label className="block text-xs font-semibold text-slate-300 mb-1">
                    {t.serverUrlLabel}
                  </label>
                  <input
                    type="text"
                    value={serverUrl}
                    onChange={(e) => setServerUrl(e.target.value)}
                    className="w-full px-3.5 py-2 rounded-xl bg-slate-950 border border-slate-800 text-xs font-mono text-teal-300"
                  />
                  <p className="text-[11px] text-slate-400 mt-1">{t.serverUrlHelp}</p>
                </div>

                <div>
                  <label className="block text-xs font-semibold text-slate-300 mb-1">
                    {t.qrTargetEmployee}
                  </label>
                  <select
                    value={qrTargetUserId}
                    onChange={(e) => setQrTargetUserId(e.target.value)}
                    className="w-full px-3.5 py-2 rounded-xl bg-slate-950 border border-slate-800 text-xs text-white"
                  >
                    <option value="">{t.qrMultiUseOption}</option>
                    {users.map((u) => (
                      <option key={u.id} value={u.id}>
                        {u.employee_no || u.employee_number} — {u.name || u.full_name}
                      </option>
                    ))}
                  </select>
                </div>

                <div className="grid grid-cols-2 gap-3">
                  <div>
                    <label className="block text-xs font-semibold text-slate-300 mb-1">
                      {t.qrMaxUses}
                    </label>
                    <input
                      type="number"
                      min={1}
                      max={500}
                      value={qrMaxUses}
                      onChange={(e) => setQrMaxUses(Number(e.target.value))}
                      className="w-full px-3.5 py-2 rounded-xl bg-slate-950 border border-slate-800 text-xs text-white"
                    />
                  </div>
                  <div>
                    <label className="block text-xs font-semibold text-slate-300 mb-1">
                      {t.qrExpiresHours}
                    </label>
                    <input
                      type="number"
                      min={1}
                      max={720}
                      value={qrExpiresHours}
                      onChange={(e) => setQrExpiresHours(Number(e.target.value))}
                      className="w-full px-3.5 py-2 rounded-xl bg-slate-950 border border-slate-800 text-xs text-white"
                    />
                  </div>
                </div>

                <button
                  type="button"
                  onClick={() => handleGenerateQr()}
                  className="w-full py-3 rounded-xl bg-teal-500 hover:bg-teal-400 text-slate-950 font-bold text-xs shadow-lg shadow-teal-500/20 transition"
                >
                  ★ {t.qrGenerateBtn}
                </button>
              </div>

              <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 flex flex-col items-center justify-between">
                <div className="w-full flex items-center justify-between mb-3">
                  <h3 className="font-bold text-base text-white">{t.qrLatestBoxTitle}</h3>
                  <span className="px-2.5 py-0.5 rounded-full text-[10px] font-bold bg-emerald-500/15 text-emerald-300 border border-emerald-500/30">
                    Ed25519 Signed
                  </span>
                </div>

                {activeQrUri ? (
                  <>
                    <div className="bg-white p-3 rounded-2xl shadow-xl my-2">
                      {/* eslint-disable-next-line @next/next/no-img-element */}
                      <img
                        src={`/admin-api/qr?data=${encodeURIComponent(activeQrUri)}`}
                        alt="Madar Agent Enrollment QR Code"
                        className="w-52 h-52"
                      />
                    </div>
                    <div className="w-full space-y-2.5 mt-3">
                      <div className="p-2.5 rounded-xl bg-slate-950 border border-slate-800 font-mono text-[11px] text-teal-300 break-all">
                        {activeQrUri}
                      </div>
                      <div className="flex flex-wrap gap-2">
                        <button
                          type="button"
                          onClick={() => handleCopy('uri', activeQrUri)}
                          className="flex-1 py-2 px-3 rounded-xl bg-slate-800 hover:bg-slate-700 text-xs font-semibold text-white transition"
                        >
                          {copiedField === 'uri' ? t.copied : t.copyQrUri}
                        </button>
                        <button
                          type="button"
                          onClick={() => handleCopy('token', activeTokenCode)}
                          className="flex-1 py-2 px-3 rounded-xl bg-slate-800 hover:bg-slate-700 text-xs font-semibold text-teal-300 transition"
                        >
                          {copiedField === 'token' ? t.copied : t.copyTokenOnly}
                        </button>
                      </div>
                    </div>
                  </>
                ) : (
                  <div className="my-auto text-center py-10 space-y-3">
                    <p className="text-xs text-slate-400">
                      {locale === 'ar'
                        ? 'اضغط على زر توليد رمز QR لإصدار رمز التحاق موقّع للموظفين.'
                        : 'Click "Generate Signed QR & Token" to create an instant onboarding QR code for your employees.'}
                    </p>
                    <button
                      type="button"
                      onClick={() => handleGenerateQr('')}
                      className="px-5 py-2.5 rounded-xl bg-teal-500 hover:bg-teal-400 text-slate-950 font-bold text-xs transition"
                    >
                      {t.qrGenerateBtn}
                    </button>
                  </div>
                )}
              </div>
            </div>
          </div>
        )}

        {/* TAB 5: ENROLLED DEVICES & SECURITY */}
        {activeTab === 'devices' && (
          <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6">
            <h3 className="font-bold text-base text-white mb-4">
              {locale === 'ar' ? 'أجهزة الموظفين الموثقة' : 'Enrolled Employee Devices'} (
              {devices.length})
            </h3>
            <div className="overflow-x-auto">
              <table className="w-full text-xs">
                <thead>
                  <tr className="border-b border-slate-800 text-slate-400">
                    <th className="py-2.5 px-3 text-start">Employee</th>
                    <th className="py-2.5 px-3 text-start">Device Name</th>
                    <th className="py-2.5 px-3 text-start">Platform</th>
                    <th className="py-2.5 px-3 text-start">Attestation</th>
                    <th className="py-2.5 px-3 text-start">Status</th>
                    <th className="py-2.5 px-3 text-end">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60">
                  {devices.map((dev) => {
                    const statusUpper = String(dev.status || 'active').toUpperCase();
                    return (
                      <tr key={dev.id}>
                        <td className="py-3 px-3 font-semibold text-white">
                          {dev.user_name || dev.full_name} ({dev.employee_no || dev.employee_number})
                        </td>
                        <td className="py-3 px-3 text-slate-300">{dev.device_name}</td>
                        <td className="py-3 px-3 font-mono text-slate-400">{dev.platform}</td>
                        <td className="py-3 px-3 font-mono text-teal-300">
                          {dev.attestation_state || dev.attestation_status || 'verified'}
                        </td>
                        <td className="py-3 px-3">
                          <span
                            className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                              statusUpper === 'ACTIVE'
                                ? 'bg-emerald-500/20 text-emerald-300'
                                : 'bg-rose-500/20 text-rose-300'
                            }`}
                          >
                            {statusUpper}
                          </span>
                        </td>
                        <td className="py-3 px-3 text-end space-x-1.5 rtl:space-x-reverse">
                          {statusUpper === 'ACTIVE' && (
                            <>
                              <button
                                type="button"
                                onClick={() => handleRevokeDevice(dev.id)}
                                className="px-2.5 py-1 rounded-lg bg-amber-500/15 hover:bg-amber-500/25 text-amber-300 font-semibold text-[11px]"
                              >
                                Revoke
                              </button>
                              <button
                                type="button"
                                onClick={() => handleWipeDevice(dev.id)}
                                className="px-2.5 py-1 rounded-lg bg-rose-500/15 hover:bg-rose-500/25 text-rose-300 font-semibold text-[11px]"
                              >
                                Remote Wipe
                              </button>
                            </>
                          )}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* TAB 6: 28-KEY SOVEREIGN POLICY ENGINE */}
        {activeTab === 'policies' && (
          <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6">
            <div className="mb-4">
              <h3 className="font-bold text-base text-white">
                {locale === 'ar'
                  ? 'محرك السياسات السيادية والدفاع ضد تسرب البيانات (28 مفتاح تحكم)'
                  : 'Sovereign Policy & DLP Engine (28 Live Controls)'}
              </h3>
              <p className="text-xs text-slate-400 mt-1">
                {locale === 'ar'
                  ? 'أي تعديل هنا يُوقّع رقمياً بمفتاح Ed25519 ويُدفع فوراً لتطبيقات الموظفين (Madar Agent).'
                  : 'Changes are cryptographically signed with Ed25519 and pushed live to connected Madar Agent clients.'}
              </p>
            </div>
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3.5">
              {(policyCatalog.length > 0
                ? policyCatalog.map((c) => [c.key, policyValues[c.key] ?? c.defaultValue, c])
                : Object.entries(policyValues).map(([k, v]) => [k, v, null])
              ).map(([key, val, meta]: any) => (
                <div
                  key={key}
                  className="p-3.5 rounded-xl bg-slate-950 border border-slate-800 flex items-center justify-between gap-3"
                >
                  <div className="min-w-0">
                    <div className="font-mono text-xs font-semibold text-white truncate">{key}</div>
                    {meta?.description && (
                      <div className="text-[11px] text-slate-400 truncate mt-0.5">
                        {meta.description}
                      </div>
                    )}
                    <div className="text-[11px] text-slate-500 mt-0.5">
                      Value: <span className="text-teal-300 font-mono">{String(val)}</span>
                    </div>
                  </div>
                  {typeof val === 'boolean' ? (
                    <button
                      type="button"
                      onClick={() => handlePublishPolicyChange(key, !val)}
                      className={`px-3 py-1.5 rounded-lg text-xs font-bold transition ${
                        val
                          ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40'
                          : 'bg-slate-800 text-slate-400 border border-slate-700'
                      }`}
                    >
                      {val ? 'ON' : 'OFF'}
                    </button>
                  ) : (
                    <input
                      type="text"
                      defaultValue={String(val)}
                      onBlur={(e) => {
                        const raw = e.target.value;
                        if (raw !== String(val)) {
                          const parsed =
                            typeof val === 'number' && !Number.isNaN(Number(raw))
                              ? Number(raw)
                              : raw;
                          handlePublishPolicyChange(key, parsed);
                        }
                      }}
                      className="w-24 px-2.5 py-1 rounded-lg bg-slate-900 border border-slate-700 text-xs font-mono text-right text-teal-300"
                    />
                  )}
                </div>
              ))}
            </div>
          </div>
        )}

        {/* TAB 7: OFFICIAL BROADCASTS */}
        {activeTab === 'broadcasts' && (
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6">
              <h3 className="font-bold text-base text-white mb-3">
                {locale === 'ar' ? 'نشر تعميم رسمي جديد' : 'Publish Official Broadcast'}
              </h3>
              <form onSubmit={handlePublishBroadcast} className="space-y-3.5">
                <div>
                  <label className="block text-xs text-slate-300 mb-1">Broadcast Title *</label>
                  <input
                    type="text"
                    value={bcTitle}
                    onChange={(e) => setBcTitle(e.target.value)}
                    placeholder="Mandatory Security Policy Update"
                    className="w-full px-3.5 py-2 rounded-xl bg-slate-950 border border-slate-800 text-xs text-white"
                  />
                </div>
                <div>
                  <label className="block text-xs text-slate-300 mb-1">Official Message *</label>
                  <textarea
                    rows={4}
                    value={bcBody}
                    onChange={(e) => setBcBody(e.target.value)}
                    placeholder="Please review and acknowledge the updated directive..."
                    className="w-full p-3 rounded-xl bg-slate-950 border border-slate-800 text-xs text-white"
                  />
                </div>
                <label className="flex items-center gap-2 text-xs text-slate-300 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={bcAckRequired}
                    onChange={(e) => setBcAckRequired(e.target.checked)}
                  />
                  <span>Require Mandatory Read Acknowledgment</span>
                </label>
                <button
                  type="submit"
                  className="w-full py-2.5 rounded-xl bg-teal-500 hover:bg-teal-400 text-slate-950 font-bold text-xs transition"
                >
                  Publish Broadcast
                </button>
              </form>
            </div>

            <div className="lg:col-span-2 bg-slate-900 border border-slate-800 rounded-2xl p-6 space-y-3">
              <h3 className="font-bold text-base text-white mb-2">
                {locale === 'ar' ? 'التعاميم المنشورة ونسب الإقرار' : 'Published Broadcasts'} (
                {broadcasts.length})
              </h3>
              {broadcasts.map((b) => (
                <div
                  key={b.id}
                  className="p-4 rounded-xl bg-slate-950 border border-slate-800 flex items-start justify-between gap-4"
                >
                  <div>
                    <div className="font-bold text-sm text-white">
                      {b.title}{' '}
                      <span className="text-xs font-mono text-teal-400">({b.ref_no})</span>
                    </div>
                    <p className="text-xs text-slate-300 mt-1">{b.body}</p>
                    <div className="text-[11px] text-slate-500 mt-2">{b.created_at}</div>
                  </div>
                  <div className="text-end shrink-0">
                    <span className="px-2.5 py-1 rounded-lg bg-teal-500/15 text-teal-300 font-mono text-xs font-bold">
                      Ack: {b.ack_count ?? 0} / {b.total_recipients ?? users.length}
                    </span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* TAB 8: COMPLIANCE, LEGAL HOLD & IMMUTABLE AUDIT LOG */}
        {activeTab === 'compliance' && (
          <div className="space-y-6">
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              {/* Legal Hold Creation */}
              <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6">
                <h3 className="font-bold text-base text-white mb-2">
                  {locale === 'ar'
                    ? 'إصدار أمر تحفظ قانوني (Legal Hold)'
                    : 'Activate Sovereign Legal Hold'}
                </h3>
                <p className="text-xs text-slate-400 mb-4">
                  Prevents deletion or retention purging of messages & attachments during active
                  investigations.
                </p>
                <form onSubmit={handleCreateLegalHold} className="space-y-3">
                  <input
                    type="text"
                    value={lhName}
                    onChange={(e) => setLhName(e.target.value)}
                    placeholder="Matter Reference (e.g., AUDIT-2026-Q4)"
                    className="w-full px-3.5 py-2 rounded-xl bg-slate-950 border border-slate-800 text-xs text-white"
                  />
                  <input
                    type="text"
                    value={lhReason}
                    onChange={(e) => setLhReason(e.target.value)}
                    placeholder="Reason / Regulatory Mandate"
                    className="w-full px-3.5 py-2 rounded-xl bg-slate-950 border border-slate-800 text-xs text-white"
                  />
                  <button
                    type="submit"
                    className="w-full py-2.5 rounded-xl bg-amber-500 hover:bg-amber-400 text-slate-950 font-bold text-xs transition"
                  >
                    Activate Legal Hold ({legalHolds.length} Active)
                  </button>
                </form>
              </div>

              {/* Tamper-Evident Audit Export */}
              <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 flex flex-col justify-between">
                <div>
                  <h3 className="font-bold text-base text-white mb-2">
                    {locale === 'ar'
                      ? 'تصدير سجل التدقيق الجنائي الموثق (JSON / CSV)'
                      : 'Tamper-Evident Audit & Compliance Export'}
                  </h3>
                  <p className="text-xs text-slate-400 mb-4">
                    Exports the SHA-256 hash-chained audit trail with RFC 4180 CSV formula-injection
                    sanitization.
                  </p>
                  <div className="flex gap-3">
                    <button
                      type="button"
                      onClick={() => handleExportAuditBundle('json')}
                      className="flex-1 py-2.5 rounded-xl bg-teal-500 hover:bg-teal-400 text-slate-950 font-bold text-xs transition"
                    >
                      Export JSON Bundle
                    </button>
                    <button
                      type="button"
                      onClick={() => handleExportAuditBundle('csv')}
                      className="flex-1 py-2.5 rounded-xl bg-slate-800 hover:bg-slate-700 text-teal-300 font-bold text-xs transition"
                    >
                      Export Sanitized CSV
                    </button>
                  </div>
                </div>
                {ediscoveryResult && (
                  <pre className="mt-4 p-3 rounded-xl bg-slate-950 border border-slate-800 text-[10px] font-mono text-teal-300 max-h-40 overflow-auto">
                    {ediscoveryResult}
                  </pre>
                )}
              </div>
            </div>

            {/* Immutable SHA-256 Hash-Chained Audit Log */}
            <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6">
              <div className="flex items-center justify-between mb-4">
                <h3 className="font-bold text-base text-white">
                  Immutable SHA-256 Hash-Chained Audit Trail ({auditLogs.length})
                </h3>
                <span className="px-3 py-1 rounded-full text-xs font-bold bg-emerald-500/15 text-emerald-300 border border-emerald-500/30">
                  {auditVerification?.valid !== false
                    ? `✓ Chain Verified (${auditVerification?.checkedCount ?? auditLogs.length} entries)`
                    : '⚠ Chain Tamper Detected'}
                </span>
              </div>
              <div className="overflow-x-auto">
                <table className="w-full text-xs">
                  <thead>
                    <tr className="border-b border-slate-800 text-slate-400">
                      <th className="py-2 px-3 text-start">#</th>
                      <th className="py-2 px-3 text-start">Action</th>
                      <th className="py-2 px-3 text-start">Target</th>
                      <th className="py-2 px-3 text-start">Row SHA-256 Hash</th>
                      <th className="py-2 px-3 text-start">Timestamp</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/60">
                    {auditLogs.map((log) => (
                      <tr key={log.id}>
                        <td className="py-2.5 px-3 font-mono text-slate-400">{log.id}</td>
                        <td className="py-2.5 px-3 font-mono font-bold text-teal-300">
                          {log.action}
                        </td>
                        <td className="py-2.5 px-3 text-slate-300">
                          {log.target_type}:{log.target_id || '—'}
                        </td>
                        <td className="py-2.5 px-3 font-mono text-[10px] text-slate-400">
                          {(log.row_hash_hex || log.entry_hash || '').slice(0, 24)}...
                        </td>
                        <td className="py-2.5 px-3 text-slate-400">{log.created_at}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        )}

        {/* TAB 9: CLOUD RELAY SERVICES (ADM-02, ENR-06) & ENTERPRISE SSO / LDAP (AUTH-01, AUTH-06) */}
        {activeTab === 'cloud' && (
          <div className="space-y-6">
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              {/* Blind Cloud Relay & Official Domain Verification */}
              <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 space-y-4">
                <div className="flex items-center justify-between">
                  <h3 className="font-bold text-base text-white">
                    {locale === 'ar'
                      ? 'الخدمات السحابية الوسيطة وتوثيق النطاق (madar-relay)'
                      : 'Blind Push/SMS Relay & Domain Verification (ADM-02)'}
                  </h3>
                  <span
                    className={`px-2.5 py-0.5 rounded-full text-[10px] font-bold ${
                      cloudServices?.domain_verified
                        ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30'
                        : 'bg-amber-500/20 text-amber-300 border border-amber-500/30'
                    }`}
                  >
                    {cloudServices?.domain_verified
                      ? locale === 'ar'
                        ? '✓ نطاق موثّق رسمياً'
                        : '✓ Domain Verified'
                      : locale === 'ar'
                        ? 'بانتظار تحقق DNS TXT'
                        : 'Pending DNS TXT'}
                  </span>
                </div>

                <form onSubmit={handleSaveCloudServices} className="space-y-3.5">
                  <div>
                    <label className="block text-xs text-slate-300 mb-1">
                      {locale === 'ar'
                        ? 'النطاق الرسمي لمساحة العمل (Official Domain - ENR-06)'
                        : 'Official Organization Domain'}
                    </label>
                    <input
                      type="text"
                      value={officialDomain}
                      onChange={(e) => setOfficialDomain(e.target.value)}
                      placeholder="chat.afaq-logistics.sa"
                      className="w-full px-3.5 py-2 rounded-xl bg-slate-950 border border-slate-800 text-xs font-mono text-white"
                    />
                    {cloudServices?.dns_txt_expected && (
                      <div className="mt-2 p-2.5 rounded-xl bg-slate-950 border border-slate-800 text-[11px] font-mono text-teal-300 space-y-1">
                        <div>Host: {cloudServices.dns_txt_host}</div>
                        <div>TXT: {cloudServices.dns_txt_expected}</div>
                      </div>
                    )}
                  </div>

                  <div>
                    <label className="block text-xs text-slate-300 mb-1">
                      {locale === 'ar'
                        ? 'عنوان خدمة السحابة العمياء (Madar Blind Relay URL)'
                        : 'Madar Blind Relay URL'}
                    </label>
                    <input
                      type="text"
                      value={relayUrl}
                      onChange={(e) => setRelayUrl(e.target.value)}
                      className="w-full px-3.5 py-2 rounded-xl bg-slate-950 border border-slate-800 text-xs font-mono text-teal-300"
                    />
                  </div>

                  <div>
                    <label className="block text-xs text-slate-300 mb-1">
                      {locale === 'ar'
                        ? 'مفتاح اشتراك السحابة الوسيطة (TENANT_TOKEN)'
                        : 'Cloud Relay Subscription Token (TENANT_TOKEN)'}
                    </label>
                    <input
                      type="password"
                      value={tenantToken}
                      onChange={(e) => setTenantToken(e.target.value)}
                      placeholder={
                        cloudServices?.tenant_token_configured
                          ? '•••••••••••••••• (Configured)'
                          : 'Paste TENANT_TOKEN...'
                      }
                      className="w-full px-3.5 py-2 rounded-xl bg-slate-950 border border-slate-800 text-xs font-mono text-white"
                    />
                  </div>

                  <div className="grid grid-cols-2 gap-3">
                    <div>
                      <label className="block text-xs text-slate-300 mb-1">
                        {locale === 'ar' ? 'مزود رسائل التحقق (SMS OTP)' : 'SMS OTP Provider'}
                      </label>
                      <select
                        value={smsProvider}
                        onChange={(e) => setSmsProvider(e.target.value as any)}
                        className="w-full px-3 py-2 rounded-xl bg-slate-950 border border-slate-800 text-xs text-white"
                      >
                        <option value="madar_relay">Madar SMS Relay (TENANT_TOKEN)</option>
                        <option value="webhook">Enterprise Webhook / SMPP</option>
                        <option value="console">Console (Dev/Test)</option>
                        <option value="none">Disabled (Air-Gapped)</option>
                      </select>
                    </div>
                    <div className="flex items-end pb-1">
                      <label className="flex items-center gap-2 text-xs text-slate-300 cursor-pointer">
                        <input
                          type="checkbox"
                          checked={pushRelayEnabled}
                          onChange={(e) => setPushRelayEnabled(e.target.checked)}
                        />
                        <span>
                          {locale === 'ar'
                            ? 'تفعيل الإيقاظ الصامت (Zero-Payload Push)'
                            : 'Enable Zero-Payload Wake'}
                        </span>
                      </label>
                    </div>
                  </div>

                  {smsProvider === 'webhook' && (
                    <div>
                      <label className="block text-xs text-slate-300 mb-1">SMS Webhook URL</label>
                      <input
                        type="text"
                        value={smsWebhookUrl}
                        onChange={(e) => setSmsWebhookUrl(e.target.value)}
                        placeholder="https://sms-gateway.corp.local/send"
                        className="w-full px-3.5 py-2 rounded-xl bg-slate-950 border border-slate-800 text-xs font-mono text-white"
                      />
                    </div>
                  )}

                  <div className="flex gap-3 pt-2">
                    <button
                      type="submit"
                      className="flex-1 py-2.5 rounded-xl bg-teal-500 hover:bg-teal-400 text-slate-950 font-bold text-xs transition"
                    >
                      {locale === 'ar' ? 'حفظ إعدادات السحابة' : 'Save Cloud Config'}
                    </button>
                    <button
                      type="button"
                      onClick={handleVerifyDomain}
                      className="px-4 py-2.5 rounded-xl bg-slate-800 hover:bg-slate-700 text-teal-300 font-bold text-xs transition"
                    >
                      {locale === 'ar' ? 'تحقق من DNS TXT' : 'Verify DNS TXT'}
                    </button>
                  </div>
                </form>
              </div>

              {/* Enterprise Identity Providers (OIDC / SAML 2.0 / Active Directory LDAP) */}
              <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 space-y-4">
                <h3 className="font-bold text-base text-white">
                  {locale === 'ar'
                    ? 'ربط هوية مساحة العمل ومزامنة الدليل النشط (OIDC / SAML / LDAP)'
                    : 'Enterprise Identity & Active Directory Sync (AUTH-01, AUTH-06)'}
                </h3>

                <form onSubmit={handleCreateAuthProvider} className="space-y-3">
                  <div className="grid grid-cols-2 gap-3">
                    <div>
                      <label className="block text-xs text-slate-300 mb-1">Protocol</label>
                      <select
                        value={idpKind}
                        onChange={(e) => setIdpKind(e.target.value as any)}
                        className="w-full px-3 py-2 rounded-xl bg-slate-950 border border-slate-800 text-xs text-white"
                      >
                        <option value="ldap">Active Directory (LDAP)</option>
                        <option value="oidc">OpenID Connect (OIDC)</option>
                        <option value="saml">SAML 2.0 Enterprise</option>
                      </select>
                    </div>
                    <div>
                      <label className="block text-xs text-slate-300 mb-1">Provider Name</label>
                      <input
                        type="text"
                        value={idpName}
                        onChange={(e) => setIdpName(e.target.value)}
                        className="w-full px-3.5 py-2 rounded-xl bg-slate-950 border border-slate-800 text-xs text-white"
                      />
                    </div>
                  </div>

                  <div>
                    <label className="block text-xs text-slate-300 mb-1">
                      Encrypted Provider Configuration (JSON)
                    </label>
                    <textarea
                      rows={4}
                      value={idpConfigText}
                      onChange={(e) => setIdpConfigText(e.target.value)}
                      className="w-full p-3 rounded-xl bg-slate-950 border border-slate-800 text-xs font-mono text-teal-300"
                    />
                  </div>

                  <button
                    type="submit"
                    className="w-full py-2.5 rounded-xl bg-teal-500 hover:bg-teal-400 text-slate-950 font-bold text-xs transition"
                  >
                    {locale === 'ar'
                      ? 'إضافة مزود الهوية وتفعيل المزامنة الدورية (كل 15 دقيقة)'
                      : 'Add Identity Provider (15m Auto-Sync)'}
                  </button>
                </form>

                <div className="space-y-2 pt-2">
                  {authProviders.map((p) => (
                    <div
                      key={p.id}
                      className="p-3 rounded-xl bg-slate-950 border border-slate-800 flex items-center justify-between gap-3"
                    >
                      <div>
                        <div className="text-xs font-bold text-white">
                          {p.name}{' '}
                          <span className="text-[10px] font-mono uppercase text-teal-400">
                            [{p.kind}]
                          </span>
                        </div>
                        <div className="text-[11px] text-slate-400">
                          Sync every {p.sync_interval_minutes || 15}m • Last:{' '}
                          {p.last_sync_status || 'ready'}
                        </div>
                      </div>
                      <button
                        type="button"
                        onClick={() => handleSyncAuthProvider(p.id)}
                        className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-teal-300 text-xs font-bold transition"
                      >
                        ↻ {locale === 'ar' ? 'مزامنة الآن' : 'Sync Now'}
                      </button>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </div>
        )}
      </main>
    </div>
  );
}
