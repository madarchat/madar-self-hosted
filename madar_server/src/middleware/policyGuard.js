import { db } from '../db/pool.js';
import { forbidden, badRequest } from '../lib/errors.js';
import { ensureDefaultWorkspace, resolveEffectivePolicy, getPolicySpecMap } from '../services/policyEngine.js';

/**
 * Loads the authenticated user's roles and effective workspace policy into req.policy and req.userRoles.
 */
export async function attachPolicyContext(req, _res, next) {
  try {
    if (!req.auth?.userId) return next();
    const user = await db.one(
      'SELECT id, workspace_id, department_id, profile_type, account_status FROM users WHERE id = $1',
      [req.auth.userId],
    );
    if (!user) return next();
    if (user.account_status === 'suspended' || user.account_status === 'offboarded') {
      return next(forbidden('account_inactive', 'تم تعليق هذا الحساب المؤسسي أو إنهاء صلاحيته'));
    }

    const roleRows = await db.many(
      'SELECT role, scope_department_id FROM user_roles WHERE user_id = $1',
      [user.id],
    );
    const roles = roleRows.map((r) => r.role);

    const isPurePersonal =
      user.profile_type === 'personal' &&
      !user.workspace_id &&
      !req.auth.workspaceId &&
      roles.length === 0;

    let workspaceId = req.auth.workspaceId || user.workspace_id;
    if (!workspaceId && !isPurePersonal) {
      const ws = await ensureDefaultWorkspace();
      workspaceId = ws.id;
    }

    const resolved = await resolveEffectivePolicy(
      isPurePersonal ? null : workspaceId,
      user.id,
      isPurePersonal ? 'personal' : user.profile_type || 'workspace',
    );
    req.auth.workspaceId = workspaceId;
    req.auth.departmentId = user.department_id;
    req.auth.profileType = user.profile_type || 'workspace';
    req.auth.roles = roles;
    req.userRoles = roles;
    req.roleScopes = roleRows;
    req.effectivePolicy = resolved;
    req.policy = resolved.policies;
    req.policyVersion = resolved.version;
    req.policyLockedKeys = resolved.lockedKeys;
    return next();
  } catch (err) {
    return next(err);
  }
}

/**
 * Central PolicyGuard middleware: enforces a policy predicate before executing a route handler.
 * @param {string} policyKey
 * @param {(value: any, req: import('express').Request) => boolean} predicate
 * @param {string} errorCode
 * @param {string} errorMessage
 */
export function requirePolicy(
  policyKey,
  predicate = (val) => Boolean(val),
  errorCode = 'policy_denied',
  errorMessage = `العملية مرفوضة بموجب السياسة المؤسسية (${policyKey})`,
) {
  return async (req, res, next) => {
    if (!req.policy) {
      await new Promise((resolve, reject) => {
        attachPolicyContext(req, res, (err) => (err ? reject(err) : resolve()));
      }).catch(next);
      if (res.headersSent) return;
    }
    const val = req.policy?.[policyKey];
    if (!predicate(val, req)) {
      return next(forbidden(errorCode, errorMessage, { policy_key: policyKey, effective_value: val }));
    }
    return next();
  };
}

/**
 * Enforces RBAC role membership.
 * @param {string[]} allowedRoles
 */
export function requireRoles(...allowedRoles) {
  return async (req, res, next) => {
    if (!req.userRoles) {
      await new Promise((resolve, reject) => {
        attachPolicyContext(req, res, (err) => (err ? reject(err) : resolve()));
      }).catch(next);
      if (res.headersSent) return;
    }
    const roles = req.userRoles || [];
    if (roles.includes('SUPER_ADMIN') || allowedRoles.some((r) => roles.includes(r))) {
      return next();
    }
    return next(
      forbidden(
        'insufficient_role',
        `تتطلب هذه العملية أحد الأدوار التالية: ${allowedRoles.join(', ')}`,
      ),
    );
  };
}

/**
 * ADM-04 Separation of Duties check between IT_ADMIN and COMPLIANCE_OFFICER:
 * - IT_ADMIN cannot modify compliance_managed policies (retention.*, dlp.*) unless they also hold SUPER_ADMIN or COMPLIANCE_OFFICER.
 * - COMPLIANCE_OFFICER cannot manage users/devices/channels unless they also hold SUPER_ADMIN or IT_ADMIN.
 */
export function assertPolicyEditPermission(userRoles, policyKey) {
  const specMap = getPolicySpecMap();
  const spec = specMap.get(policyKey);
  if (!spec) {
    throw badRequest('unknown_policy_key', `مفتاح السياسة غير معروف: ${policyKey}`);
  }
  const isSuper = userRoles.includes('SUPER_ADMIN');
  if (isSuper) return;

  if (spec.compliance_managed) {
    if (!userRoles.includes('COMPLIANCE_OFFICER')) {
      throw forbidden(
        'compliance_separation_of_duties',
        `السياسة ${policyKey} خاضعة لمسؤول الامتثال (COMPLIANCE_OFFICER) ولا يمكن لمدير تقنية المعلومات تعديلها (فصل الصلاحيات ADM-04)`,
      );
    }
  } else if (!userRoles.includes('IT_ADMIN')) {
    throw forbidden(
      'it_admin_separation_of_duties',
      `السياسة ${policyKey} خاضعة لمدير تقنية المعلومات (IT_ADMIN) ولا يمكن لمسؤول الامتثال تعديلها (فصل الصلاحيات ADM-04)`,
    );
  }
}

/**
 * Enforces attachment upload policies: media.upload, chat.max_attachment_mb / media.max_mb (TC-POL-13),
 * and chat.allowed_mime_categories / media.allowed_types / chat.allowed_mime_types (TC-POL-14).
 */
export function assertAttachmentAllowed(policies = {}, { sizeBytes = 0, mimeType = '' } = {}) {
  if (policies['media.upload'] === false) {
    throw forbidden('policy_media_upload_disabled', 'رفع المرفقات والوسائط معطل بموجب سياسة المؤسسة (media.upload)');
  }

  const maxMb = Number(policies['chat.max_attachment_mb'] ?? policies['media.max_mb'] ?? 25);
  const maxBytes = maxMb * 1024 * 1024;
  if (sizeBytes > maxBytes) {
    throw badRequest(
      'attachment_too_large',
      `حجم المرفق يتجاوز الحد المسموح به في سياسة المؤسسة (${maxMb} MB)`,
    );
  }

  const mime = String(mimeType || '').toLowerCase().trim();
  if (!mime) return;

  const allowedTypes = policies['chat.allowed_mime_types'];
  if (Array.isArray(allowedTypes) && allowedTypes.length > 0 && !allowedTypes.includes('*/*')) {
    // Check if chat.allowed_mime_types was explicitly customized (or check category below)
    const defaultMimes = [
      'image/jpeg',
      'image/png',
      'image/webp',
      'application/pdf',
      'text/plain',
      'audio/mpeg',
      'audio/mp4',
      'audio/aac',
      'audio/ogg',
      'video/mp4',
    ];
    const isCustomizedMimeList =
      allowedTypes.length !== defaultMimes.length ||
      allowedTypes.some((m, i) => m !== defaultMimes[i]);
    if (isCustomizedMimeList && !allowedTypes.includes(mime)) {
      throw forbidden(
        'policy_mime_type_denied',
        `نوع الملف (${mime}) غير مسموح به بموجب سياسة المؤسسة (chat.allowed_mime_types)`,
      );
    }
  }

  const allowedCategories =
    policies['chat.allowed_mime_categories'] ||
    policies['media.allowed_types'] ||
    ['image', 'document', 'audio', 'video', 'archive'];

  let category = 'other';
  if (mime.startsWith('image/')) {
    category = 'image';
  } else if (mime.startsWith('video/')) {
    category = 'video';
  } else if (mime.startsWith('audio/')) {
    category = 'audio';
  } else if (
    mime.includes('zip') ||
    mime.includes('rar') ||
    mime.includes('7z') ||
    mime.includes('tar') ||
    mime.includes('gzip')
  ) {
    category = 'archive';
  } else if (
    mime.startsWith('text/') ||
    mime === 'application/pdf' ||
    mime.includes('msword') ||
    mime.includes('officedocument') ||
    mime.includes('vnd.') ||
    mime === 'application/json' ||
    mime === 'application/rtf'
  ) {
    category = 'document';
  }

  if (Array.isArray(allowedCategories) && !allowedCategories.includes(category)) {
    throw forbidden(
      'policy_mime_category_denied',
      `فئة الملف (${category}: ${mime}) غير مسموح بها بموجب سياسة المؤسسة`,
    );
  }
}
