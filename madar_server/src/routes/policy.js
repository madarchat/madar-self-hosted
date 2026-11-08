import { Router } from 'express';
import { db } from '../db/pool.js';
import { requireAuth } from '../middleware/auth.js';
import { attachPolicyContext } from '../middleware/policyGuard.js';
import {
  buildSignedPolicyBundle,
  loadPolicyCatalog,
  ensureDefaultWorkspace,
} from '../services/policyEngine.js';
import { validate, z } from '../lib/validate.js';

export const policyRouter = Router();

/** Public / Authenticated: returns the open policy catalog (specs/policy-catalog.json). */
policyRouter.get('/catalog', (_req, res) => {
  res.json({
    success: true,
    catalog: loadPolicyCatalog(),
  });
});

/** Returns the Ed25519 JWS signed policy bundle for the current user & workspace (Section 7.3 & POL-04). */
policyRouter.get(['/bundle', '/me'], requireAuth, attachPolicyContext, async (req, res) => {
  const workspaceId = req.auth.workspaceId || (await ensureDefaultWorkspace()).id;
  const bundle = await buildSignedPolicyBundle(workspaceId, req.auth.userId, req.auth.profileType || 'workspace');
  const p = bundle.payload.policies;

  // Build human-readable Arabic governance summary for "ما تديره مساحة عملي" screen (POL-04)
  const managedSummaryAr = {
    managed_by_institution: [
      `الاحتفاظ برسائل القنوات لمدة ${p['retention.message_days'] ?? p['retention.days'] ?? 365} يوم`,
      `الاحتفاظ بسجل التدقيق لمدة ${p['retention.audit_days'] ?? 730} يوم`,
      p['dlp.allow_copy'] ? 'النسخ من المحادثات مسموح' : 'منع نسخ النصوص خارج محادثات مساحة العمل',
      p['dlp.allow_external_share'] ? 'المشاركة الخارجية مسموحة' : 'منع مشاركة المحتوى والملفات خارج التطبيق',
      p['dlp.screenshot_policy'] === 'block' || p['security.screenshot_block']
        ? 'حظر لقطات الشاشة وتسجيل الشاشة داخل مساحة العمل'
        : p['dlp.screenshot_policy'] === 'audit'
          ? 'تسجيل حدث تدقيق عند أخذ لقطة شاشة'
          : 'لقطات الشاشة مسموحة',
      `الحد الأعلى للأجهزة المسجلة لكل موظف: ${p['device.max_per_user'] ?? p['device.max_devices'] ?? 3}`,
      'إمكانية المسح الانتقائي لخزنة العمل فقط عند فقدان الجهاز أو انتهاء الخدمة',
    ],
    never_touched_by_institution: [
      'لا تملك إدارة مساحة العمل أي وصول إلى خزنتك الشخصية أو محادثاتك الخاصة في مدار',
      'لا يمكن لإدارة مساحة العمل الاطلاع على صورك أو ملفاتك أو جهات اتصالك على الهاتف',
      'لا يتتبع التطبيق موقعك الجغرافي ولا يصل إلى الكاميرا أو الميكروفون في الخلفية',
      'المسح عن بُعد يقتصر حصرياً على خزنة العمل دون المساس بأي بيانات شخصية',
    ],
  };

  res.json({
    success: true,
    ...bundle,
    effective_policy: p,
    managed_summary_ar: managedSummaryAr,
  });
});

/** Client acknowledges that it has verified and applied a policy bundle version. */
policyRouter.post(
  '/ack',
  requireAuth,
  validate({
    body: z.object({
      version: z.coerce.number().int().positive(),
      device_id: z.string().uuid().optional(),
    }),
  }),
  async (req, res) => {
    const deviceId = req.auth.deviceId || req.body.device_id;
    if (deviceId) {
      await db.query(
        `UPDATE devices
         SET policy_version = $2, policy_applied_at = NOW(), last_seen_at = NOW()
         WHERE id = $1 AND user_id = $3`,
        [deviceId, req.body.version, req.auth.userId],
      );
    }
    res.json({ success: true, version: req.body.version });
  },
);
