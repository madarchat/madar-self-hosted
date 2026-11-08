<div dir="rtl">

# مدار لمساحات العمل — معمارية الخادم ولوحة الإدارة

> يصف الكود الموجود في هذا المستودع كما هو اليوم (2026-11-07).
> التطبيق الذي يستعمله الموظف (وضع مساحة العمل في تطبيق مدار) في مستودع منفصل.

---

## 1. الصورة في دقيقة

```
 هاتف الموظف (تطبيق مدار، وضع مساحة العمل)
        │  HTTPS + WebSocket
        ▼
 ┌──────────────────────────────────────┐        ┌──────────────────────────────┐
 │ madar_server   :5025 (docker)        │◄───────│ madar_admin_console  :5030   │
 │ Express + WebSocket + STUN           │ مفتاح   │ Next.js — واجهة + BFF         │
 │ قاعدة PostgreSQL واحدة (49 جدولاً)   │ مستوى   │ بلا اتصال بقاعدة البيانات     │
 └───────┬──────────────────────────────┘ التحكم  └──────────────────────────────┘
         │                                              ▲ متصفح المدير
   PostgreSQL · Redis · MinIO · Coturn · Caddy
```

**منتج لمساحة عمل واحدة يستضيفه العميل بنفسه.** عملية واحدة، قاعدة بيانات واحدة، بلا اتصال بأي خادم تابع لمدار. على خادم العرض الحالي يعمل على 5026 واللوحة على 5031 حتى لا يصطدما بسحابة الأفراد.

**ما ليس هنا عن قصد:** مسارات الأفراد (`/moments`, `/people`, `/pulse`, `/invites`) وجداولها غير موجودة، فلا تستطيع إدارة مساحة العمل جمع بيانات اجتماعية شخصية عن موظفيها.

---

## 2. خريطة الكود

```
madar-self-hosted/
├── madar_server/
│   ├── src/
│   │   ├── index.js, app.js        الإقلاع، التوجيه، /.well-known/madar-workspace.json، /health
│   │   ├── config/env.js           متغيرات البيئة + assertEnv
│   │   ├── routes/                 موجّه لكل مجال (انظر §3)
│   │   ├── middleware/             auth (JWT) · controlPlaneGuard · policyGuard
│   │   ├── services/               policyEngine · push (blind wake) · blocks · relations
│   │   ├── realtime/               ws.js (WebSocket) · hub.js · calls.js · ice.js
│   │   ├── lib/                    fieldCrypto (تشفير الحقول) · jws · audit · totp · arabicSearch · password …
│   │   ├── jobs/cleanup.js         مهمة كل دقيقة (انتهاء الجلسات، التنظيف)
│   │   ├── stun/                   STUN UDP
│   │   └── db/
│   │       ├── pool.js, migrate.js
│   │       └── migrations/001_enterprise_baseline.sql   ← المخطط كاملاً
│   ├── bin/madarctl.js             أداة سطر الأوامر
│   └── test/
├── madar_admin_console/            Next.js — src/app (صفحات + admin-api)، src/server.js
├── bin/seed-demo.js                مساحة عمل «آفاق» التجريبية
├── setup.sh                        المثبّت
├── docker-compose.yml, deploy/     caddy, coturn
└── specs/                          openapi.yaml · asyncapi.yaml · policy-catalog.json
```

---

## 3. الواجهات (`/api/v1`)

| البادئة | الغرض |
| :--- | :--- |
| `/enroll`, `/auth/*` | الانضمام برمز QR، الدخول برقم وظيفي وكلمة مرور، تحديث الرمز، TOTP، الجلسات (`workspace_auth.js`, `auth.js`) |
| `/channels` | القنوات: الرسائل، **القرارات**، **المتابعات**، **المراجع المثبّتة**، الملخص |
| `/decisions`, `/followups` | عمليات على القرارات والمتابعات |
| `/broadcasts` | **التعاميم** الرسمية: قوالب، تأكيد الاطلاع، أسئلة فهم، إحصاءات، تذكير، تصدير |
| `/threads` | الرسائل المباشرة |
| `/directory`, `/presence`, `/users` | دليل الموظفين، الحضور (متاح، في اجتماع…)، الملف |
| `/hub` | مركز الاهتمام (ما ينتظر الموظف) |
| `/search` | بحث موحّد بتطبيع عربي (`lib/arabicSearch.js`) |
| `/policy` | كتالوج السياسات |
| `/devices`, `/keys`, `/media`, `/calls` | الأجهزة، المفاتيح، الوسائط، إعداد ICE |
| `/relay`, `/v1/*` | تسجيل مقابض الإشعارات لمُرحِّل خارجي (انظر §7) |
| `/admin/*` | **مستوى التحكم** — محمي بـ `controlPlaneGuard` (انظر §5) |

خارج `/api/v1`: `GET /.well-known/madar-workspace.json` (هوية مساحة العمل؛ يقرؤه التطبيق قبل إرسال أي بيانات) و `GET /health`.

المواصفات الآلية في `specs/openapi.yaml` و`specs/asyncapi.yaml` — **لم تُراجَع مقابل الكود في هذا التحديث**؛ اعتبر الكود هو المرجع.

### واجهات الإدارة (`/admin`)

`setup` (معالج أول تشغيل) · `overview` · `departments` · `channels` · `users` (إنشاء، استيراد CSV، تعديل، إعادة كلمة مرور، **إنهاء خدمة** `offboard`) · `enrollment-tokens` · `devices` (إلغاء، **مسح عن بعد**) · `policies` (مجموعات، معاينة، نشر، تراجع) · `audit-log` (+ `verify`) · `legal-holds` · `break-glass` (طلب + موافقة ثانية).

---

## 4. نموذج البيانات

قاعدة واحدة؛ المخطط كاملاً في `001_enterprise_baseline.sql` (49 جدولاً). أهمها:

| المجال | الجداول |
| :--- | :--- |
| مساحة العمل | `workspace`, `departments`, `service_entitlements` |
| الأشخاص والأدوار | `users`, `user_roles` (`SUPER_ADMIN`, `IT_ADMIN`, `EXEC_MANAGER`, `COMPLIANCE_OFFICER`, `DEPT_HEAD`, `MODERATOR`, `BROADCASTER`, `MEMBER`, `GUEST`) |
| الدخول | `credentials`, `sessions`, `refresh_tokens`, `mfa_factors`, `recovery_codes`, `auth_codes`, `auth_providers` (إعدادات SSO مشفّرة) |
| الأجهزة والانضمام | `devices`, `enrollment_tokens`, `user_key_bundles` |
| القنوات | `channels`, `channel_members`, `channel_messages`, `channel_references`, `mentions`, `reactions`, `attachments` |
| ذاكرة مساحة العمل | `decisions`, `followups`, `hub_items` |
| الرسائل المباشرة | `threads`, `thread_members`, `messages`, `message_edits`, `offline_message_queue`, `user_blocks` |
| التعاميم | `broadcasts`, `broadcast_versions`, `broadcast_recipients`, `broadcast_receipts`, `broadcast_templates` |
| السياسات | `policy_entries`, `policy_versions`, `policy_groups`, `policy_group_members`, `policy_signing_keys` |
| الحوكمة | `audit_log`, `legal_holds`, `break_glass` |
| البحث | `search_docs` |
| الإشعارات والمكالمات | `relay_push_handles`, `relay_wake_events`, `calls` |

**التشفير عند التخزين:** نصوص الرسائل والتعاميم وإعدادات مزودي الهوية تُشفَّر بـ `lib/fieldCrypto.js` (`encryptField` / `decryptField`) بمفتاح `MADAR_MASTER_KEY`. هذا **ليس تشفيراً طرفياً**: الخادم يفك التشفير ليخدم البحث والحفظ القانوني والتصدير. هذا مقصود، ويُعرض للموظف في شاشة «ما تديره مساحة عملي».

**إضافة جدول:** ملف ترحيل جديد مرقّم (`002_….sql`) بجانب الأساسي، idempotent. لا تعدّل `001` بعد تطبيقه على أي خادم.

---

## 5. لوحة الإدارة ومستوى التحكم

`madar_admin_console` تطبيق Next.js يعمل كـ BFF (Backend for Frontend):

* **لا تملك اتصالاً بقاعدة البيانات.** كل أمر إداري طلب HTTP إلى `/api/v1/admin/*` عبر `admin-api/proxy`.
* تضيف الترويسة `X-Madar-Control-Plane-Key` بقيمة `ADMIN_PLANE_SECRET` (أو `CONTROL_PLANE_KEY`). الخادم يقارنها بمقارنة ثابتة الزمن.
* جلسة المتصفح: كوكي HttpOnly + رمز CSRF (`X-Madar-CSRF`) على كل طلب يغيّر شيئاً.

`controlPlaneGuard` على الخادم:

1. `ADMIN_API_ENABLED=false` ← كل `/admin` يُرجع 404 (لعقد الحافة المكشوفة).
2. `ADMIN_ALLOWED_IPS` ← فقط من عناوين الإدارة.
3. `ADMIN_PLANE_SECRET` ← فقط من يحمل المفتاح (اللوحة و`madarctl`).

> ⚠️ المفتاح **سر مشترك يُرسل كما هو** وليس توقيع HMAC لكل طلب، رغم أن وثائق سابقة قالت ذلك. إن لم يُضبط `ADMIN_PLANE_SECRET` يُتجاوز الشرط الثالث (يبقى رمز المدير JWT مطلوباً). `CONTROL_PLANE_HMAC_SECRET` يولّده `setup.sh` ويمرّره docker-compose، لكن **لا يقرؤه أي كود**.

---

## 6. السياسات والتدقيق

* **السياسات موقّعة:** عند إتمام معالج `/setup` يولّد الخادم زوج مفاتيح Ed25519. كل حزمة سياسات تُنشر كـ JWS (`alg: EdDSA`)، والتطبيق يتحقق من التوقيع ويرفض أي إصدار أقدم من المخزّن.
* **الكتالوج:** `specs/policy-catalog.json` (58 مفتاحاً على الخادم؛ التطبيق يحمل نسخة في `feature_gate.dart`). أمثلة: منع النسخ، علامة مائية، مدة الجلسة دون اتصال.
* **`policyGuard`** يطبّق السياسات على الطلبات في الخادم.
* **سلسلة تدقيق:** كل سجل في `audit_log` يحمل هاش السجل السابق. `madarctl verify-audit` أو `GET /admin/audit-log/verify` يكشف أي تعديل.
* **كسر الزجاج:** وصول استثنائي يحتاج طلباً من مسؤول وموافقة مسؤول **آخر** (`dual_control_violation` إن حاول مقدّم الطلب الموافقة بنفسه).
* **الحفظ القانوني:** `legal_holds` يمنع حذف رسائل القناة أو المستخدم الخاضع للحفظ.
* **إنهاء الخدمة إجراء إداري فقط.** `DELETE /users/me` يُرجع `offboarding_is_administrative`.
* **المسح عن بعد:** `POST /admin/devices/:id/wipe` ← إطار `device.wipe` عبر WebSocket ← التطبيق يمحو بيانات مساحة العمل.

---

## 7. الإشعارات

* التطبيق مفتوح أو متصل: WebSocket مباشرة.
* التطبيق مغلق: «إيقاظ أعمى» (`services/push.js` → `dispatchBlindWake`) — إشارة بلا محتوى (`{t:"wake", vault_id, sync_hint}`) تُرسل إلى مُرحِّل خارجي على `MADAR_RELAY_URL` / `PUSH_RELAY_URL` مع `TENANT_TOKEN`، والمُرحِّل يحوّلها لـ FCM/APNs.

> ⚠️ **المُرحِّل غير موجود** في أي مستودع، **والتطبيق لا يسجّل مقبضاً** عبر `POST /relay/handles` أصلاً. بدون ضبطه تُسجَّل محاولة الإيقاظ في `relay_wake_events` ولا يصل شيء، أي أن **الموظف لا يستلم إشعاراً والتطبيق مغلق**. هذا أكبر نقص وظيفي في منتج مساحات العمل اليوم.

---

## 8. ما هو نموذج أولي أو غير مكتمل

| البند | الحالة الحقيقية |
| :--- | :--- |
| مُرحِّل الإشعارات | غير مبني — انظر §7 |
| SSO — LDAP | **محاكاة.** لا يتصل بخادم LDAP. يبحث عن المستخدم في قائمة JSON داخل إعداد المزود، ويقبل كلمة مرور نصية أو هاش. لا تستعمله مع عميل |
| SSO — OIDC | يقبل رموزاً موقّعة Ed25519 أو HS256 بـ `client_secret` فقط. المزودون الحقيقيون (Azure AD، Keycloak، Google) يوقّعون RS256 عبر JWKS — **لن يعمل معهم** |
| SSO — SAML | تحقق مبسّط من الإفادة؛ لم يُختبر مع مزود حقيقي |
| `env.js` | نسخة من خادم الأفراد: فيه متغيرات لا تخص مساحات العمل (`INVITE_*`, `LOOKUP_*`, `FIREBASE_*`). غير ضارة لكنها مربكة |
| بقايا شخصية | `routes/auth.js` فيه `/recaptcha`، و`lib/` فيه `phoneHash`, `lookupLimit`, `firebasePhone`, `sms` — مستعملة من مسارات قديمة؛ تحتاج مراجعة لإزالتها |
| `specs/*.yaml` | لم تُراجَع مقابل الكود |
| `POST /relay/handles` | **بلا مصادقة** (عليه حد المعدّل العام فقط) — أي أحد يستطيع تسجيل مقابض. يجب ربطه بجلسة جهاز |
| قنوات `confidential_e2ee` / `enhanced_privacy` | **ليست مشفّرة طرفياً** رغم الاسم: التطبيق يرسل النص، والخادم فقط لا يفهرسه ويخفيه عن كسر الزجاج |
| WebSocket | يقبل الرمز بأربع طرق منها `?token=` في الرابط (يظهر في سجلات الوكيل العكسي). تطبيق مساحة العمل يرسله في أول إطار؛ يجب إلغاء طريقة الرابط |
| حذف البيانات حسب مدة الاحتفاظ | يدوي فقط (`POST /admin/retention/purge`)؛ لا مهمة مجدولة |
| `/admin*` في Caddyfile الذي يولّده `setup.sh` | يوجّه لوحة الإدارة تحت مسار فرعي واللوحة بلا `basePath` — غالباً لا يعمل؛ استعمل نطاقاً فرعياً مستقلاً للوحة (لم يُختبر) |

---

## 9. الاختبارات

```bash
cd madar_server && npm test      # 34 اختباراً
```

* `enterprise_e2e.test.js` — انضمام حقيقي برمز وكلمة مرور، محتوى الرمز، القنوات، الدليل، التعاميم المفكوكة، وغياب جداول الأفراد من المخطط.
* `workspace_v1.test.js` — الإعداد، الأدوار، السياسات.
* `keys.test.js`, `validate.test.js`.

السيناريو الحيّ من التطبيق مقابل هذا الخادم: [SCENARIO_AFAQ_E2E_AR.md](SCENARIO_AFAQ_E2E_AR.md).

</div>
