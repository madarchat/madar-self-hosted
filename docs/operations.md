<div dir="rtl">

# التثبيت والتشغيل — مدار لمساحات العمل

---

## 1. التثبيت عند العميل

**المتطلبات:** خادم Linux، Docker + Compose (أو Node 20+ و PostgreSQL للتثبيت المباشر)، نطاق يشير للخادم، منفذا 80/443، و UDP للمكالمات.

```bash
git clone <repo> madar-self-hosted && cd madar-self-hosted
./setup.sh --docker          # يولّد الأسرار في .env ويشغّل كل الحاويات
```

ثم افتح لوحة الإدارة وأكمل معالج **`/setup`**: هوية مساحة العمل، المدير العام، قالب الحوكمة. عند الاعتماد يولّد الخادم مفتاح توقيع السياسات Ed25519 ويُقفل المعالج.

### خيارات `setup.sh`

| الخيار | العمل |
| :--- | :--- |
| `--docker` | كل شيء بالحاويات: PostgreSQL، Redis، MinIO، Coturn، الخادم، اللوحة |
| `--native` | على المضيف مباشرة بـ Node و PostgreSQL محليين |
| `--seed-admin` | إنشاء مساحة العمل والمدير من سطر الأوامر بدل المعالج. الرقم الوظيفي للمدير من `ADMIN_USER` (افتراضياً `EMP-100`) |
| `--reset-setup` | إعادة فتح معالج `/setup` |
| `--non-interactive` | بلا أسئلة (من `.env.setup` أو القيم الافتراضية) |
| `--update` | بعد `git pull`: إعادة البناء والتشغيل مع حفظ `.env` والبيانات |
| `--reconfigure` | إعادة توليد ملفات `.env` |
| `--check` | فحص الخادم ونقطة الاكتشاف واللوحة |
| `--stop` | إيقاف كل شيء |

### المنافذ (docker-compose)

| الخدمة | المنفذ |
| :--- | :--- |
| الخادم (`api`) | `${API_PORT:-5025}` + STUN UDP `${STUN_PORT:-3478}` |
| لوحة الإدارة | `${ADMIN_CONSOLE_PORT:-5030}` |
| MinIO | `${MINIO_PORT:-9000}` |
| Coturn | `3479` UDP/TCP + نطاق المرحِّل `49160–49200` UDP |
| Caddy | 80, 443 |

---

## 2. للتقييم والتطوير

```bash
cd madar_server && npm install && npm run migrate
node ../bin/seed-demo.js --force   # مساحة عمل «آفاق» (يمحو بيانات مساحة العمل الحالية)
npm start                          # http://localhost:5025
npm test                           # 34 اختباراً
```

البذرة تطبع رابط `madar://enroll?...` جاهزاً للمسح من التطبيق، وبيانات الدخول. تفاصيل مساحة العمل التجريبية (الموظفون، كلمات المرور، القنوات) في [SCENARIO_AFAQ_E2E_AR.md](SCENARIO_AFAQ_E2E_AR.md#مساحة-العمل-التجريبية).

---

## 3. `madarctl`

```bash
cd madar_server && node bin/madarctl.js <command>
```

| الأمر | العمل |
| :--- | :--- |
| `health` | حالة الخادم |
| `doctor` | فحص شامل: القاعدة، مفتاح التوقيع، الكتالوج، سلامة سلسلة التدقيق |
| `verify-audit` (`audit verify`) | التحقق من سلسلة هاش سجل التدقيق |
| `policy-list` (`policy list`) | السياسات الحالية |
| `rotate-keys` | تدوير مفتاح توقيع السياسات |
| `issue-enrollment [max_uses] [expires_hours]` | إصدار رمز انضمام |
| `bootstrap [standard\|regulated\|defense]` | تطبيق قالب حوكمة |
| `init-workspace --name … --admin-user … --admin-email … --admin-password … --preset …` | إنشاء مساحة العمل والمدير |

**لا يوجد أمر نسخ احتياطي.** انظر §5.

---

## 4. متغيرات البيئة

القائمة الكاملة في `madar_server/src/config/env.js` و`docker-compose.yml`. ما يخص مساحات العمل:

| المتغير | الغرض |
| :--- | :--- |
| `DEPLOYMENT_PROFILE=workspace` | يعطّل كل مسار لا يخص مساحات العمل (مثل FCM المباشر) |
| `DATABASE_URL`, `REDIS_URL` | البنية |
| `JWT_SECRET`, `ACCESS_TOKEN_TTL`, `REFRESH_TOKEN_TTL_DAYS` | الجلسات |
| `MADAR_MASTER_KEY` | تشفير الحقول عند التخزين. **فقده = فقد كل الرسائل.** احفظه خارج الخادم |
| `ADMIN_PLANE_SECRET` / `CONTROL_PLANE_KEY` | مفتاح اللوحة ← الخادم. يجب أن يتطابق في الاثنين |
| `ADMIN_API_ENABLED`, `ADMIN_ALLOWED_IPS` | عزل مستوى التحكم |
| `ADMIN_SESSION_SECRET`, `COOKIE_SECURE` | جلسات متصفح اللوحة |
| `MADAR_RELAY_URL` / `PUSH_RELAY_URL`, `TENANT_TOKEN` / `PUSH_RELAY_TOKEN` | مُرحِّل الإشعارات (غير موجود بعد — [architecture.md §7](architecture.md#7-الإشعارات)) |
| `TURN_*`, `STUN_*`, `ICE_PUBLIC_HOST`, `TURN_EXTERNAL_IP` | المكالمات |
| `MINIO_*` | تخزين الوسائط |
| `PUBLIC_URL`, `CORS_ORIGINS`, `TRUST_PROXY` | العنوان العام |

`CONTROL_PLANE_HMAC_SECRET` يولَّد ويُمرَّر لكنه غير مستعمل.

---

## 5. النسخ الاحتياطي والاستعادة

لا أداة مدمجة. الحد الأدنى:

```bash
docker compose exec postgres pg_dump -U "$DB_USER" "$DB_NAME" | gzip > madar-$(date +%F).sql.gz
docker run --rm -v madar-self-hosted_miniodata:/d -v "$PWD":/b alpine tar czf /b/minio-$(date +%F).tgz -C /d .
cp .env  backup/   # فيه MADAR_MASTER_KEY — بدونه النسخة عديمة الفائدة
```

اسم مجلد MinIO يتبع اسم مشروع compose؛ تحقق منه بـ `docker volume ls`.

---

## 6. النسخة التجريبية العامة

تعمل نسخة تجريبية لمساحة عمل «آفاق» على:

| الخدمة | النطاق |
| :--- | :--- |
| خادم مساحة العمل | `workspace.protosoftdev.online` |
| لوحة الإدارة | `control.protosoftdev.online` |

كلمات مرور النسخة العامة **ليست** الافتراضية الموجودة في `bin/seed-demo.js`؛ الافتراضية للتجربة المحلية فقط. عند تشغيل `seed-demo.js` على أي خادم مكشوف مرّر `--admin-password` و`--staff-password`.

```bash
cd madar_server && node ../bin/seed-demo.js --force --admin-password '...' --staff-password '...'
```

</div>
