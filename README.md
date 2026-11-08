<div dir="rtl">

# مدار لمساحات العمل — الاستضافة الذاتية

مساحة عمل تعمل بالكامل على خوادمك، بديلاً للبريد الإلكتروني: قنوات رسمية، سجل قرارات، متابعات، تعاميم بتأكيد اطلاع، ودليل موظفين. لا اتصال بأي خادم تابع لمدار.

تطبيق الموظف هو تطبيق مدار نفسه في وضع مساحة العمل (من المتجر أو نسخة الويب [app.protosoftdev.online](https://app.protosoftdev.online)).

```bash
git clone https://github.com/madarchat/madar-self-hosted.git
cd madar-self-hosted
```

التوثيق المصوّر: [docs.protosoftdev.online](https://docs.protosoftdev.online).

**👈 ابدأ من [docs/README.md](docs/README.md).**

---

| المكوّن | المسار | المنفذ (docker / خادم العرض) |
| :--- | :--- | :---: |
| الخادم | `madar_server/` | 5025 / 5026 |
| لوحة الإدارة | `madar_admin_console/` | 5030 / 5031 |
| أداة الإدارة | `madar_server/bin/madarctl.js` | — |
| مساحة العمل التجريبية | `bin/seed-demo.js` | — |
| المثبّت | `setup.sh` + `docker-compose.yml` | — |

```bash
./setup.sh --docker                                   # تثبيت كامل عند العميل
# أو للتطوير:
cd madar_server && npm install && npm run migrate && npm start
npm test                                              # 34 اختباراً
```

| الوثيقة | المحتوى |
| :--- | :--- |
| [docs/architecture.md](docs/architecture.md) | الخادم، اللوحة، البيانات، السياسات، وما هو نموذج أولي |
| [docs/operations.md](docs/operations.md) | التثبيت، `madarctl`، البيئة، النسخ الاحتياطي |
| [docs/SCENARIO_AFAQ_E2E_AR.md](docs/SCENARIO_AFAQ_E2E_AR.md) | جولة مصوّرة |
| [SECURITY.md](SECURITY.md) | الأمان والإبلاغ عن الثغرات |

الترخيص: AGPL-3.0-only.

</div>
