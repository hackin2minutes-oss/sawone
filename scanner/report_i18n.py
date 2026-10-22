"""Arabic text for the Sawone report (report.py --lang ar).

Keys are the English text exactly as report.py passes it to T(), with whitespace collapsed; values may
use the same {placeholders}. Tool output (finding titles, rule IDs, paths, package names) is never
translated. Terminology follows common Saudi cybersecurity usage (NCA documents): ثغرة، حرجة، عالية،
متوسطة، منخفضة، تقييم الثغرات، اختبار الاختراق، الضوابط.
"""

AR = {
    # ---------------------------------------------------------------- report frame
    "Application Security<br/>Assessment Report": "تقرير تقييم<br/>أمن التطبيقات",
    "CONFIDENTIAL": "سري",
    "Contents": "المحتويات",
    "Appendix {x}": "الملحق {x}",
    "this report describes unremediated security weaknesses. Share it only with people responsible for fixing or "
    "governing them.": "يصف هذا التقرير نقاط ضعف أمنية لم تُعالج بعد. لا تشاركه إلا مع المسؤولين عن معالجتها أو "
                       "حوكمتها.",
    "Generated automatically by Sawone from open-source scanners pinned for this run. Findings are tool output and "
    "may include false positives; validate before acting on them.":
        "أُنشئ تلقائياً بواسطة Sawone من أدوات فحص مفتوحة المصدر مثبتة الإصدارات لهذا التشغيل. النتائج مخرجات أدوات "
        "وقد تتضمن نتائج إيجابية كاذبة؛ تحقق منها قبل اتخاذ أي إجراء.",
    "Repository": "المستودع", "Branch / ref": "الفرع / المرجع", "Commit": "الإيداع (Commit)",
    "Pipeline run": "تشغيل خط النشر", "Generated": "تاريخ الإنشاء", "Enforcement": "وضع التطبيق",
    "Gate threshold": "حد البوابة", "Pull request": "طلب الدمج", "Container image": "صورة الحاوية",
    "Enforce — failed gates block the pipeline": "إلزامي — البوابات الفاشلة توقف خط النشر",
    "Report only — gates evaluated, pipeline not blocked": "تقرير فقط — تُقيَّم البوابات دون إيقاف خط النشر",
    "{t} (fixable) · CISA KEV at any severity": "{t} (القابلة للإصلاح) · ثغرات CISA KEV بأي درجة خطورة",
    "Only findings new in this change block": "تمنع فقط النتائج الجديدة في هذا التغيير",

    # ---------------------------------------------------------------- verdict
    "NO RESULTS": "لا توجد نتائج", "INCOMPLETE": "غير مكتمل", "FAILED": "لم يجتز", "PASSED": "اجتاز",
    "The scan produced no gate results.": "لم ينتج الفحص أي نتائج للبوابات.",
    "{n} scanner(s) did not complete, so results are missing. The other gates passed.":
        "لم تكتمل {n} من أدوات الفحص، لذا توجد نتائج ناقصة. اجتازت البوابات الأخرى.",
    "{f} of {t} security gates failed": "لم تجتز {f} من أصل {t} بوابة أمنية",
    "and {n} scanner(s) did not complete": " ولم تكتمل {n} من أدوات الفحص",
    "Report-only mode: the pipeline was not blocked; in enforce mode it would have been.":
        "وضع التقرير فقط: لم يُوقَف خط النشر، وكان سيُوقَف في الوضع الإلزامي.",
    "All {t} security gates passed.": "اجتازت جميع البوابات الأمنية ({t}).",

    # ---------------------------------------------------------------- headings
    "Executive summary": "الملخص التنفيذي", "Results by stage": "النتائج حسب المرحلة",
    "Most significant risks": "أهم المخاطر", "Priority actions": "الإجراءات ذات الأولوية",
    "Scope and method": "النطاق والمنهجية", "What was assessed": "ما تم تقييمه", "What was detected": "ما تم اكتشافه",
    "How results are judged": "كيف تُقيَّم النتائج", "Security gate results": "نتائج البوابات الأمنية",
    "Findings by tool": "النتائج حسب الأداة", "Pipeline jobs": "مهام خط النشر",
    "Risk-ranked findings": "النتائج مرتبة حسب الخطورة", "Trend and fix deadlines": "الاتجاه ومواعيد المعالجة",
    "Age of blocking findings": "عمر النتائج المانعة", "Past their fix deadline": "تجاوزت موعد المعالجة",
    "Detailed results": "النتائج التفصيلية", "Compliance evidence": "أدلة الامتثال",
    "Accepted risks and false positives": "المخاطر المقبولة والنتائج الإيجابية الكاذبة",
    "False-positive rate by tool": "نسبة النتائج الإيجابية الكاذبة حسب الأداة",
    "Supply chain and release": "سلسلة الإمداد والإصدار", "Tool versions": "إصدارات الأدوات",
    "Definitions": "التعريفات", "Report artefacts": "ملفات التقرير", "Evidence index": "فهرس الأدلة",

    # ---------------------------------------------------------------- severities, statuses, tags
    "Critical": "حرجة", "High": "عالية", "Medium": "متوسطة", "Low": "منخفضة", "Unrated": "غير مصنفة",
    "Very high": "عالية جداً",
    "Passed": "اجتاز", "Failed": "لم يجتز", "Scanner error": "خطأ في أداة الفحص", "Skipped": "تم تخطيه",
    "Report only": "تقرير فقط", "Cancelled": "أُلغي",
    "Blocking": "مانعة", "Tracked": "متابَعة", "Accepted": "مقبولة", "False positive": "إيجابية كاذبة",
    "LIVE": "نشط", "New": "جديدة", "escalated": "صُعّدت", "overdue since {d}": "متأخرة منذ {d}",
    "exception expired {d}": "انتهى الاستثناء {d}", "also: {r}": "أيضاً: {r}",
    "Info": "معلومة", "Informational": "معلوماتية", "image": "الصورة",
    "Evidenced": "مُثبت بالأدلة", "Gap": "فجوة", "Unverified": "غير مُتحقق منه", "Not assessed": "لم يُقيَّم",

    # ---------------------------------------------------------------- stages
    "Risk policy": "سياسة المخاطر", "Pipeline integrity": "سلامة خط النشر", "Scanner": "أداة الفحص",
    "Threat modelling": "نمذجة التهديدات", "Secrets detection": "كشف الأسرار",
    "Static application security testing (SAST)": "الاختبار الثابت لأمن التطبيقات (SAST)",
    "Software composition analysis (SCA)": "تحليل مكونات البرمجيات (SCA)",
    "Licence compliance": "الامتثال للتراخيص", "Infrastructure as code (IaC)": "البنية التحتية كرمز (IaC)",
    "Kubernetes and Helm": "Kubernetes وHelm", "CI/CD pipeline security": "أمن خطوط CI/CD",
    "Container image security": "أمن صور الحاويات",
    "Dynamic application security testing (DAST)": "الاختبار الديناميكي لأمن التطبيقات (DAST)",
    "Interactive application security testing (IAST)": "الاختبار التفاعلي لأمن التطبيقات (IAST)",
    "Runtime protection": "الحماية أثناء التشغيل", "Vulnerability tracking": "تتبع الثغرات",
    "Baseline exceptions and the threat-intelligence feeds (CISA KEV, FIRST EPSS) that decide which findings block.":
        "استثناءات خط الأساس ومصادر استخبارات التهديدات (CISA KEV و FIRST EPSS) التي تحدد النتائج المانعة.",
    "Jobs that crashed or produced no report.": "المهام التي تعطلت أو لم تُنتج تقريراً.",
    "The scanner's own health.": "سلامة أداة الفحص نفسها.",
    "Design-level threats derived from the threat model kept in the repository. Every threat at or above the "
    "configured severity must be fixed or carry a recorded decision.":
        "تهديدات على مستوى التصميم مستخرجة من نموذج التهديدات المحفوظ في المستودع. يجب معالجة كل تهديد بالخطورة "
        "المحددة أو أعلى، أو توثيق قرار بشأنه.",
    "Credentials, keys and tokens committed to the repository, including its full Git history (Gitleaks), and secrets "
    "verified live against their provider (TruffleHog).":
        "بيانات الاعتماد والمفاتيح والرموز المودعة في المستودع، بما في ذلك سجل Git الكامل (Gitleaks)، والأسرار التي "
        "تم التحقق من أنها نشطة لدى مزودها (TruffleHog).",
    "Source code analysed for injection, unsafe deserialisation, weak cryptography and other code-level flaws "
    "(Semgrep).": "تحليل الشيفرة المصدرية بحثاً عن الحقن وإلغاء التسلسل غير الآمن والتشفير الضعيف وغيرها من عيوب "
                  "الشيفرة (Semgrep).",
    "Third-party dependencies checked against vulnerability databases (Trivy, with OSV-Scanner as a cross-check), "
    "and a software bill of materials of the repository itself (Syft).":
        "فحص المكتبات الخارجية مقابل قواعد بيانات الثغرات (Trivy، مع OSV-Scanner للتحقق المتقاطع)، وقائمة مكونات "
        "برمجية (SBOM) للمستودع نفسه (Syft).",
    "Dependency licences checked for restricted or forbidden terms (Trivy).":
        "فحص تراخيص المكتبات بحثاً عن شروط مقيدة أو محظورة (Trivy).",
    "Terraform, Dockerfiles and other configuration checked for insecure settings (Trivy config, with Checkov as a "
    "second opinion, and Hadolint for Dockerfiles).":
        "فحص ملفات Terraform وDockerfile وغيرها من الإعدادات بحثاً عن إعدادات غير آمنة (Trivy config، مع Checkov "
        "كرأي ثانٍ، وHadolint لملفات Dockerfile).",
    "Manifests validated against the Kubernetes schemas (kubeconform) and reviewed for workload hardening "
    "(kube-linter, optional OPA policies).":
        "التحقق من ملفات Kubernetes مقابل المخططات المعتمدة (kubeconform) ومراجعة تحصين أعباء العمل (kube-linter، "
        "وسياسات OPA الاختيارية).",
    "Workflow definitions checked for errors (actionlint) and for supply-chain risks such as script injection, "
    "excessive permissions and unpinned actions (zizmor).":
        "فحص تعريفات سير العمل بحثاً عن الأخطاء (actionlint) ومخاطر سلسلة الإمداد مثل حقن السكربتات والصلاحيات "
        "المفرطة والإجراءات غير المثبتة (zizmor).",
    "The image built from this commit: its software bill of materials (Syft), known vulnerabilities in OS and "
    "language packages (Trivy, cross-checked by Grype), secrets left in its layers, and CIS image benchmark checks "
    "(Dockle).": "الصورة المبنية من هذا الإيداع: قائمة مكوناتها البرمجية (Syft)، والثغرات المعروفة في حزم نظام "
                 "التشغيل واللغات (Trivy، مع تحقق متقاطع عبر Grype)، والأسرار المتبقية في طبقاتها، وفحوصات معيار "
                 "CIS للصور (Dockle).",
    "The running application attacked from outside: passive baseline, active full scan and API scan driven by the "
    "OpenAPI specification (OWASP ZAP), plus template checks (Nuclei). When credentials are configured the scans run "
    "as a logged-in user.": "مهاجمة التطبيق أثناء تشغيله من الخارج: فحص أساسي سلبي، وفحص نشط كامل، وفحص للواجهات "
                            "البرمجية وفق مواصفات OpenAPI (OWASP ZAP)، إضافة إلى فحوصات القوالب (Nuclei). عند ضبط "
                            "بيانات الدخول تعمل الفحوصات كمستخدم مسجّل الدخول.",
    "An agent inside the running application observed data flows during the scanner's traffic.":
        "راقب وكيل داخل التطبيق تدفقات البيانات أثناء حركة أداة الفحص.",
    "A web application firewall (ModSecurity with the OWASP Core Rule Set) placed in front of the application, "
    "checked to block common attacks while letting legitimate traffic through.":
        "جدار حماية لتطبيقات الويب (ModSecurity مع OWASP Core Rule Set) أمام التطبيق، يُتحقق من أنه يمنع الهجمات "
        "الشائعة ويسمح بالحركة المشروعة.",
    "Results imported into DefectDojo for triage and tracking.": "استيراد النتائج إلى DefectDojo للفرز والمتابعة.",

    # ---------------------------------------------------------------- executive summary
    "Gates failed": "بوابات لم تجتز", "Blocking findings": "نتائج مانعة", "Critical (blocking)": "حرجة (مانعة)",
    "Known exploited (KEV)": "مستغلة فعلياً (KEV)", "Live secrets": "أسرار نشطة", "Past fix deadline": "تجاوزت موعد المعالجة",
    "{u} unique findings after merging {m} duplicates reported by more than one tool · {a} accepted in the baseline":
        "{u} نتيجة فريدة بعد دمج {m} نتيجة مكررة أبلغت عنها أكثر من أداة · {a} مقبولة في خط الأساس",
    "{n} new in this change": "{n} جديدة في هذا التغيير", "{n} scanner error(s)": "{n} خطأ في أدوات الفحص",
    "P1: fix before release · P2: fix in the current cycle · P3: schedule. Derived automatically from the gate "
    "results; adjust to your risk appetite.":
        "P1: عالجها قبل الإصدار · P2: عالجها في الدورة الحالية · P3: جدولها. مستخلصة تلقائياً من نتائج البوابات؛ "
        "عدّلها وفق مستوى تقبّلك للمخاطر.",
    # actions (areas)
    "Secrets": "الأسرار", "Known-exploited vulnerabilities": "الثغرات المستغلة فعلياً",
    "Running application": "التطبيق أثناء التشغيل", "Source code": "الشيفرة المصدرية", "Dependencies": "المكتبات",
    "Container image": "صورة الحاوية", "Infrastructure as code": "البنية التحتية كرمز", "Kubernetes": "Kubernetes",
    "CI/CD": "CI/CD", "Threat model": "نموذج التهديدات", "Fix deadlines": "مواعيد المعالجة",
    "Scan coverage": "تغطية الفحص",
    # actions (text)
    "Revoke and rotate the {n} exposed credential(s) now, then remove them from the code, the image and the Git "
    "history. Treat every leaked secret as compromised: removing it from the latest commit does not make it safe.":
        "ألغِ بيانات الاعتماد المكشوفة ({n}) واستبدلها فوراً، ثم أزلها من الشيفرة والصورة وسجل Git. تعامل مع كل "
        "سر مسرّب على أنه مخترق: حذفه من آخر إيداع لا يجعله آمناً.",
    "{n} of them were verified as live against their provider.": "تم التحقق من أن {n} منها نشطة لدى مزودها.",
    "Patch the {n} vulnerability(ies) listed in CISA's Known Exploited Vulnerabilities catalogue first: {ids}.":
        "عالج أولاً الثغرات ({n}) المدرجة في فهرس CISA للثغرات المستغلة فعلياً: {ids}.",
    "Fix the {n} high-risk issue(s) confirmed by attacking the running application: {names}.":
        "عالج المشكلات عالية الخطورة ({n}) التي تأكدت بمهاجمة التطبيق أثناء تشغيله: {names}.",
    "Fix {n} high-severity code finding(s); most frequent: {rules}.":
        "عالج نتائج الشيفرة عالية الخطورة ({n})؛ الأكثر تكراراً: {rules}.",
    "Upgrade {p} dependency(ies) with fixable advisories ({n} in total)":
        "حدّث المكتبات ({p}) التي لها إصلاحات متاحة ({n} ثغرة إجمالاً)",
    ", for example {ex}.": "، مثل {ex}.",
    "Rebuild the image to clear {n} fixable advisory(ies)": "أعد بناء الصورة لمعالجة الثغرات القابلة للإصلاح ({n})",
    ": {n} are in operating-system packages and are fixed by rebuilding on a current base image":
        ": منها {n} في حزم نظام التشغيل وتُعالج بإعادة البناء على صورة أساس حديثة",
    "; the rest need the application dependency upgrades above.": "؛ ويتطلب الباقي تحديثات المكتبات المذكورة أعلاه.",
    "Fix {n} misconfiguration(s) in {files} before the next apply; they ship to every environment built from this code.":
        "عالج الإعدادات الخاطئة ({n}) في {files} قبل التطبيق القادم؛ فهي تنتقل إلى كل بيئة تُبنى من هذه الشيفرة.",
    "Fix the manifest validation and policy failures listed in the Kubernetes section.":
        "عالج إخفاقات التحقق والسياسات المذكورة في قسم Kubernetes.",
    "Harden the workflows: {n} high-risk pattern(s) flagged by zizmor (for example script injection, broad permissions "
    "or unpinned actions).": "حصّن ملفات سير العمل: رصد zizmor أنماطاً عالية الخطورة ({n}) (مثل حقن السكربتات أو "
                             "الصلاحيات الواسعة أو الإجراءات غير المثبتة).",
    "Record a decision for the {n} open threat(s) in {f}: implement the mitigation, or add it to {m} with an owner and "
    "reason.": "وثّق قراراً بشأن التهديدات المفتوحة ({n}) في {f}: نفّذ إجراء التخفيف، أو أضفها إلى {m} مع تحديد "
               "المسؤول والسبب.",
    "The WAF let an attack through or blocked legitimate traffic; review its rules.":
        "سمح جدار الحماية بمرور هجوم أو منع حركة مشروعة؛ راجع قواعده.",
    "{n} blocking finding(s) are past their fix deadline (SLA). Escalate them to their owners.":
        "تجاوزت {n} من النتائج المانعة موعد المعالجة المحدد (SLA). صعّدها إلى المسؤولين عنها.",
    "{n} scanner(s) failed to complete ({tools}). Their results are missing; fix and re-run before relying on this "
    "report.": "لم تكتمل {n} من أدوات الفحص ({tools}). نتائجها ناقصة؛ أصلحها وأعد التشغيل قبل الاعتماد على هذا التقرير.",

    # ---------------------------------------------------------------- scope
    "{k} ({v} files)": "{k} ({v} ملفات)", "none found": "لم يُعثر على شيء",
    "Languages": "اللغات", "Frameworks": "أطر العمل", "Dependency ecosystems": "منظومات المكتبات",
    "Dependency manifests": "ملفات تعريف المكتبات", "Dockerfiles": "ملفات Dockerfile", "Terraform": "Terraform",
    "Kubernetes manifests": "ملفات Kubernetes", "Helm charts": "مخططات Helm",
    "CloudFormation / Bicep / ARM": "CloudFormation / Bicep / ARM", "CI systems": "أنظمة CI",
    "OpenAPI specification": "مواصفات OpenAPI",
    "Blocking threshold": "حد المنع", "Known exploited": "المستغلة فعلياً", "Accepted risks": "المخاطر المقبولة",
    "Report-only tools": "أدوات التقرير فقط", "Noise profile": "ملف الضوضاء", "Duplicates": "التكرارات",
    "Fix deadlines (SLA)": "مواعيد المعالجة (SLA)",
    "Enforce: a failed gate fails the pipeline": "إلزامي: البوابة الفاشلة توقف خط النشر",
    "Report only: gates are evaluated and reported, the pipeline is not blocked":
        "تقرير فقط: تُقيَّم البوابات ويُبلَّغ عنها دون إيقاف خط النشر",
    "Fixable findings rated {t}": "النتائج القابلة للإصلاح بخطورة {t}",
    "CVEs in the CISA KEV catalogue block at any severity": "ثغرات فهرس CISA KEV تمنع بأي درجة خطورة",
    "Exceptions in .sawone-baseline.yml, each with an owner, a reason and an expiry date; an expired exception stops "
    "suppressing. False positives are recorded the same way, with type: false-positive":
        "استثناءات في ‎.sawone-baseline.yml، لكل منها مسؤول وسبب وتاريخ انتهاء؛ ويتوقف الاستثناء المنتهي عن الإخفاء. "
        "تُسجَّل النتائج الإيجابية الكاذبة بالطريقة نفسها مع type: false-positive",
    "Second-opinion tools (Checkov, OSV-Scanner, kube-linter, Nuclei, Dockle) are shown but never block":
        "أدوات الرأي الثاني (Checkov وOSV-Scanner وkube-linter وNuclei وDockle) تُعرض ولا تمنع أبداً",
    "Balanced: low-severity findings from second-opinion tools are counted but not listed":
        "متوازن: تُحصى النتائج منخفضة الخطورة من أدوات الرأي الثاني دون إدراجها",
    "Full: every finding is listed": "كامل: تُدرج كل النتائج",
    "The same flaw reported by several tools, or by several rules of one tool, is merged into one finding in chapters "
    "1 and 4; each tool's own list in chapter 5 is complete":
        "يُدمج الخلل نفسه الذي أبلغت عنه عدة أدوات أو عدة قواعد لأداة واحدة في نتيجة واحدة في الفصلين 1 و4؛ وقائمة كل "
        "أداة في الفصل 5 كاملة",
    "Days to fix from first seen: {s}": "أيام المعالجة من أول ظهور: {s}",
    "Version policy “{p}”: every tool resolved once and pinned by digest for the whole run (see Appendix A)":
        "سياسة الإصدارات «{p}»: حُددت كل أداة مرة واحدة وثُبتت ببصمتها طوال التشغيل (انظر الملحق A)",
    "See Appendix A": "انظر الملحق A",

    # ---------------------------------------------------------------- gates
    "Every check the pipeline ran, in pipeline order. A failed gate found blocking issues; a scanner error means the "
    "tool did not finish, so its results are missing (never treat it as clean); report-only tools are tracked but "
    "never block.": "كل فحص نفذه خط النشر بالترتيب. البوابة الفاشلة وجدت مشكلات مانعة؛ وخطأ أداة الفحص يعني أن الأداة "
                    "لم تكتمل ونتائجها ناقصة (لا تعتبره نظيفاً أبداً)؛ وأدوات التقرير فقط تُتابَع ولا تمنع.",
    "pre-existing on base branch": "موجودة مسبقاً في الفرع الأساسي",
    "Pass/fail check — no individual findings": "فحص نجاح/فشل — لا نتائج تفصيلية", "No findings": "لا توجد نتائج",
    "Counts are every finding a tool reported. Only findings that break the gate policy block (see 2.3); the rest are "
    "tracked. Pass/fail tools report a result, not individual findings.":
        "الأعداد هي كل ما أبلغت عنه الأداة. تمنع فقط النتائج المخالفة لسياسة البوابة (انظر 2.3)؛ ويُتابَع الباقي. أدوات "
        "النجاح/الفشل تُبلغ عن نتيجة لا عن نتائج تفصيلية.",
    "Jobs pass in report-only mode even when their gates fail; the gate results above are what would block in enforce "
    "mode.": "تنجح المهام في وضع التقرير فقط حتى عند فشل بواباتها؛ ونتائج البوابات أعلاه هي ما سيمنع في الوضع الإلزامي.",

    # ---------------------------------------------------------------- risk-ranked, trend
    "Unique findings across every tool, duplicates merged, ordered by: blocking, known exploited, severity, then "
    "exploit probability (EPSS). At most 8 findings per tool are shown here so one noisy scanner cannot hide the "
    "others; every finding appears in its tool's section in chapter 5.":
        "النتائج الفريدة من كل الأدوات بعد دمج المكرر، مرتبة حسب: المنع، ثم الاستغلال الفعلي، ثم الخطورة، ثم احتمال "
        "الاستغلال (EPSS). يُعرض هنا 8 نتائج كحد أقصى لكل أداة حتى لا تحجب أداة كثيرة النتائج غيرها؛ وتظهر كل نتيجة "
        "في قسم أداتها في الفصل 5.",
    "No blocking or known-exploited findings.": "لا توجد نتائج مانعة أو مستغلة فعلياً.",
    "{n} further blocking findings are listed in their tool sections.": "{n} نتيجة مانعة أخرى مدرجة في أقسام أدواتها.",
    "Each finding keeps the date it was first seen, carried over from the previous report of this branch. Its fix "
    "deadline is that date plus the SLA for its severity.":
        "تحتفظ كل نتيجة بتاريخ أول ظهور لها، منقولاً من التقرير السابق لهذا الفرع. وموعد معالجتها هو ذلك التاريخ مضافاً "
        "إليه مدة SLA لدرجة خطورتها.",
    "No previous report of this branch was found, so every finding is first seen today. Trends appear from the next "
    "scan.": "لم يُعثر على تقرير سابق لهذا الفرع، لذا يُعد اليوم أول ظهور لكل نتيجة. تظهر الاتجاهات من الفحص القادم.",
    "New since last scan": "جديدة منذ آخر فحص", "Fixed since last scan": "عولجت منذ آخر فحص",
    "Blocking open": "مانعة مفتوحة", "Past deadline": "تجاوزت الموعد",
    "0–7 days": "0–7 أيام", "8–30 days": "8–30 يوماً", "31–90 days": "31–90 يوماً", "Over 90 days": "أكثر من 90 يوماً",
    "First seen": "أول ظهور", "Due": "الموعد",

    # ---------------------------------------------------------------- details
    "One section per pipeline stage and one panel per tool: what the tool checked, its result, and its findings "
    "ordered by priority.": "قسم لكل مرحلة ولوحة لكل أداة: ما فحصته الأداة، ونتيجتها، ونتائجها مرتبة حسب الأولوية.",
    "Not run: {why}": "لم يُنفذ: {why}", "Source SBOM": "قائمة مكونات المصدر (SBOM)",
    "{n} packages (CycloneDX, {f})": "{n} حزمة (CycloneDX، {f})", "{n} packages (CycloneDX)": "{n} حزمة (CycloneDX)",
    "{n} catalogued files not counted": "{n} ملف مفهرس غير محسوب",
    "The tool did not complete, so its results are missing.": "لم تكتمل الأداة، لذا نتائجها ناقصة.",
    "Remediation plan — {n} package(s) to upgrade": "خطة المعالجة — {n} حزمة للتحديث",
    "Advisories ({n})": "الإشعارات الأمنية ({n})",
    "Checkov does not rate severity without its commercial platform key, so these findings are shown as Unrated; "
    "Trivy config is the rated, blocking IaC gate.":
        "لا يصنّف Checkov الخطورة دون مفتاح منصته التجارية، لذا تظهر هذه النتائج غير مصنفة؛ وبوابة IaC المصنفة والمانعة "
        "هي Trivy config.",
    "{n} low-severity finding(s) from this second-opinion tool are counted above but not listed (noise profile: "
    "balanced).": "{n} نتيجة منخفضة الخطورة من أداة الرأي الثاني هذه محسوبة أعلاه وغير مدرجة (ملف الضوضاء: متوازن).",
    "{n} finding(s) of muted rules are hidden (noise.mute_rules).": "أُخفيت {n} نتيجة لقواعد مكتومة (noise.mute_rules).",
    "No findings.": "لا توجد نتائج.",
    "This tool reports pass or fail, not individual findings. Last lines of its output:":
        "تُبلغ هذه الأداة عن نجاح أو فشل لا عن نتائج تفصيلية. آخر أسطر مخرجاتها:",
    "Passed. This tool reports pass or fail rather than individual findings.":
        "اجتاز. تُبلغ هذه الأداة عن نجاح أو فشل بدلاً من نتائج تفصيلية.",
    "{n} threats identified:": "تم تحديد {n} تهديداً:",
    "Open threats requiring a decision ({n})": "تهديدات مفتوحة تتطلب قراراً ({n})",
    "Showing {limit} of {total}.": "عرض {limit} من {total}.",
    "{n} further threat(s) below the gate threshold or already decided are listed in findings.json.":
        "{n} تهديد آخر دون حد البوابة أو تم البت فيه مدرج في findings.json.",
    "Every threat at or above the threshold has a recorded decision.": "لكل تهديد عند الحد أو أعلى قرار موثق.",
    "Image": "الصورة", "Image ID": "معرّف الصورة",
    "{n} secret(s) found inside the image layers.": "عُثر على {n} سر داخل طبقات الصورة.",
    "Anyone who can pull the image can read them: rotate them and remove them from the build.":
        "يستطيع كل من يسحب الصورة قراءتها: استبدلها وأزلها من عملية البناء.",
    "{n} in {k}": "{n} في {k}", "OS packages": "حزم نظام التشغيل", "language runtime": "بيئة تشغيل اللغة",
    "application packages": "حزم التطبيق", "other": "أخرى",
    "Grype scanned the SBOM independently. It agrees with Trivy on {a} blocking advisories, and reports {b} that Trivy "
    "did not": "فحص Grype قائمة المكونات بشكل مستقل. يتفق مع Trivy في {a} إشعاراً مانعاً، ويُبلغ عن {b} لم يُبلغ عنها Trivy",
    "The usual causes are a different vulnerability database (Grype also matches upstream advisories for Debian "
    "packages that Debian has not yet triaged) and Grype seeing the language runtime itself as a package. Duplicates "
    "are merged in chapter 4.": "الأسباب المعتادة هي اختلاف قاعدة بيانات الثغرات (يطابق Grype أيضاً إشعارات المصدر "
                                "لحزم Debian التي لم تفرزها Debian بعد)، واعتبار Grype بيئة تشغيل اللغة نفسها حزمة. "
                                "تُدمج التكرارات في الفصل 4.",
    "Blocking advisories found only by Grype": "إشعارات مانعة وجدها Grype وحده",
    "Grype found nothing that Trivy missed.": "لم يجد Grype شيئاً فات Trivy.",
    "Operating-system packages": "حزم نظام التشغيل", "Application packages": "حزم التطبيق",
    "{n} package(s) to upgrade — usually cleared by rebuilding on a current base image.":
        "{n} حزمة للتحديث — تُعالج عادة بإعادة البناء على صورة أساس حديثة.",
    "{n} package(s) to upgrade.": "{n} حزمة للتحديث.",
    "Evidence and remediation": "الأدلة والمعالجة", "{n} more instances in {f}.": "{n} حالة أخرى في {f}.",
    "Remediation:": "المعالجة:", "No alerts.": "لا توجد تنبيهات.",
    "allowed": "مسموح", "informational": "معلوماتي", "blocked (HTTP 403)": "ممنوع (HTTP 403)",
    "As expected": "كما هو متوقع", "Not blocked (info)": "لم يُمنع (معلومة)", "Not as expected": "خلاف المتوقع",
    "legitimate request": "طلب مشروع", "SQL injection": "حقن SQL", "command injection": "حقن الأوامر",
    "cross-site scripting": "البرمجة عبر المواقع (XSS)", "path traversal": "اجتياز المسارات",
    "template injection": "حقن القوالب",
    "Generic attacks first, then the same attacks against each real endpoint and parameter from the OpenAPI "
    "specification. Template injection is informational: the OWASP Core Rule Set at paranoia level 1 does not claim "
    "to block it. A passing WAF is a compensating control, not a fix: the application flaws in the DAST section "
    "remain exploitable wherever the WAF is absent or bypassed.":
        "هجمات عامة أولاً، ثم الهجمات نفسها على كل نقطة نهاية ومعامل حقيقي من مواصفات OpenAPI. حقن القوالب معلوماتي: "
        "لا تدّعي مجموعة قواعد OWASP CRS عند مستوى الحساسية 1 منعه. اجتياز جدار الحماية ضابط تعويضي لا معالجة: تبقى "
        "عيوب التطبيق في قسم DAST قابلة للاستغلال حيثما غاب جدار الحماية أو تم تجاوزه.",

    # ---------------------------------------------------------------- compliance, baseline, supply chain
    "Which controls this run produced technical evidence for. This is an evidence map, not a compliance attestation: "
    "each control also needs process and governance evidence that a pipeline cannot produce. Appendix D lists the exact "
    "artefacts, with their SHA-256 hashes, behind each control.":
        "الضوابط التي أنتج هذا التشغيل أدلة تقنية لها. هذه خريطة أدلة وليست شهادة امتثال: يحتاج كل ضابط أيضاً إلى أدلة "
        "إجرائية وحوكمية لا يستطيع خط النشر إنتاجها. يسرد الملحق D الملفات الدقيقة، مع بصمات SHA-256، خلف كل ضابط.",
    "Evidenced: every stage mapped to the control ran and passed. Gap: a mapped stage failed. Unverified: a mapped "
    "scanner errored. Not assessed: no mapped stage ran.":
        "مُثبت بالأدلة: نُفذت كل المراحل المرتبطة بالضابط واجتازت. فجوة: فشلت مرحلة مرتبطة. غير مُتحقق منه: حدث خطأ في "
        "أداة مرتبطة. لم يُقيَّم: لم تُنفذ أي مرحلة مرتبطة.",
    "OWASP ASVS 4.0.3": "OWASP ASVS 4.0.3", "NIST SSDF (SP 800-218)": "NIST SSDF (SP 800-218)",
    "NCA ECC-2:2024": "الضوابط الأساسية للأمن السيبراني (NCA ECC-2:2024)",
    "NCA CSCC-1:2019": "ضوابط الأمن السيبراني للأنظمة الحساسة (NCA CSCC-1:2019)",
    "NCA CCC-2:2024": "ضوابط الأمن السيبراني للحوسبة السحابية (NCA CCC-2:2024)",
    "SAMA CSF": "إطار الأمن السيبراني للبنك المركزي السعودي (SAMA CSF)",
    "Saudi PDPL": "نظام حماية البيانات الشخصية (PDPL)",
    "Findings that would block but are covered by an active exception in .sawone-baseline.yml. Each exception has an "
    "owner and an expiry date; when it expires the finding blocks again.":
        "نتائج كانت ستمنع لكنها مشمولة باستثناء ساري في ‎.sawone-baseline.yml. لكل استثناء مسؤول وتاريخ انتهاء؛ وعند "
        "انتهائه تعود النتيجة مانعة.",
    "A high rate means that tool's rules need tuning (noise.mute_rules, or a rule-level exception) for this codebase.":
        "النسبة المرتفعة تعني أن قواعد تلك الأداة تحتاج إلى ضبط لهذه الشيفرة (noise.mute_rules أو استثناء على مستوى القاعدة).",
    "{n} exception(s) expired": "انتهى {n} استثناء", "and now block again:": "وعادت مانعة:",
    "How the scanned artefact was built and what happens to it next. Publishing, signing and SLSA provenance are done "
    "only by the release workflow, on trusted pushes. The release workflow also signs this report's evidence manifest.":
        "كيف بُني الملف المفحوص وما يحدث له بعد ذلك. النشر والتوقيع وإثبات المصدر SLSA تتم فقط عبر سير عمل الإصدار عند "
        "الدفع الموثوق. ويوقّع سير عمل الإصدار أيضاً بيان أدلة هذا التقرير.",
    "Image built": "الصورة المبنية", "SBOM": "قائمة المكونات (SBOM)",
    "Published / signed / provenance": "النشر / التوقيع / إثبات المصدر", "Trigger": "المُشغِّل",

    # ---------------------------------------------------------------- appendices
    "Each tool was resolved once at the start of the run and pinned by digest for every job, so this report states "
    "exactly what scanned the build.": "حُددت كل أداة مرة واحدة في بداية التشغيل وثُبتت ببصمتها لكل مهمة، لذا يذكر "
                                       "هذا التقرير بدقة ما فحص البناء.",
    "Version policy: {p}.": "سياسة الإصدارات: {p}.", "Tool manifest not available.": "بيان الأدوات غير متاح.",
    "Likely to be exploited with severe impact; fix immediately.": "مرجح الاستغلال بأثر بالغ؛ عالجها فوراً.",
    "Serious weakness; fix before release.": "ضعف جسيم؛ عالجه قبل الإصدار.",
    "Exploitable under some conditions; fix in the normal cycle.": "قابل للاستغلال في ظروف معينة؛ عالجه في الدورة المعتادة.",
    "Limited impact or hardening advice.": "أثر محدود أو توصية تحصين.",
    "The tool does not rate severity (for example Checkov without its platform key).":
        "لا تصنّف الأداة الخطورة (مثل Checkov دون مفتاح منصته).",
    "Breaks the gate policy: fixable at the threshold severity, known exploited, or a failed check.":
        "تخالف سياسة البوابة: قابلة للإصلاح بخطورة الحد، أو مستغلة فعلياً، أو فحص فاشل.",
    "Reported for awareness; does not block.": "يُبلّغ عنها للعلم؛ ولا تمنع.",
    "Would block, but covered by an active baseline exception.": "كانت ستمنع، لكنها مشمولة باستثناء ساري في خط الأساس.",
    "Recorded in the baseline as not a real issue; counted in the false-positive rate.":
        "مسجلة في خط الأساس على أنها ليست مشكلة حقيقية؛ وتُحسب في نسبة النتائج الإيجابية الكاذبة.",
    "A secret verified as working against its provider.": "سر تم التحقق من أنه يعمل لدى مزوده.",
    "Listed in CISA's Known Exploited Vulnerabilities catalogue.": "مدرجة في فهرس CISA للثغرات المستغلة فعلياً.",
    "FIRST Exploit Prediction Scoring System: probability of exploitation in the next 30 days.":
        "نظام FIRST للتنبؤ بالاستغلال: احتمال الاستغلال خلال الثلاثين يوماً القادمة.",
    "The tool did not finish; its results are missing, not clean.": "لم تكتمل الأداة؛ نتائجها ناقصة وليست نظيفة.",
    "Gate results, release facts and the findings summary": "نتائج البوابات وبيانات الإصدار وملخص النتائج",
    "Every normalised finding, per tool": "كل نتيجة موحّدة، لكل أداة",
    "Findings with cross-tool duplicates merged, first seen and fix deadline":
        "النتائج بعد دمج المكرر بين الأدوات، مع أول ظهور وموعد المعالجة",
    "Compliance controls and the artefacts that evidence each one": "ضوابط الامتثال والملفات التي تثبت كل ضابط",
    "SHA-256 of every file in this report set (sha256sum -c)": "بصمة SHA-256 لكل ملف في مجموعة التقرير (sha256sum -c)",
    "SARIF from every tool (also uploaded to code scanning when enabled)":
        "ملفات SARIF من كل أداة (وتُرفع إلى Code Scanning عند التفعيل)",
    "OWASP ZAP reports": "تقارير OWASP ZAP", "Raw tool output, SBOMs and the threat model": "مخرجات الأدوات الخام وقوائم المكونات ونموذج التهديدات",
    "Every tool's log": "سجل كل أداة", "Gate results for CI test views": "نتائج البوابات لعروض الاختبار في CI",
    "For each control: the artefacts in this report set that evidence it, with the first 16 characters of their "
    "SHA-256. evidence/manifest.sha256 covers every file; verify it with sha256sum -c and, on trusted pushes, the "
    "signature made by the release workflow.":
        "لكل ضابط: الملفات في مجموعة التقرير التي تثبته، مع أول 16 حرفاً من بصمة SHA-256. يغطي الملف "
        "evidence/manifest.sha256 كل الملفات؛ تحقق منه عبر sha256sum -c، ومن التوقيع الذي ينشئه سير عمل الإصدار عند "
        "الدفع الموثوق.",
    "no artefact (stage not run)": "لا يوجد ملف (لم تُنفذ المرحلة)",

    # ---------------------------------------------------------------- small helpers
    "+{n} more": "+{n} أخرى", "no fix yet": "لا يوجد إصلاح بعد",
    "Showing the {limit} highest-priority of {total} findings. Full list: {src} in the report artefact.":
        "عرض أعلى {limit} نتيجة أولوية من أصل {total}. القائمة الكاملة: {src} في ملفات التقرير.",
    "Showing the {limit} highest-priority of {total} rules. Full list: {src} in the report artefact.":
        "عرض أعلى {limit} قاعدة أولوية من أصل {total}. القائمة الكاملة: {src} في ملفات التقرير.",
    "Showing {limit} of {total} advisories. Full list: {src}.": "عرض {limit} من {total} إشعاراً. القائمة الكاملة: {src}.",
    "{n} more packages need upgrading.": "{n} حزمة أخرى تحتاج إلى تحديث.",

    # ---------------------------------------------------------------- table headers
    "Advisories": "الإشعارات", "Advisory": "الإشعار", "Affected packages": "الحزم المتأثرة", "Alert": "التنبيه",
    "All findings": "كل النتائج", "Area": "المجال", "Attack / evidence": "الهجوم / الدليل", "CWE": "CWE",
    "Control": "الضابط", "Element": "العنصر", "Evidence artefacts": "ملفات الأدلة", "Evidence from": "مصدر الأدلة",
    "Expected": "المتوقع", "Expires": "ينتهي", "False positives": "الإيجابية الكاذبة", "File": "الملف",
    "Finding": "النتيجة", "Fixed in": "أُصلح في", "Installed": "المثبت", "Instances": "الحالات", "Job": "المهمة",
    "Location": "الموقع", "Meaning": "المعنى", "Method": "الطريقة", "Owner": "المسؤول", "Package": "الحزمة",
    "Parameter": "المعامل", "Rate": "النسبة", "Reason": "السبب", "Request": "الطلب", "Requirement": "المتطلب",
    "Response": "الاستجابة", "Result": "النتيجة", "Risk": "الخطر", "Severity": "الخطورة",
    "Severity of blocking findings": "خطورة النتائج المانعة", "Stage": "المرحلة", "Status": "الحالة",
    "Suggested mitigation": "التخفيف المقترح", "Threat": "التهديد", "Tool": "الأداة", "Type": "النوع", "URL": "الرابط",
    "Upgrade to": "التحديث إلى", "Version / image digest": "الإصدار / بصمة الصورة", "Where": "المكان",
    "Worst": "الأشد", "Details": "التفاصيل", "Found by": "اكتشفتها",
}
