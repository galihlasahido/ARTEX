package server

import (
	"errors"
	"log"

	"github.com/Autumn-27/artex/db"
)

// builtinTaskTemplate is one entry of the seeded, reusable task-template catalog
// shipped with ARTEX (recon/CVE sweep, red-team subdomain+network pivot, stack-aware
// exploitation, WAF/CDN control validation, full-chain shell/DB proof-of-impact).
type builtinTaskTemplate struct {
	Name        string
	Description string
	Goal        string
}

// builtinTaskTemplates holds the seed content. CreateTaskTemplate derives each
// template's nkey from Name (case-insensitive) and inserts ON CONFLICT (nkey) DO
// NOTHING, so editing this slice in a later release only adds templates whose name
// was never seeded before; it never overwrites an operator's edited copy of an
// already-seeded template. Renaming a seeded template in the UI does not delete the
// old row — the next startup reseeds the original under its original name alongside
// the rename, the same first-insert-only rule every other seed in this package
// follows (seedPrompts, seedOrchestrationTools).
var builtinTaskTemplates = []builtinTaskTemplate{
	{
		Name:        "Full-Scope CVE-Aware Autonomous Pentest",
		Description: "Pentest otomatis end-to-end untuk seluruh aset dalam scope: recon, fingerprint, pemindaian CVE (nuclei+patch-diff), pengujian berbasis temuan (api-security/ffuf/dalfox/sqlmap/php2shell sesuai kondisi), verifikasi bukti traffic, dan laporan dengan nomor CVE serta rekomendasi remediasi.",
		Goal: `Lakukan pentest menyeluruh dan otomatis terhadap seluruh aset yang ada di scope task ini, dari recon sampai pelaporan terverifikasi. Hanya uji aset yang sudah terdaftar di scope; jangan menyentuh apa pun di luar itu.

Fase 1 — Recon & asset discovery
- Enumerasi subdomain dan aset (subfinder, bbot — gunakan skill bbot-recon untuk breadth-first recon: subdomain, cek subdomain-takeover, archived URL, parameter mining, enrichment IP/ASN).
- Resolusi DNS/IP, port & service scan (nmap, httpx) untuk tiap host hidup.
- Fingerprint teknologi per endpoint (httpx -tech-detect: web server, framework, CMS, library, versi bila terlihat di header/banner/response).
- Crawl aplikasi (katana) untuk memetakan endpoint, parameter, form, dan file JS; untuk permukaan API gunakan skill api-recon untuk mengumpulkan endpoint REST/GraphQL/WebSocket/SOAP.
- Tulis setiap aset dan fakta yang ditemukan ke asset graph dengan anchor yang benar, agar coverage ledger akurat.

Fase 2 — Pemindaian kerentanan berbasis CVE (wajib)
- Jalankan nuclei dengan template set yang terpasang (NUCLEI_TEMPLATES_DIR), fokus pada tag cves, vulnerabilities, exposures, misconfiguration, default-logins, dan technologies yang relevan dengan hasil fingerprint fase 1.
- Untuk setiap teknologi/versi yang teridentifikasi, cocokkan secara eksplisit ke CVE yang diketahui menimpa versi tersebut; catat nomor CVE pada fact/finding, bukan hanya nama template nuclei.
- Sadari bahwa template set nuclei di-bake pada saat build image dan bisa tertinggal dari CVE terbaru — jika target memakai software/versi yang tidak tercakup template yang ada, catat sebagai gap (hint/catatan), jangan diklaim "tidak vulnerable".
- Untuk CVE yang punya exploit publik tapi tidak ada PoC siap pakai, atau butuh rekonstruksi dari vendor patch, gunakan skill patch-diff.
- Sebelum menjalankan kode/PoC pihak ketiga apa pun (exploit publik, script dari GitHub/gist, paket pip/npm/go, atau apa pun yang di-pipe ke shell), wajib ikuti skill third-party-code-review lebih dulu.

Fase 3 — Pengujian berbasis temuan
- Untuk permukaan API, gunakan skill api-security: cek BOLA/IDOR/BFLA, kesalahan auth/authorization, masalah JWT, dan isu spesifik REST/GraphQL/WebSocket/SOAP lainnya.
- Fuzzing path & parameter tersembunyi dengan ffuf pada endpoint yang dicrawl di fase 1.
- Uji reflected/stored XSS dengan dalfox hanya pada parameter yang terbukti merefleksikan input.
- Uji injeksi SQL dengan sqlmap hanya pada parameter dengan indikasi kuat (error DB, perubahan response time/konten) — jangan jalankan brute-force sqlmap ke semua parameter tanpa indikasi.
- Jika target menjalankan PHP dan ada temuan LFI/file-inclusion, gunakan skill php2shell untuk menilai eksploitasi lebih lanjut.
- Credential testing (hydra/ncrack) dan apa pun yang berisiko mengganggu ketersediaan layanan hanya dijalankan sesuai noise profile yang aktif dan intercept/approval gate; jangan lakukan serangan yang bisa menyebabkan denial of service.
- Ikuti noise governor yang aktif (ARTEX_NOISE_PROFILE) dan budget token/turn yang berlaku; jangan membanjiri target di luar profil yang disetel.

Fase 4 — Bukti & verifikasi
- Setiap finding harus terikat ke traffic request/response yang terekam oleh proxy, dengan evidence quote verbatim dan POE level yang sesuai — jangan tandai finding sebagai verified tanpa bukti yang mengikatnya.
- Beri severity, class, dan confidence yang wajar; sertakan nomor CVE pada finding bila relevan.
- Jalankan retest pada finding yang meragukan sebelum dilaporkan sebagai final.
- Jika ragu atau butuh keputusan operator (misalnya aksi berisiko tinggi atau butuh kredensial), gunakan mekanisme tanya-operator (sidequestion) daripada menebak atau melanjutkan tanpa izin.

Fase 5 — Pelaporan
- Tutup goal dengan prove_goal hanya setelah bukti memadai terkumpul.
- Sertakan ringkasan coverage (aset yang sudah diuji vs belum), daftar finding dengan severity dan CVE terkait, dan rekomendasi remediasi singkat per finding.`,
	},
	{
		Name:        "Red Team: Domain-Wide Subdomain Sweep & Scoped Network Pivot",
		Description: "Red team dari satu domain root: enumerasi seluruh subdomain (bbot+subfinder), fingerprint & CVE scan per subdomain (nuclei+patch-diff), lalu pivot jaringan HANYA pada CIDR/IP yang eksplisit di scope (nmap/arp-scan/impacket/hydra), dengan ekspansi scope otomatis diblok dan diajukan ke operator via sidequestion.",
		Goal: `Lakukan red team sweep dari satu domain root: temukan seluruh subdomain, nilai mana yang vulnerable, lalu — hanya bila diizinkan lewat scope — telusuri jaringan tempat sistem itu terhubung. Hanya uji aset dan rentang IP yang sudah terdaftar di scope task ini; jangan menyerang apa pun di luar itu.

Fase 1 — Footprint domain & subdomain
- Enumerasi subdomain seluas mungkin: bbot (gunakan skill bbot-recon — breadth-first: brute force DNS, sumber pasif, archived URL/Wayback, parameter mining, enrichment IP/ASN) dan subfinder sebagai pelengkap.
- Cek subdomain-takeover pada setiap subdomain yang resolve ke CNAME layanan pihak ketiga.
- Resolusi DNS/IP tiap subdomain, lalu probe hidup (httpx) dan fingerprint teknologi (web server, framework, CMS, versi bila terlihat).
- Catat setiap subdomain sebagai aset di asset graph dengan anchor yang benar, termasuk subdomain yang mati/tidak merespons (agar coverage ledger lengkap).

Fase 2 — Triage & port/service scan
- Port & service scan (nmap) pada tiap IP unik di balik subdomain yang hidup, untuk melihat layanan selain HTTP (SSH, RDP, SMB, WinRM, database, dll).
- Crawl tiap aplikasi web (katana) untuk endpoint, parameter, file JS, dan kemungkinan kredensial/token yang bocor di client-side.
- Untuk permukaan API, gunakan skill api-recon.

Fase 3 — Pemindaian kerentanan per subdomain (wajib cek CVE)
- Jalankan nuclei dengan tag cves, vulnerabilities, exposures, misconfiguration, default-logins, dan takeovers pada setiap subdomain hidup; cocokkan versi teknologi yang terfingerprint ke CVE spesifik, catat nomor CVE di finding/fact — bukan hanya nama template nuclei.
- Template nuclei di-bake saat build image dan bisa tertinggal CVE terbaru; bila software/versi target tidak tercakup template yang ada, catat sebagai gap, jangan diklaim aman.
- Untuk CVE yang hanya punya patch vendor tanpa PoC publik, gunakan skill patch-diff.
- Sebelum menjalankan kode/PoC pihak ketiga apa pun, wajib ikuti skill third-party-code-review lebih dulu.
- Untuk permukaan API, tambahkan pengujian skill api-security (BOLA/IDOR/BFLA, auth/JWT).
- Ranking: tandai subdomain dengan risiko tertinggi — software usang bervulnerable publik, panel admin terbuka, API tanpa auth, kredensial/token bocor di JS, port manajemen (RDP/WinRM/SMB/VNC/SSH) terbuka ke internet — sebagai titik masuk paling layak untuk fase lanjutan.

Fase 4 — Jaringan tempat sistem terhubung (hanya dalam scope yang didaftarkan)
- Fase ini HANYA berjalan pada CIDR/IP yang sudah eksplisit terdaftar di company scope task ini sebagai bagian dari rules of engagement. Jangan menganggap "terhubung secara jaringan" sebagai izin otomatis untuk menyerang.
- Bila selama fase 1-3 ditemukan indikasi sistem terhubung ke segmen/host yang BELUM ada di scope (misal IP internal, VPN gateway, jaringan lain yang terjangkau), JANGAN diserang. Catat sebagai fact/hint "potensi ekspansi scope: <alasan>" dan ajukan pertanyaan ke operator lewat mekanisme tanya-operator (sidequestion) untuk meminta scope ditambah secara eksplisit sebelum disentuh.
- Discovery segmen lokal yang sudah dalam scope: nmap (host/service discovery), arp-scan, arping, fping, netdiscover.
- Enumerasi SMB/AD read-only lebih dulu: impacket-netview, impacket-rpcdump, impacket-samrdump (null session/guest atau kredensial yang memang disediakan operator pada task ini) sebelum mencoba apa pun yang invasif.
- Dump kredensial (impacket-secretsdump) dan eksekusi jarak jauh (impacket-wmiexec) adalah aksi berisiko tinggi: jalankan hanya setelah persetujuan eksplisit lewat intercept gate, hanya pada host yang ada di scope, tanpa membuat persistence atau mengubah konfigurasi target.
- Credential testing (hydra, ncrack, sshpass) dan audit konfigurasi SSH (ssh-audit) hanya pada host dalam scope dan sesuai noise profile yang aktif; jangan sampai menyebabkan account lockout atau denial of service.
- Hash cracking (hashcat, john) hanya untuk hash yang didapat sah dari dalam scope engagement ini.

Fase 5 — Bukti, verifikasi, dan batas
- Setiap finding — di level domain maupun jaringan — harus terikat ke traffic/bukti nyata (request/response via proxy, atau output tool yang terekam) dengan evidence quote verbatim dan POE level yang sesuai.
- Beri severity, class, confidence, dan nomor CVE bila relevan; jalankan retest pada finding yang meragukan sebelum final.
- Patuhi noise governor dan budget token/turn yang berlaku; hentikan atau tanya operator (sidequestion) sebelum aksi yang bisa mengganggu ketersediaan layanan atau melebihi scope yang disetujui.

Fase 6 — Pelaporan
- Tutup goal dengan prove_goal hanya setelah bukti memadai terkumpul.
- Laporkan: daftar seluruh subdomain yang ditemukan (vulnerable vs tidak, dengan CVE terkait), peta jaringan yang terjangkau (in-scope vs ditandai untuk ekspansi scope beserta status permintaan operator), dan rekomendasi remediasi singkat per finding.`,
	},
	{
		Name:        "Deep Stack-Specific Web Exploitation (PHP/Java/.NET/Node)",
		Description: "Fingerprint stack tiap host dulu, lalu cabang ke kelas kerentanan spesifik PHP (php2shell/deserialization), Java (actuator/Fastjson/Struts2/Spring4Shell/JNDI/XXE), .NET (ViewState deserialization/elmah/IIS), atau Node (prototype pollution/SSTI/node-serialize/npm CVE). Eksploitasi RCE/deserialization wajib approval operator sebelum dijalankan.",
		Goal: `Lakukan pengujian web mendalam yang disesuaikan dengan stack teknologi target. Jangan memakai satu daftar teknik generik untuk semua host — identifikasi dulu stack tiap host, baru pilih kelas kerentanan yang relevan. Hanya uji aset yang ada di scope task ini.

Fase 1 — Identifikasi stack (wajib sebelum fase 2)
- Fingerprint tiap host (httpx -tech-detect): header Server/X-Powered-By, ekstensi file (.php/.jsp/.aspx/.ashx), nama cookie sesi (PHPSESSID = PHP, JSESSIONID = Java, ASP.NET_SessionId/.AspNetCore.* = .NET, connect.sid = Node/Express), halaman error default, path khas framework.
- Kalau satu domain punya banyak subdomain dengan stack berbeda-beda, ulangi identifikasi per host dan jalankan fase 2 secara terpisah untuk masing-masing — jangan asumsikan satu stack berlaku untuk semua subdomain.
- Catat stack yang terdeteksi sebagai fact pada aset tersebut sebelum melanjutkan.

Fase 2 — Cabang sesuai stack yang terdeteksi

PHP:
- Gunakan skill php2shell untuk temuan LFI/file-inclusion.
- Cek insecure deserialization (unserialize() pada parameter yang terlihat base64/serialized), object injection, dan exposure debug (phpinfo(), error_reporting aktif di production).
- Cocokkan versi PHP/CMS/plugin yang terfingerprint ke CVE (nuclei tag cves + skill patch-diff untuk yang tanpa PoC publik).

Java:
- Cek endpoint actuator Spring Boot (/actuator/env, /actuator/heapdump, /actuator/health) yang bisa membocorkan secret/config.
- Cek indikasi deserialization gadget chain: Fastjson autoType, Struts2 OGNL injection (lewat Content-Type multipart yang dimanipulasi), Spring4Shell (class.module.classLoader), titik injeksi JNDI gaya Log4Shell pada header yang kemungkinan dilog (User-Agent, X-Api-Version, dll).
- Cek XXE pada endpoint yang menerima XML/SOAP.
- Tidak ada tool gadget-chain (seperti ysoserial) yang terpasang di image ini — kalau perlu membuat/mengambil payload gadget chain, itu kode pihak ketiga: wajib ikuti skill third-party-code-review dulu, dan jangan mengeksekusi apa pun yang berpotensi RCE tanpa persetujuan eksplisit operator (tanya lewat sidequestion sebelum mencoba eksploitasi, bukan hanya enumerasi).

.NET:
- Kalau ada parameter __VIEWSTATE, cek apakah MAC/enkripsi ViewState aktif; ViewState tanpa validasi MAC yang benar adalah indikasi deserialization RCE (butuh machineKey yang valid/bocor — ini juga RCE berisiko tinggi, enumerasi dulu, minta approval sebelum eksploitasi).
- Cek exposure /elmah.axd, /trace.axd, dan file konfigurasi yang salah expose (web.config, appsettings.json).
- Cek misconfig IIS lewat nuclei.

Node.js:
- Cek prototype pollution pada endpoint yang menerima JSON dan melakukan merge/assign object.
- Cek SSTI pada template engine (EJS/Pug/Handlebars) dengan payload non-destruktif untuk pembuktian minimal, bukan RCE penuh tanpa approval.
- Periksa bundle JS yang dicrawl (katana) untuk pola insecure deserialization (node-serialize) atau secret/API key yang ter-hardcode.
- Cocokkan dependency npm yang teridentifikasi ke CVE lewat skill patch-diff.
- Cek exposure .env/config.json yang tidak sengaja ter-serve sebagai static file.

Fase 3 — Disiplin eksploitasi
- Enumerasi dan pembuktian kerentanan boleh otomatis; eksploitasi yang berpotensi RCE, deserialization gadget chain, atau mengubah state target harus berhenti dan minta persetujuan operator (sidequestion) dulu sebelum dijalankan — jangan lanjut otomatis hanya karena indikasi awal positif.
- Sebelum menjalankan kode/PoC pihak ketiga apa pun, wajib ikuti skill third-party-code-review.

Fase 4 — Bukti & pelaporan
- Setiap finding terikat ke traffic/bukti nyata dengan evidence quote verbatim dan POE level yang sesuai; sertakan nomor CVE bila relevan.
- Jalankan retest pada finding yang meragukan sebelum final.
- Laporkan per host: stack yang terdeteksi, kelas kerentanan yang diuji, temuan dengan severity dan CVE, serta rekomendasi remediasi.`,
	},
	{
		Name:        "WAF/CDN Control Validation (Announced Bypass Testing)",
		Description: "Uji efektivitas WAF/CDN: baseline deteksi lewat canary payload, lalu sweep teknik evasion (sqlmap tamper, encoding, HPP, header tricks, smuggling-probe minimal) untuk melihat mana yang lolos ke origin. Severity dibedakan jujur antara \"WAF bisa dilewati\" vs \"origin juga rentan\". Default memakai User-Agent assessment terdeklarasi sesuai docs/scanner-user-agent.md.",
		Goal: `Validasi efektivitas WAF/CDN di depan target: apakah kontrol itu benar-benar menahan payload berbahaya sebelum mencapai origin, dan teknik evasion apa yang berhasil menembusnya. Ini bukan tujuan menyembunyikan assessment dari SOC klien.

Prasyarat (dilakukan operator, bukan agent)
- Task ini diasumsikan memakai User-Agent assessment terdeklarasi (ARTEX-Assessment/1.0) sesuai docs/scanner-user-agent.md, dikonfigurasi lewat task_user_agents di config.json untuk origin target task ini, lalu ARTEX direstart. Operator harus memastikan ini sudah aktif sebelum task dijalankan, karena agent tidak bisa mengubah config.json sendiri. Kalau belum dikonfigurasi, catat sebagai catatan di awal laporan bahwa request tidak membawa label assessment.

Fase 1 — Baseline & identifikasi kontrol
- Konfirmasi UA assessment terkirim pada satu request awal (kalau sudah dikonfigurasi operator).
- Fingerprint WAF/CDN: nuclei (template deteksi WAF), header respons (Server, cf-ray, X-Sucuri-ID, X-Akamai-*, dll), halaman block khas vendor.
- Coba identifikasi IP origin asli di balik CDN (riwayat DNS, sertifikat transparency log, subdomain yang mungkin tidak di-proxy) — hanya pada aset yang sudah ada di scope, jangan menyerang IP origin itu dulu sebelum dikonfirmasi ada di scope.

Fase 2 — Baseline deteksi
- Kirim beberapa payload canary yang jelas berbahaya (pola SQLi, XSS, path traversal klasik) lewat WAF dan catat mana yang diblokir (403/406/block page khas vendor). Ini jadi baseline tingkat deteksi kontrol.

Fase 3 — Sweep teknik bypass
- Untuk tiap canary yang diblokir, coba ulang dengan teknik evasion dan catat teknik mana yang berhasil meloloskan payload yang secara semantik sama ke origin tanpa terdeteksi:
  - sqlmap --tamper (space2comment, charencode, randomcase, equaltolike, apostrophemask, versionedkeywords, dll) untuk SQLi.
  - Encoding/case variation, double-encoding, unicode normalization, null-byte, HTTP parameter pollution, pemindahan payload antara query string/body/header, confusion Content-Type (ffuf -enc/-raw, header custom).
  - nuclei waf-fuzz dan template fuzzing lain yang terpasang.
  - Header-based tricks (X-Forwarded-For, X-Original-URL) hanya kalau origin langsung sudah dikonfirmasi ada di scope.
- HTTP request smuggling/desync: HANYA probe diferensial yang aman dan minimal (satu-dua request timing-based untuk deteksi, bukan eksploitasi desync berkelanjutan), karena smuggling bisa memengaruhi pengguna lain di belakang proxy yang sama. Hentikan segera dan tanya operator (sidequestion) kalau ada tanda respons bercampur dengan user lain.

Fase 4 — Bukti & klasifikasi dampak
- Untuk setiap bypass yang berhasil, simpan pasangan request/response: versi yang diblokir vs versi yang lolos ke origin dengan payload yang secara efektif sama, terikat ke traffic yang terekam proxy.
- Klasifikasi dampak dengan jujur: kalau origin TIDAK rentan terhadap payload yang lolos itu, bypass ini tetap dicatat sebagai finding (kelemahan kontrol WAF) tapi severity-nya informational/low — bukan exploitation nyata. Kalau origin JUGA rentan terhadap payload yang lolos, ini jadi finding penuh dengan severity sesuai dampak nyata di origin (defense-in-depth gagal total).
- Jangan melanjutkan ke eksploitasi/eksfiltrasi data lewat jalur bypass melebihi yang diperlukan untuk membuktikan payload mencapai origin.
- Aksi berisiko tinggi (sqlmap, hydra, dll) tetap tunduk pada intercept/approval gate yang sudah ada.

Fase 5 — Pelaporan
- Laporkan: produk WAF/CDN yang teridentifikasi (bila bisa), tingkat deteksi baseline, daftar teknik bypass yang berhasil dengan bukti, dan apakah payload yang lolos punya dampak nyata di origin atau tertahan oleh kontrol level aplikasi (defense-in-depth masih berfungsi).
- Ini memberi klien gambaran jujur: apakah WAF satu-satunya pertahanan mereka, atau origin juga punya validasi sendiri.`,
	},
	{
		Name:        "Full Chain Exploitation: Shell Access & Database Extraction (Proof of Impact)",
		Description: "Dari kerentanan awal sampai bukti eksekusi kode di server dan/atau akses database, dengan disiplin bukti-minimal: tidak dump penuh, tidak backdoor/persistence, tidak mengubah/menghapus data, data sensitif selalu dimasking. Setiap upaya eksekusi berhenti dulu untuk approval operator sebelum dijalankan.",
		Goal: `Buktikan dampak nyata sampai ke titik eksekusi kode di server dan/atau akses ke database — bukan hanya identifikasi kerentanan. Ini template dampak tertinggi: hanya jalankan pada aset yang scope-nya SUDAH mencakup izin eksplisit untuk eksploitasi sampai RCE/akses data, bukan sekadar izin scanning. Prinsip inti di seluruh fase: ambil bukti seminim mungkin untuk membuktikan akses — jangan dump penuh, jangan merusak, jangan tinggalkan backdoor.

Fase 1 — Dasar temuan
- Kalau task ini punya source task (hasil recon/CVE-scan sebelumnya), gunakan fact/finding dari sana sebagai titik awal; kalau tidak, lakukan recon dan pemindaian CVE singkat dulu (fingerprint, nuclei tag cves/vulnerabilities, crawl) untuk menemukan kandidat jalur eksploitasi.
- Prioritaskan kerentanan yang realistis mengarah ke RCE atau akses data langsung: LFI/RFI, insecure deserialization, command injection, unrestricted file upload, SQLi, exposed admin panel dengan kredensial lemah/default, exposed DB port tanpa auth.

Fase 2 — Mendapatkan foothold (eksekusi kode)
- Pilih jalur sesuai kerentanan yang ditemukan:
  - LFI/file-inclusion pada PHP: gunakan skill php2shell untuk mengubah LFI menjadi RCE.
  - SQLi dengan privilege DB tinggi: sqlmap --os-shell/--os-pwn (tool ini sudah wajib approval operator lewat intercept rule).
  - Command injection atau unrestricted file upload: verifikasi RCE dengan command non-destruktif (misalnya echo/id/whoami-equivalent), jangan langsung upload webshell persisten.
  - Insecure deserialization (Java/.NET/PHP/Node): jalankan hanya payload pembuktian minimal yang mengeksekusi command non-destruktif, bukan payload yang mengubah state server.
  - Kredensial default/lemah di panel admin/SSH yang sudah melalui rule approval hydra/ncrack: gunakan hanya untuk login verifikasi, bukan brute force masif.
- Sebelum menjalankan kode/PoC/exploit pihak ketiga apa pun (publik atau hasil rekonstruksi dari patch-diff), wajib ikuti skill third-party-code-review.
- Setiap upaya eksekusi kode adalah aksi berisiko tinggi: tidak ada satu nama tool tetap yang bisa dicegat otomatis untuk kasus ini (berbeda dari sqlmap/hydra yang sudah ada argv rule) — karena itu, SELALU berhenti dan tanya persetujuan operator lewat sidequestion sebelum benar-benar menjalankan command apa pun di luar enumerasi, meskipun model merasa yakin kerentanannya valid.

Fase 3 — Pembuktian minimal setelah mendapat akses
- Setelah shell/RCE terbukti: jalankan HANYA command pembuktian (whoami/id, hostname, pwd, daftar isi direktori kerja saat ini) untuk mendokumentasikan level akses.
- JANGAN: memasang persistence/backdoor, membuat user baru, mengubah permission, menghapus/mengubah/mengenkripsi file apa pun, atau pivot ke host lain tanpa persetujuan baru dari operator.
- Catat setiap command yang dijalankan di server target sebagai bagian evidence, termasuk command yang gagal.

Fase 4 — Akses database (bila relevan)
- Temukan kredensial DB lewat cara yang sah dalam konteks akses yang sudah didapat: baca file konfigurasi (.env, config.php, web.config, application.properties) yang terbaca dari foothold — jangan menebak kredensial.
- Kalau DB terbuka langsung tanpa auth atau lewat SQLi: enumerasi nama database dan tabel dulu. Untuk membuktikan akses, ambil HANYA count baris dan maksimal 2-3 baris sampel yang DIMASKING (misalnya nilai sensitif dipotong jadi beberapa karakter + "***") — jangan dump seluruh tabel atau seluruh database.
- Kalau menemukan password hash: cracking (hashcat/john) opsional dan hanya untuk membuktikan kredensial lemah pada SATU contoh, bukan mem-crack seluruh daftar hash.
- Data yang terbukti sensitif (PII, kredensial, data pembayaran) tidak boleh ditulis utuh ke mana pun (finding, report, log) — selalu masking.

Fase 5 — Bukti & batas
- Setiap langkah (dari vuln awal sampai shell/DB) harus terikat ke evidence nyata: traffic request/response, output command yang terekam, atau capture dari proxy — dengan evidence quote verbatim dan POE level yang sesuai.
- Jalankan retest sebelum finding ditandai final.
- Patuhi noise governor dan budget token/turn. Hentikan dan tanya operator sebelum aksi apa pun yang berisiko mengganggu ketersediaan layanan atau melebihi scope yang disetujui.

Fase 6 — Pelaporan
- Tutup goal dengan prove_goal hanya setelah bukti memadai terkumpul untuk klaim "akses server/database berhasil dibuktikan".
- Laporkan chain lengkap: kerentanan awal → cara mendapat foothold → level akses yang dibuktikan → akses database (bila ada) dengan data yang sudah di-masking → rekomendasi remediasi.
- Nyatakan secara eksplisit di laporan: tidak ada backdoor/persistence yang ditinggalkan, tidak ada data yang diubah/dihapus, dan tidak ada data sensitif yang diekstrak melebihi yang diperlukan untuk pembuktian.`,
	},
}

// seedTaskTemplates inserts each builtinTaskTemplates entry on first run only; see
// the comment on builtinTaskTemplates for the exact idempotency rule.
func seedTaskTemplates(pg *db.DB) {
	for _, t := range builtinTaskTemplates {
		_, err := pg.CreateTaskTemplate(db.TaskTemplateInput{
			Name:        t.Name,
			Description: t.Description,
			Goal:        t.Goal,
		})
		if err == nil || errors.Is(err, db.ErrTaskTemplateNameConflict) {
			continue
		}
		log.Printf("[task-templates] seed %q failed: %v", t.Name, err)
	}
}
