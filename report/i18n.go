package report

import "github.com/Autumn-27/artex/db"

// reportStrings holds every presentational label the DOCX deliverable prints,
// so the same structural report can be rendered in more than one language
// without duplicating the rendering logic. Only labels and boilerplate are
// localized — never the finding data itself (summaries, PoC, operator-written
// reports), which stays in whatever language the agent recorded it. Standard
// identifiers (OWASP category codes, CVSS, the severity key constants) are not
// translated either; only their human-facing display labels are.
//
// The English table (langEN) is the single source of truth for English, so the
// Markdown report's package-level verificationLabel/statusLabel delegate to it
// and can never drift from the DOCX.
type reportStrings struct {
	code string // "en" | "id"

	// cover
	coverTitle           string
	coverSubtitle        string
	coverConfidential    string
	coverObjective       string
	coverGeneratedPrefix string
	coverGeneratedBy     string

	// scopeFallback is the placeholder used in place of an empty task title in
	// the confidentiality and executive-summary sentences.
	scopeFallback string

	// confidentiality
	confHeading  string
	confPara1Fmt string // one %s: the assessed scope / task title
	confPara2    string
	confPara3    string

	// methodology
	methodHeading string
	methodIntro   string
	methodPhases  []phaseText

	// standards
	stdHeading      string
	stdIntro        string
	stdBullets      []string
	stdOwaspHeading string

	// executive summary
	execHeading           string
	execSummaryFmt        string // two args: scope (%s), count (%d)
	execSeverityBreakdown string
	execAssetsInScope     string
	execNoAssets          string
	execFindingsSummary   string
	execNoFindings        string

	// tables
	tblSeverity         string
	tblCount            string
	tblTotal            string
	tblInfoUnclassified string
	tblNum              string
	tblFinding          string
	tblVerification     string

	// detailed findings
	findingsHeading     string
	findingsNone        string
	lblFindingRecord    string
	lblPoE              string
	lblVerification     string
	lblProof            string
	lblVerificationNote string
	lblStatus           string
	lblOWASP            string
	lblPoC              string
	lblConfidence       string
	lblCounterevidence  string
	lblDetailedReport   string
	staleNotice         string
	proofNone           string
	proofBoundFmt       string // one %d: the bound-traffic count
	verifUnavailable    string
	verifMissing        string
	owaspUnmapped       string

	// coverage appendix
	coverageHeading  string
	lblCompleteness  string
	lblLedgerEntries string
	lblOpenGaps      string
	coverageMoreFmt  string // one %d: the remaining gap count

	// running header / footer / document metadata
	docTitlePrefix     string // prepended to the task title in the page header and doc metadata
	footerConfidential string
	footerPagePrefix   string // "Page " — precedes the page number in the footer
	footerPageOf       string // " of " — between the page number and total

	// severity display labels, keyed by the lowercase severity key
	severity map[string]string
	// verification-state display labels, keyed by the db.Verification* constant
	verification map[string]string
	// triage/remediation display labels, keyed by the db.Finding* status constant
	status map[string]string
}

type phaseText struct{ name, detail string }

// severityDisplay returns the localized severity label for a severity key,
// falling back to the uppercased key (or INFO for the empty/unknown key) so an
// unexpected value is still printed rather than dropped.
func (s reportStrings) severityDisplay(sev string) string {
	if label, ok := s.severity[normalizeSeverityKey(sev)]; ok {
		return label
	}
	return severityLabel(sev)
}

func (s reportStrings) verificationDisplay(state string) string {
	if label, ok := s.verification[state]; ok {
		return label
	}
	if state == "" {
		return s.verification[db.VerificationUnverified]
	}
	return state // unknown value passes through rather than vanishing
}

// statusDisplay returns the localized status label, or "" when the finding was
// never triaged (empty status) so the caller skips the bullet entirely.
func (s reportStrings) statusDisplay(state string) string {
	if state == "" {
		return ""
	}
	if label, ok := s.status[state]; ok {
		return label
	}
	return state
}

func normalizeSeverityKey(sev string) string {
	switch sev {
	case "critical", "high", "medium", "low", "":
		return sev
	}
	return sev
}

// stringsFor returns the localized string table for a language code. Anything
// other than a known code (including "") falls back to English, so an
// unrecognized ?lang= value produces a valid English report rather than an
// error.
func stringsFor(code string) reportStrings {
	switch code {
	case "id":
		return langID
	default:
		return langEN
	}
}

var langEN = reportStrings{
	code: "en",

	scopeFallback: "the assessed scope",

	coverTitle:           "PENETRATION TEST REPORT",
	coverSubtitle:        "Automated, evidence-bound security assessment",
	coverConfidential:    "CONFIDENTIAL — FOR AUTHORIZED RECIPIENTS ONLY",
	coverObjective:       "Objective",
	coverGeneratedPrefix: "Generated: ",
	coverGeneratedBy:     "Generated by: ARTEX Autonomous Penetration Testing Platform",

	confHeading: "Confidentiality",
	confPara1Fmt: "This document presents the results of a security assessment against %s. " +
		"It is intended for the operator who commissioned this task and the recipients they designate.",
	confPara2: "This report may contain information about exploitable weaknesses in the assessed systems. " +
		"Treat it as confidential: do not copy, forward or publish it, in whole or in part, without the " +
		"prior written consent of the party that commissioned this assessment.",
	confPara3: "A penetration test is a point-in-time assessment. It does not prove the absence of vulnerabilities, " +
		"only that the tested conditions, as covered by this task's scope, were examined at the time it ran. " +
		"Subsequent changes to the system or its environment can change its security posture.",

	methodHeading: "Methodology",
	methodIntro: "This assessment was performed by ARTEX, a self-hosted, LLM-driven autonomous penetration testing " +
		"platform. A planner decomposes the task's goal into intents; a worker executes each intent with real " +
		"tools under policy and approval gates, then writes observed assets, facts and findings back into the " +
		"task's exploration graph. The cycle repeats until the goal is proven or the task is stopped.",
	methodPhases: []phaseText{
		{"Reconnaissance", "Asset discovery, service/technology fingerprinting, and endpoint enumeration within the task's declared scope."},
		{"Testing", "Vulnerability identification and, where authorized, exploitation attempts — gated by the intercept/approval policy and the active noise profile."},
		{"Verification", "Findings are bound to recorded evidence (captured traffic or tool output) and, where configured, re-tested before being reported as confirmed."},
		{"Reporting", "Confirmed findings, their proof strength, and open coverage gaps are compiled into this report."},
	},

	stdHeading: "Standards & References",
	stdIntro:   "Testing follows common industry references, including:",
	stdBullets: []string{
		"OWASP — Open Web Application Security Project (Top 10, Testing Guide, API Security Top 10)",
		"NIST — National Institute of Standards and Technology Cybersecurity Framework",
		"CIS — Center for Internet Security Benchmarks",
		"CVSS — Common Vulnerability Scoring System (severity reference)",
	},
	stdOwaspHeading: "OWASP Top 10:2021",

	execHeading: "Executive Summary",
	execSummaryFmt: "This report presents the results of an automated, evidence-bound penetration test against %s. " +
		"%d finding(s) were confirmed during this assessment.",
	execSeverityBreakdown: "Severity breakdown",
	execAssetsInScope:     "Assets in scope",
	execNoAssets:          "No assets were recorded for this task.",
	execFindingsSummary:   "Findings summary",
	execNoFindings:        "No vulnerabilities were confirmed during this assessment.",

	tblSeverity:         "Severity",
	tblCount:            "Count",
	tblTotal:            "Total",
	tblInfoUnclassified: "INFO / UNCLASSIFIED",
	tblNum:              "#",
	tblFinding:          "Finding",
	tblVerification:     "Verification",

	findingsHeading:     "Detailed Findings",
	findingsNone:        "No vulnerabilities confirmed this time.",
	lblFindingRecord:    "Finding record",
	lblPoE:              "PoE level",
	lblVerification:     "Verification",
	lblProof:            "Proof",
	lblVerificationNote: "Verification note",
	lblStatus:           "Status",
	lblOWASP:            "OWASP Top 10:2021",
	lblPoC:              "PoC / Evidence:",
	lblConfidence:       "Confidence rationale:",
	lblCounterevidence:  "Counterevidence:",
	lblDetailedReport:   "Detailed report:",
	staleNotice:         "The evidence has changed; the detailed report needs updating.",
	proofNone:           "no bound traffic evidence",
	proofBoundFmt:       "%d bound traffic exchange(s)",
	verifUnavailable:    "unknown (quality lookup failed — proof strength unavailable)",
	verifMissing:        "not assessed (no finding record — quality fields unavailable)",
	owaspUnmapped:       "not mapped to a specific category",

	coverageHeading:  "Appendix A — Coverage",
	lblCompleteness:  "Completeness",
	lblLedgerEntries: "Ledger entries",
	lblOpenGaps:      "Open gaps",
	coverageMoreFmt:  "…and %d more (see the coverage API).",

	docTitlePrefix:     "Penetration Test Report — ",
	footerConfidential: "CONFIDENTIAL",
	footerPagePrefix:   "Page ",
	footerPageOf:       " of ",

	severity: map[string]string{
		"critical": "CRITICAL", "high": "HIGH", "medium": "MEDIUM", "low": "LOW", "": "INFO",
	},
	verification: map[string]string{
		db.VerificationUnverified:    "Unverified",
		db.VerificationVerified:      "Verified",
		db.VerificationBlocked:       "Blocked",
		db.VerificationNotAssessed:   "Not assessed",
		db.VerificationFalsePositive: "False positive",
	},
	status: map[string]string{
		db.FindingPending:       "Pending triage",
		db.FindingInProgress:    "In progress",
		db.FindingConfirmed:     "Confirmed",
		db.FindingResolved:      "Resolved",
		db.FindingFixed:         "Fixed",
		db.FindingFalsePositive: "False positive",
		db.FindingIgnored:       "Ignored",
		db.FindingDuplicate:     "Duplicate",
		db.FindingRiskAccepted:  "Risk accepted",
	},
}

var langID = reportStrings{
	code: "id",

	scopeFallback: "cakupan yang dinilai",

	coverTitle:           "LAPORAN UJI PENETRASI",
	coverSubtitle:        "Penilaian keamanan otomatis berbasis bukti",
	coverConfidential:    "RAHASIA — HANYA UNTUK PENERIMA YANG BERWENANG",
	coverObjective:       "Tujuan",
	coverGeneratedPrefix: "Dibuat pada: ",
	coverGeneratedBy:     "Dibuat oleh: ARTEX Autonomous Penetration Testing Platform",

	confHeading: "Kerahasiaan",
	confPara1Fmt: "Dokumen ini menyajikan hasil penilaian keamanan terhadap %s. " +
		"Dokumen ditujukan untuk operator yang menugaskan pekerjaan ini dan penerima yang mereka tunjuk.",
	confPara2: "Laporan ini dapat memuat informasi tentang kelemahan yang dapat dieksploitasi pada sistem yang diuji. " +
		"Perlakukan sebagai rahasia: dilarang menyalin, meneruskan, atau mempublikasikannya, sebagian maupun seluruhnya, " +
		"tanpa persetujuan tertulis terlebih dahulu dari pihak yang menugaskan penilaian ini.",
	confPara3: "Uji penetrasi adalah penilaian pada satu titik waktu. Hasilnya tidak membuktikan tidak adanya kerentanan, " +
		"melainkan hanya bahwa kondisi yang diuji, sesuai cakupan tugas ini, telah diperiksa pada saat pengujian berlangsung. " +
		"Perubahan pada sistem atau lingkungannya setelah itu dapat mengubah postur keamanannya.",

	methodHeading: "Metodologi",
	methodIntro: "Penilaian ini dilakukan oleh ARTEX, platform uji penetrasi otonom berbasis LLM yang di-hosting sendiri. " +
		"Sebuah planner memecah tujuan tugas menjadi intent; seorang worker menjalankan tiap intent dengan tool nyata " +
		"di bawah kebijakan dan gerbang persetujuan, lalu menuliskan aset, fakta, dan temuan yang teramati kembali ke " +
		"exploration graph tugas tersebut. Siklus ini berulang sampai tujuan terbukti atau tugas dihentikan.",
	methodPhases: []phaseText{
		{"Reconnaissance", "Penemuan aset, fingerprinting layanan/teknologi, dan enumerasi endpoint dalam cakupan yang dideklarasikan tugas."},
		{"Pengujian", "Identifikasi kerentanan dan, bila diizinkan, upaya eksploitasi — dikendalikan oleh kebijakan intercept/persetujuan dan profil noise yang aktif."},
		{"Verifikasi", "Temuan diikat ke bukti yang terekam (traffic tertangkap atau output tool) dan, bila dikonfigurasi, diuji ulang sebelum dilaporkan sebagai terkonfirmasi."},
		{"Pelaporan", "Temuan terkonfirmasi, kekuatan buktinya, dan celah cakupan yang terbuka dirangkum dalam laporan ini."},
	},

	stdHeading: "Standar & Referensi",
	stdIntro:   "Pengujian mengacu pada referensi industri yang umum, antara lain:",
	stdBullets: []string{
		"OWASP — Open Web Application Security Project (Top 10, Testing Guide, API Security Top 10)",
		"NIST — National Institute of Standards and Technology Cybersecurity Framework",
		"CIS — Center for Internet Security Benchmarks",
		"CVSS — Common Vulnerability Scoring System (acuan tingkat keparahan)",
	},
	stdOwaspHeading: "OWASP Top 10:2021",

	execHeading: "Ringkasan Eksekutif",
	execSummaryFmt: "Laporan ini menyajikan hasil uji penetrasi otomatis berbasis bukti terhadap %s. " +
		"%d temuan terkonfirmasi selama penilaian ini.",
	execSeverityBreakdown: "Rincian tingkat keparahan",
	execAssetsInScope:     "Aset dalam cakupan",
	execNoAssets:          "Tidak ada aset yang tercatat untuk tugas ini.",
	execFindingsSummary:   "Ringkasan temuan",
	execNoFindings:        "Tidak ada kerentanan yang terkonfirmasi selama penilaian ini.",

	tblSeverity:         "Tingkat Risiko",
	tblCount:            "Jumlah",
	tblTotal:            "Total",
	tblInfoUnclassified: "INFORMASI / TAK TERKLASIFIKASI",
	tblNum:              "No",
	tblFinding:          "Temuan",
	tblVerification:     "Verifikasi",

	findingsHeading:     "Detail Temuan",
	findingsNone:        "Tidak ada kerentanan yang terkonfirmasi kali ini.",
	lblFindingRecord:    "Nomor temuan",
	lblPoE:              "Tingkat PoE",
	lblVerification:     "Verifikasi",
	lblProof:            "Bukti",
	lblVerificationNote: "Catatan verifikasi",
	lblStatus:           "Status",
	lblOWASP:            "OWASP Top 10:2021",
	lblPoC:              "PoC / Bukti:",
	lblConfidence:       "Dasar keyakinan:",
	lblCounterevidence:  "Kontra-bukti:",
	lblDetailedReport:   "Laporan terperinci:",
	staleNotice:         "Bukti telah berubah; laporan terperinci perlu diperbarui.",
	proofNone:           "tidak ada bukti traffic yang terikat",
	proofBoundFmt:       "%d pertukaran traffic terikat",
	verifUnavailable:    "tidak diketahui (pembacaan kualitas gagal — kekuatan bukti tidak tersedia)",
	verifMissing:        "tidak dinilai (tidak ada catatan temuan — field kualitas tidak tersedia)",
	owaspUnmapped:       "tidak dipetakan ke kategori tertentu",

	coverageHeading:  "Lampiran A — Cakupan",
	lblCompleteness:  "Kelengkapan",
	lblLedgerEntries: "Entri ledger",
	lblOpenGaps:      "Celah terbuka",
	coverageMoreFmt:  "…dan %d lainnya (lihat coverage API).",

	docTitlePrefix:     "Laporan Uji Penetrasi — ",
	footerConfidential: "RAHASIA",
	footerPagePrefix:   "Halaman ",
	footerPageOf:       " dari ",

	severity: map[string]string{
		"critical": "KRITIKAL", "high": "TINGGI", "medium": "SEDANG", "low": "RENDAH", "": "INFORMASI",
	},
	verification: map[string]string{
		db.VerificationUnverified:    "Belum terverifikasi",
		db.VerificationVerified:      "Terverifikasi",
		db.VerificationBlocked:       "Terblokir",
		db.VerificationNotAssessed:   "Tidak dinilai",
		db.VerificationFalsePositive: "False positive",
	},
	status: map[string]string{
		db.FindingPending:       "Menunggu triase",
		db.FindingInProgress:    "Sedang dikerjakan",
		db.FindingConfirmed:     "Terkonfirmasi",
		db.FindingResolved:      "Selesai ditangani",
		db.FindingFixed:         "Sudah diperbaiki",
		db.FindingFalsePositive: "False positive",
		db.FindingIgnored:       "Diabaikan",
		db.FindingDuplicate:     "Duplikat",
		db.FindingRiskAccepted:  "Risiko diterima",
	},
}
