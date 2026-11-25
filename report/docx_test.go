package report

import (
	"archive/zip"
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/artex/db"
)

// docxParts unzips a Docx() result into name -> content, failing the test on
// any zip error so every other helper can assume the archive itself is valid.
func docxParts(t *testing.T, data []byte) map[string]string {
	t.Helper()
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatalf("docx is not a valid zip: %v", err)
	}
	out := map[string]string{}
	for _, f := range zr.File {
		rc, err := f.Open()
		if err != nil {
			t.Fatalf("open %s: %v", f.Name, err)
		}
		b, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			t.Fatalf("read %s: %v", f.Name, err)
		}
		out[f.Name] = string(b)
	}
	return out
}

// mustBeWellFormedXML fully tokenizes s, catching any unescaped '&'/'<' or
// unbalanced tag that string concatenation could have produced — the one
// property hand-built OOXML absolutely cannot get wrong without Word refusing
// to open the file.
func mustBeWellFormedXML(t *testing.T, part, s string) {
	t.Helper()
	dec := xml.NewDecoder(strings.NewReader(s))
	for {
		_, err := dec.Token()
		if err == io.EOF {
			return
		}
		if err != nil {
			t.Fatalf("%s is not well-formed XML: %v", part, err)
		}
	}
}

// requiredDocxParts are the OOXML parts build() always writes; every one of
// them must exist and parse, or Word shows a "found a problem" repair prompt
// instead of the report.
var requiredDocxParts = []string{
	"[Content_Types].xml", "_rels/.rels", "docProps/core.xml", "docProps/app.xml",
	"word/_rels/document.xml.rels", "word/styles.xml", "word/header1.xml", "word/footer1.xml", "word/document.xml",
}

func TestDocxWellFormed(t *testing.T) {
	data, err := Docx(Input{
		Title:       "Acme Corp — Q4 Assessment",
		Goal:        "Find and prove exploitable vulnerabilities in scope.",
		GeneratedAt: time.Date(2026, 1, 15, 10, 0, 0, 0, time.UTC),
		AssetCounts: map[string]int{"subdomain": 3, "endpoint": 12},
		Findings: []*db.Node{
			reportNode(1, "critical", "SQL Injection"),
			reportNode(2, "low", "Verbose Error Page"),
		},
		Quality: map[int64]db.FindingQuality{
			1: {FindingMeta: db.FindingMeta{TrafficCount: 2}, PoeLevel: 5, VerificationStatus: db.VerificationVerified},
		},
	})
	if err != nil {
		t.Fatalf("Docx: %v", err)
	}
	parts := docxParts(t, data)
	for _, name := range requiredDocxParts {
		content, ok := parts[name]
		if !ok {
			t.Fatalf("missing required part %s", name)
		}
		mustBeWellFormedXML(t, name, content)
	}
}

// Findings must be severity-sorted the same way Markdown() sorts them
// (critical, high, medium, low, unclassified) — the two deliverables must
// never present a different finding #1.
func TestDocxFindingsSortedBySeverity(t *testing.T) {
	data, err := Docx(Input{
		Title: "t",
		Findings: []*db.Node{
			reportNode(1, "low", "Low One"),
			reportNode(2, "critical", "Critical One"),
			reportNode(3, "medium", "Medium One"),
		},
		Quality: map[int64]db.FindingQuality{},
	})
	if err != nil {
		t.Fatalf("Docx: %v", err)
	}
	doc := docxParts(t, data)["word/document.xml"]
	iCrit := strings.Index(doc, "Critical One")
	iMed := strings.Index(doc, "Medium One")
	iLow := strings.Index(doc, "Low One")
	if iCrit < 0 || iMed < 0 || iLow < 0 {
		t.Fatalf("not all findings rendered:\n%s", doc)
	}
	if !(iCrit < iMed && iMed < iLow) {
		t.Fatalf("findings not severity-sorted: critical@%d medium@%d low@%d", iCrit, iMed, iLow)
	}
	if !strings.Contains(doc, "1. [CRITICAL] ") {
		t.Errorf("missing numbered+severity-labeled heading for the first finding")
	}
}

// A task with no confirmed findings must say so in both the summary and the
// detailed-findings section, never render an empty table instead.
func TestDocxNoFindings(t *testing.T) {
	data, err := Docx(Input{Title: "Empty Task", GeneratedAt: time.Now()})
	if err != nil {
		t.Fatalf("Docx: %v", err)
	}
	doc := docxParts(t, data)["word/document.xml"]
	for _, want := range []string{
		"No vulnerabilities were confirmed during this assessment.",
		"No vulnerabilities confirmed this time.",
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("missing %q in\n%s", want, doc)
		}
	}
}

// The coverage appendix appears only when the task's coverage feature is on
// (non-nil ledger), mirroring TestMarkdownCoverageGaps.
func TestDocxCoverageAppendix(t *testing.T) {
	l := db.BuildCoverageLedger(
		[]db.CoverageEntry{{Surface: "/a", RiskArea: "xss", Outcome: db.OutcomeNeedsFollowUp}},
		[]string{"sqli"}, db.CoverageCompletenessFor("timeout", false, false, true))

	withCoverage, err := Docx(Input{Title: "t", Coverage: l})
	if err != nil {
		t.Fatalf("Docx: %v", err)
	}
	doc := docxParts(t, withCoverage)["word/document.xml"]
	for _, want := range []string{"Appendix A", "timeout", "unrecorded_risk_class sqli", "needs_follow_up /a xss"} {
		if !strings.Contains(doc, want) {
			t.Errorf("missing %q in coverage appendix:\n%s", want, doc)
		}
	}

	withoutCoverage, err := Docx(Input{Title: "t", Coverage: nil})
	if err != nil {
		t.Fatalf("Docx: %v", err)
	}
	doc2 := docxParts(t, withoutCoverage)["word/document.xml"]
	if strings.Contains(doc2, "Appendix A") {
		t.Errorf("unexpected coverage appendix when coverage is off:\n%s", doc2)
	}
}

// The coverage gap list caps at reportMaxGaps, same as Markdown.
func TestDocxCoverageGapsCap(t *testing.T) {
	var entries []db.CoverageEntry
	for i := 0; i < reportMaxGaps+30; i++ {
		entries = append(entries, db.CoverageEntry{Surface: "/p", RiskArea: "xss", Outcome: db.OutcomeNeedsFollowUp})
	}
	data, err := Docx(Input{Title: "t", Coverage: db.BuildCoverageLedger(entries, nil, db.CoverageCompleteness{})})
	if err != nil {
		t.Fatalf("Docx: %v", err)
	}
	doc := docxParts(t, data)["word/document.xml"]
	if n := strings.Count(doc, "needs_follow_up /p xss"); n != reportMaxGaps {
		t.Fatalf("listed %d gaps, want %d", n, reportMaxGaps)
	}
	if !strings.Contains(doc, fmt.Sprintf("…and %d more", 30)) {
		t.Fatalf("missing overflow count line in\n%s", doc)
	}
}

// Dynamic, attacker-ish text (XML metacharacters in a finding's own fields)
// must survive as literal escaped text, not break the document's XML or let
// a crafted finding summary inject markup into the report.
func TestDocxEscapesDynamicText(t *testing.T) {
	payload := `{"vulnclass":"xss","name":"<script>alert(1)</script> & \"quoted\"","severity":"high","summary":"A & B < C","evidence":{"poc":"line1\nline2 <tag> & amp"}}`
	n := &db.Node{ID: 1, Kind: db.KindFinding, Payload: []byte(payload)}
	data, err := Docx(Input{Title: `Title with & < > " chars`, Findings: []*db.Node{n}, Quality: map[int64]db.FindingQuality{}})
	if err != nil {
		t.Fatalf("Docx: %v", err)
	}
	parts := docxParts(t, data)
	for name, content := range parts {
		mustBeWellFormedXML(t, name, content)
	}
	doc := parts["word/document.xml"]
	if strings.Contains(doc, "<script>") {
		t.Fatalf("raw <script> tag leaked unescaped into document.xml")
	}
	if !strings.Contains(doc, "alert(1)") {
		t.Errorf("escaped finding name text is missing entirely, not just escaped")
	}
	if !strings.Contains(doc, "line1") || !strings.Contains(doc, "line2") {
		t.Errorf("multi-line PoC text missing from the PoC code block")
	}
}

// PoE level, verification state and bound-traffic count must appear for a
// finding that has a quality row, using the same labels verificationLabel()
// and qualityBullets() use for Markdown.
func TestDocxProofStrengthBullets(t *testing.T) {
	data, err := Docx(Input{
		Title:    "t",
		Findings: []*db.Node{reportNode(1, "high", "Finding One")},
		Quality: map[int64]db.FindingQuality{
			1: {FindingMeta: db.FindingMeta{ID: 42, TrafficCount: 3}, PoeLevel: 4, VerificationStatus: db.VerificationVerified, VerificationNote: "checked twice"},
		},
	})
	if err != nil {
		t.Fatalf("Docx: %v", err)
	}
	doc := docxParts(t, data)["word/document.xml"]
	for _, want := range []string{"Finding record", "#42", "PoE level", "4", "Verification", "Verified", "3 bound traffic exchange(s)", "checked twice"} {
		if !strings.Contains(doc, want) {
			t.Errorf("missing %q in proof-strength bullets:\n%s", want, doc)
		}
	}
}

// A finding with no standalone quality row (Missing) and one whose lookup
// failed entirely (Unavailable) must render their own honest labels, never
// silently drop the finding or claim it is unverified.
func TestDocxMissingAndUnavailableQuality(t *testing.T) {
	missing, err := Docx(Input{
		Title:    "t",
		Findings: []*db.Node{reportNode(1, "medium", "No Row")},
		Quality:  map[int64]db.FindingQuality{}, // non-nil, empty: genuinely no rows
	})
	if err != nil {
		t.Fatalf("Docx: %v", err)
	}
	if doc := docxParts(t, missing)["word/document.xml"]; !strings.Contains(doc, "not assessed (no finding record") {
		t.Errorf("missing 'not assessed' label for a finding with no quality row:\n%s", doc)
	}

	unavailable, err := Docx(Input{
		Title:    "t",
		Findings: []*db.Node{reportNode(1, "medium", "Lookup Failed")},
		Quality:  nil, // nil: the lookup itself failed
	})
	if err != nil {
		t.Fatalf("Docx: %v", err)
	}
	if doc := docxParts(t, unavailable)["word/document.xml"]; !strings.Contains(doc, "unknown (quality lookup failed") {
		t.Errorf("missing 'lookup failed' label when Quality is nil:\n%s", doc)
	}
}

// The build output must be byte-identical across calls with the same Input
// (deterministic zip entry order, no timestamps baked in beyond GeneratedAt),
// so the report can be diffed/cached and tested reliably.
func TestDocxDeterministic(t *testing.T) {
	in := Input{Title: "t", GeneratedAt: time.Unix(0, 0).UTC(), Findings: []*db.Node{reportNode(1, "low", "F")}, Quality: map[int64]db.FindingQuality{}}
	a, err := Docx(in)
	if err != nil {
		t.Fatalf("Docx: %v", err)
	}
	b, err := Docx(in)
	if err != nil {
		t.Fatalf("Docx: %v", err)
	}
	if !bytes.Equal(a, b) {
		t.Fatalf("Docx output is not deterministic for identical Input")
	}
}

// The three new front-matter sections (confidentiality, methodology,
// standards) render, are generic to ARTEX (no third-party firm/client name,
// no copied wording from any other report), and precede the executive
// summary.
func TestDocxFrontMatterSections(t *testing.T) {
	data, err := Docx(Input{Title: "Acme Corp — Q4 Assessment", GeneratedAt: time.Now()})
	if err != nil {
		t.Fatalf("Docx: %v", err)
	}
	doc := docxParts(t, data)["word/document.xml"]
	// "&" is correctly XML-escaped to "&amp;" inside the document part.
	for _, want := range []string{
		"Confidentiality", "Methodology", "Standards &amp; References",
		"ARTEX, a self-hosted, LLM-driven autonomous penetration testing",
		"OWASP Top 10:2021",
		"A01:2021 – Broken Access Control",
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("missing %q in front matter:\n%s", want, doc)
		}
	}
	iConf := strings.Index(doc, "Confidentiality")
	iMethod := strings.Index(doc, "Methodology")
	iStd := strings.Index(doc, "Standards &amp; References")
	iExec := strings.Index(doc, "Executive Summary")
	if !(iConf < iMethod && iMethod < iStd && iStd < iExec) {
		t.Fatalf("front matter out of order: confidentiality@%d methodology@%d standards@%d execsummary@%d", iConf, iMethod, iStd, iExec)
	}

	// None of this is specific to any one client or third-party firm: it must
	// read the same regardless of the task's own title.
	for _, name := range []string{"ACSI", "Alpha Citra Siber", "Bank Aceh", "vaccmasys"} {
		if strings.Contains(doc, name) {
			t.Fatalf("front matter unexpectedly names a third party (%q):\n%s", name, doc)
		}
	}
}

// Status and the OWASP mapping render per finding in the docx, with the same
// honest fallback as Markdown for an unmapped vulnclass, and are absent for a
// finding that was never triaged.
func TestDocxStatusAndOWASPReference(t *testing.T) {
	findings := []*db.Node{
		reportNode(1, "critical", "SQL Injection"),
		reportNode(2, "low", "Weird Legacy Protocol Quirk"),
	}
	data, err := Docx(Input{
		Title:    "t",
		Findings: findings,
		Quality: map[int64]db.FindingQuality{
			1: {FindingMeta: db.FindingMeta{ID: 1, Status: db.FindingConfirmed}},
		},
	})
	if err != nil {
		t.Fatalf("Docx: %v", err)
	}
	doc := docxParts(t, data)["word/document.xml"]
	for _, want := range []string{"Status", "Confirmed", "OWASP Top 10:2021", "A03:2021 – Injection", "not mapped to a specific category"} {
		if !strings.Contains(doc, want) {
			t.Errorf("missing %q:\n%s", want, doc)
		}
	}
}

// Indonesian (Lang:"id") localizes the structural labels — cover, section
// headings, severity labels, table headers, confidentiality/footer — while
// leaving finding data and standard identifiers (OWASP codes) untouched. An
// unknown language code falls back to English.
func TestDocxIndonesian(t *testing.T) {
	in := Input{
		Lang:        "id",
		Title:       "Penilaian Q4",
		GeneratedAt: time.Date(2026, 1, 15, 10, 0, 0, 0, time.UTC),
		Findings:    []*db.Node{reportNode(1, "critical", "Temuan Kritikal")},
		Quality: map[int64]db.FindingQuality{
			1: {FindingMeta: db.FindingMeta{ID: 1, Status: db.FindingFixed}, VerificationStatus: db.VerificationVerified},
		},
	}
	data, err := Docx(in)
	if err != nil {
		t.Fatalf("Docx: %v", err)
	}
	parts := docxParts(t, data)
	for name, content := range parts {
		mustBeWellFormedXML(t, name, content)
	}
	doc := parts["word/document.xml"]
	for _, want := range []string{
		"LAPORAN UJI PENETRASI",          // cover title
		"RAHASIA — HANYA UNTUK PENERIMA", // cover confidential
		"Kerahasiaan",                    // confidentiality heading
		"Metodologi",                     // methodology heading
		"Standar &amp; Referensi",        // standards heading (escaped &)
		"Ringkasan Eksekutif",            // exec summary heading
		"Tingkat Risiko",                 // severity table header
		"KRITIKAL",                       // localized severity label
		"Detail Temuan",                  // findings heading
		"Sudah diperbaiki",               // localized status
		"Terverifikasi",                  // localized verification
		"OWASP Top 10:2021",              // standard identifier, untranslated
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("Indonesian report missing %q:\n%s", want, doc)
		}
	}
	// English cover title must NOT appear in the Indonesian report.
	if strings.Contains(doc, "PENETRATION TEST REPORT") {
		t.Errorf("Indonesian report leaked the English cover title")
	}
	// Footer page metadata part localized too.
	footer := parts["word/footer1.xml"]
	if !strings.Contains(footer, "RAHASIA") || !strings.Contains(footer, "Halaman ") {
		t.Errorf("Indonesian footer not localized:\n%s", footer)
	}

	// An unknown language code falls back to English rather than erroring.
	enFallback, err := Docx(Input{Lang: "xx", Title: "t"})
	if err != nil {
		t.Fatalf("Docx fallback: %v", err)
	}
	if !strings.Contains(docxParts(t, enFallback)["word/document.xml"], "PENETRATION TEST REPORT") {
		t.Errorf("unknown lang code did not fall back to English")
	}
}
