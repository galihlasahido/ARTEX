package report

import (
	"archive/zip"
	"bytes"
	"encoding/xml"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// Docx renders the same Input that Markdown renders into a professional
// Microsoft Word (.docx) deliverable, structured like a standard commercial
// pentest report: a cover page, a confidentiality notice, ARTEX's own testing
// methodology, the standards/references the testing is held to, an executive
// summary with a severity-breakdown and findings-summary table, one detailed
// section per finding (severity, status, proof-strength bullets, OWASP
// mapping, PoC/evidence, the two written attestations, the stale-evidence
// warning, the detailed report body), and a coverage-gap appendix — every
// finding-bearing section gated by the exact same conditions Markdown uses, so
// the two deliverables never disagree about what counts as a confirmed
// finding or how strong its proof is. The front-matter pages (confidentiality,
// methodology, standards) are presentational only — generic to ARTEX itself,
// carrying no finding data — so they exist in this richer deliverable without
// pulling Markdown into rendering them too.
//
// The OOXML package (the .docx zip and its XML parts) is built here by hand
// from the standard library only (archive/zip + encoding/xml for escaping) —
// deliberately not through a third-party docx library — so this stays a
// dependency-free, fully auditable text transform, matching Markdown's own
// "pure function over Input" shape and this project's general wariness of
// pulling in document-format libraries for a single feature.
func Docx(in Input) ([]byte, error) {
	d := &docxBuilder{s: stringsFor(in.Lang)}
	d.renderCover(in)
	d.renderConfidentiality(in)
	d.renderMethodology()
	d.renderStandards()
	d.renderExecutiveSummary(in)
	d.renderFindings(in)
	d.renderCoverageAppendix(in)
	return d.build(in)
}

// docxBuilder accumulates word/document.xml's body as a sequence of already-
// escaped <w:p>…</w:p> (or <w:tbl>…</w:tbl>) blocks. Every public render*
// method appends whole blocks; nothing downstream re-parses or re-escapes them.
type docxBuilder struct {
	body strings.Builder
	s    reportStrings // the localized label table for this report's language
}

// --- low-level XML helpers -------------------------------------------------

// escXML escapes s for use inside a <w:t> text node or an attribute value.
// encoding/xml.EscapeText covers &, <, >, and the control characters Word's
// strict XML parser otherwise rejects, so every piece of dynamic report text
// (task names, finding summaries, PoC bodies, operator-written reports) goes
// through this before it is concatenated into the document.
func escXML(s string) string {
	var b bytes.Buffer
	_ = xml.EscapeText(&b, []byte(s))
	return b.String()
}

// run renders one <w:r> with optional bold/italic/color/size(half-points)/font
// and text content split on "\n" into separate lines joined by <w:br/>, so a
// single run can carry a multi-line PoC or report body verbatim.
type runProps struct {
	bold   bool
	italic bool
	color  string // hex, no '#'; "" = inherit
	sizeHP int    // half-points; 0 = inherit
	font   string // "" = inherit (Normal style's font)
}

func (d *docxBuilder) run(text string, p runProps) string {
	var rpr strings.Builder
	if p.bold {
		rpr.WriteString("<w:b/>")
	}
	if p.italic {
		rpr.WriteString("<w:i/>")
	}
	if p.color != "" {
		fmt.Fprintf(&rpr, `<w:color w:val="%s"/>`, p.color)
	}
	if p.sizeHP > 0 {
		fmt.Fprintf(&rpr, `<w:sz w:val="%d"/><w:szCs w:val="%d"/>`, p.sizeHP, p.sizeHP)
	}
	if p.font != "" {
		fmt.Fprintf(&rpr, `<w:rFonts w:ascii="%s" w:hAnsi="%s" w:cs="%s"/>`, p.font, p.font, p.font)
	}
	rprXML := ""
	if rpr.Len() > 0 {
		rprXML = "<w:rPr>" + rpr.String() + "</w:rPr>"
	}
	lines := strings.Split(text, "\n")
	var b strings.Builder
	for i, line := range lines {
		if i > 0 {
			b.WriteString("<w:br/>")
		}
		fmt.Fprintf(&b, `<w:t xml:space="preserve">%s</w:t>`, escXML(line))
	}
	return "<w:r>" + rprXML + b.String() + "</w:r>"
}

// para wraps one or more already-built <w:r> runs into a <w:p>, with optional
// paragraph-level alignment/spacing/shading/indent.
type paraProps struct {
	center     bool
	spacingPt  int // space-before, in points; 0 = default
	shadeFill  string
	hangBullet bool // "•  " hanging-indent list item
	borderTop  bool // thin top rule (used as a separator between findings)
}

func (d *docxBuilder) para(runs string, p paraProps) string {
	var ppr strings.Builder
	if p.center {
		ppr.WriteString(`<w:jc w:val="center"/>`)
	}
	if p.spacingPt > 0 {
		fmt.Fprintf(&ppr, `<w:spacing w:before="%d"/>`, p.spacingPt*20)
	}
	if p.shadeFill != "" {
		fmt.Fprintf(&ppr, `<w:shd w:val="clear" w:color="auto" w:fill="%s"/>`, p.shadeFill)
	}
	if p.hangBullet {
		ppr.WriteString(`<w:ind w:left="432" w:hanging="432"/>`)
	}
	if p.borderTop {
		ppr.WriteString(`<w:pBdr><w:top w:val="single" w:sz="6" w:space="8" w:color="BFBFBF"/></w:pBdr>`)
	}
	pprXML := ""
	if ppr.Len() > 0 {
		pprXML = "<w:pPr>" + ppr.String() + "</w:pPr>"
	}
	return "<w:p>" + pprXML + runs + "</w:p>"
}

func (d *docxBuilder) plain(text string, p paraProps) {
	d.body.WriteString(d.para(d.run(text, runProps{}), p))
}

func (d *docxBuilder) heading1(text string) {
	d.body.WriteString(d.para(d.run(text, runProps{bold: true, sizeHP: 32, color: "6B34DB"}), paraProps{spacingPt: 18}))
}

func (d *docxBuilder) heading2(text string, color string) {
	if color == "" {
		color = "6B34DB"
	}
	d.body.WriteString(d.para(d.run(text, runProps{bold: true, sizeHP: 26, color: color}), paraProps{spacingPt: 14}))
}

func (d *docxBuilder) bullet(text string) {
	d.body.WriteString(d.para(d.run("•  "+text, runProps{}), paraProps{hangBullet: true}))
}

// bulletKV renders "**Label**: value" bullets the way qualityBullets() already
// writes them in Markdown, as a bold label run followed by a plain run — so the
// docx bullet text matches the Markdown bullet text exactly, field for field.
func (d *docxBuilder) bulletKV(label, value string) {
	runs := d.run("•  ", runProps{}) + d.run(label+": ", runProps{bold: true}) + d.run(value, runProps{})
	d.body.WriteString(d.para(runs, paraProps{hangBullet: true}))
}

func (d *docxBuilder) pageBreak() {
	d.body.WriteString(`<w:p><w:r><w:br w:type="page"/></w:r></w:p>`)
}

// codeBlock renders a monospace, lightly shaded block preserving every line
// break — used for PoC/evidence text and for fenced code inside a reporter-
// written detailed-report body. Each line is its own shaded paragraph so a
// very long block still wraps and shades correctly instead of growing one
// giant unshaded run.
func (d *docxBuilder) codeBlock(text string) {
	for _, line := range strings.Split(strings.TrimRight(text, "\n"), "\n") {
		if line == "" {
			line = " "
		}
		d.body.WriteString(d.para(d.run(line, runProps{font: "Consolas", sizeHP: 18}), paraProps{shadeFill: "F2F2F2"}))
	}
}

// markdownBlock renders a Markdown-ish body (the two free-text attestations
// and the reporter-written detailed report, all stored as Markdown — see
// db.FindingQuality.Report) with just enough fidelity for a report: blank-line
// paragraphs, ```-fenced blocks as codeBlock, "- " lines as bullets, and inline
// **bold**. It is not a full Markdown parser; it exists so the same stored text
// reads sensibly in both the Markdown report and this docx, never so it can
// round-trip arbitrary Markdown.
func (d *docxBuilder) markdownBlock(md string) {
	lines := strings.Split(md, "\n")
	inFence := false
	var fence []string
	var para []string
	flushPara := func() {
		if len(para) == 0 {
			return
		}
		d.body.WriteString(d.para(d.inlineBold(strings.Join(para, " ")), paraProps{}))
		para = nil
	}
	for _, line := range lines {
		trimmed := strings.TrimLeft(line, " \t")
		if strings.HasPrefix(trimmed, "```") {
			if inFence {
				d.codeBlock(strings.Join(fence, "\n"))
				fence = nil
				inFence = false
			} else {
				flushPara()
				inFence = true
			}
			continue
		}
		if inFence {
			fence = append(fence, line)
			continue
		}
		if strings.TrimSpace(line) == "" {
			flushPara()
			continue
		}
		if strings.HasPrefix(trimmed, "- ") {
			flushPara()
			d.body.WriteString(d.para(d.inlineBold("•  "+strings.TrimPrefix(trimmed, "- ")), paraProps{hangBullet: true}))
			continue
		}
		para = append(para, strings.TrimSpace(line))
	}
	if inFence {
		d.codeBlock(strings.Join(fence, "\n")) // unterminated fence: render what there is rather than drop it
	}
	flushPara()
}

// inlineBold splits text on **bold** markers and renders each segment as its
// own run, so "**Label**: value" becomes a bold run followed by a plain run.
func (d *docxBuilder) inlineBold(text string) string {
	var b strings.Builder
	segs := strings.Split(text, "**")
	for i, seg := range segs {
		if seg == "" {
			continue
		}
		b.WriteString(d.run(seg, runProps{bold: i%2 == 1}))
	}
	return b.String()
}

// --- severity -----------------------------------------------------------

func severityColor(sev string) string {
	switch strings.ToLower(sev) {
	case "critical":
		return "C00000"
	case "high":
		return "FF0000"
	case "medium":
		return "ED7D31"
	case "low":
		return "BF8F00"
	default:
		return "808080"
	}
}

func severityLabel(sev string) string {
	return strings.ToUpper(nz(sev, "INFO"))
}

// --- sections -------------------------------------------------------------

func (d *docxBuilder) renderCover(in Input) {
	for i := 0; i < 6; i++ {
		d.body.WriteString(d.para("", paraProps{}))
	}
	d.body.WriteString(d.para(d.run(d.s.coverTitle, runProps{bold: true, sizeHP: 56, color: "6B34DB"}), paraProps{center: true, spacingPt: 12}))
	d.body.WriteString(d.para(d.run(nz(in.Title, "Unnamed task"), runProps{bold: true, sizeHP: 32}), paraProps{center: true, spacingPt: 24}))
	d.body.WriteString(d.para(d.run(d.s.coverSubtitle, runProps{italic: true, sizeHP: 22}), paraProps{center: true, spacingPt: 8}))
	d.body.WriteString(d.para("", paraProps{spacingPt: 36}))
	d.body.WriteString(d.para(d.run(d.s.coverConfidential, runProps{bold: true, sizeHP: 24, color: "C00000"}), paraProps{center: true}))
	d.body.WriteString(d.para("", paraProps{spacingPt: 36}))
	if goal := strings.TrimSpace(in.Goal); goal != "" {
		d.body.WriteString(d.para(d.run(d.s.coverObjective, runProps{bold: true, sizeHP: 22}), paraProps{center: true, spacingPt: 8}))
		d.body.WriteString(d.para(d.run(truncate(goal, 500), runProps{sizeHP: 20}), paraProps{center: true, spacingPt: 4}))
	}
	d.body.WriteString(d.para("", paraProps{spacingPt: 24}))
	d.body.WriteString(d.para(d.run(d.s.coverGeneratedPrefix+in.GeneratedAt.Format("2006-01-02 15:04:05"), runProps{sizeHP: 20}), paraProps{center: true, spacingPt: 4}))
	d.body.WriteString(d.para(d.run(d.s.coverGeneratedBy, runProps{sizeHP: 20}), paraProps{center: true, spacingPt: 4}))
	d.pageBreak()
}

// renderConfidentiality renders a generic confidentiality notice. It names no
// third party and reproduces no other report's wording — only the task's own
// Title, which the operator controls — so it carries forward the *idea* that a
// pentest deliverable states who it is for and that it is not for further
// distribution, without copying anyone else's confidential document text.
func (d *docxBuilder) renderConfidentiality(in Input) {
	d.heading1(d.s.confHeading)
	d.plain(fmt.Sprintf(d.s.confPara1Fmt, nz(in.Title, d.s.scopeFallback)), paraProps{spacingPt: 8})
	d.plain(d.s.confPara2, paraProps{spacingPt: 8})
	d.plain(d.s.confPara3, paraProps{spacingPt: 8})
	d.pageBreak()
}

// renderMethodology documents ARTEX's own actual testing workflow (see
// docs/ARCHITECTURE.md §3 and the engine loop in server/engine.go) — not any
// other firm's methodology — so this section is accurate about the tool that
// produced the report instead of being decorative boilerplate.
func (d *docxBuilder) renderMethodology() {
	d.heading1(d.s.methodHeading)
	d.plain(d.s.methodIntro, paraProps{spacingPt: 8})
	for _, p := range d.s.methodPhases {
		runs := d.run(p.name+": ", runProps{bold: true, color: "6B34DB"}) + d.run(p.detail, runProps{})
		d.body.WriteString(d.para(runs, paraProps{spacingPt: 10}))
	}
	d.pageBreak()
}

// renderStandards lists the public industry standards/frameworks ARTEX's
// testing draws on and the OWASP Top 10:2021 categories findings in this
// report are mapped against (see owaspReference, quality.go) — all public
// reference material, not any third party's proprietary content.
func (d *docxBuilder) renderStandards() {
	d.heading1(d.s.stdHeading)
	d.plain(d.s.stdIntro, paraProps{spacingPt: 8})
	for _, s := range d.s.stdBullets {
		d.bullet(s)
	}
	d.heading2(d.s.stdOwaspHeading, "")
	for _, s := range []string{
		"A01:2021 – Broken Access Control", "A02:2021 – Cryptographic Failures", "A03:2021 – Injection",
		"A04:2021 – Insecure Design", "A05:2021 – Security Misconfiguration", "A06:2021 – Vulnerable and Outdated Components",
		"A07:2021 – Identification and Authentication Failures", "A08:2021 – Software and Data Integrity Failures",
		"A09:2021 – Security Logging and Monitoring Failures", "A10:2021 – Server-Side Request Forgery",
	} {
		d.bullet(s)
	}
	d.pageBreak()
}

func (d *docxBuilder) renderExecutiveSummary(in Input) {
	d.heading1(d.s.execHeading)

	fs := sortedFindingViews(in)
	counts := map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0, "": 0}
	for _, f := range fs {
		key := strings.ToLower(f.Severity)
		if _, ok := counts[key]; !ok {
			key = ""
		}
		counts[key]++
	}
	d.plain(fmt.Sprintf(d.s.execSummaryFmt, nz(in.Title, d.s.scopeFallback), len(fs)), paraProps{spacingPt: 8})

	d.heading2(d.s.execSeverityBreakdown, "")
	d.severityTable(counts)

	d.heading2(d.s.execAssetsInScope, "")
	var types []string
	for t := range in.AssetCounts {
		types = append(types, t)
	}
	sort.Strings(types)
	if len(types) == 0 {
		d.plain(d.s.execNoAssets, paraProps{})
	}
	for _, t := range types {
		d.bulletKV(humanizeAssetType(t), strconv.Itoa(in.AssetCounts[t]))
	}

	d.heading2(d.s.execFindingsSummary, "")
	if len(fs) == 0 {
		d.plain(d.s.execNoFindings, paraProps{})
	} else {
		d.findingsSummaryTable(fs)
	}
	d.pageBreak()
}

func (d *docxBuilder) renderFindings(in Input) {
	d.heading1(d.s.findingsHeading)
	fs := sortedFindingViews(in)
	if len(fs) == 0 {
		d.body.WriteString(d.para(d.run(d.s.findingsNone, runProps{italic: true}), paraProps{}))
		d.pageBreak()
		return
	}
	for i, f := range fs {
		if i > 0 {
			d.pageBreak()
		}
		title := nz(f.Name, nz(f.VulnClass, "Uncategorized"))
		runs := d.run(fmt.Sprintf("%d. [%s] ", i+1, d.s.severityDisplay(f.Severity)), runProps{bold: true, sizeHP: 26, color: severityColor(f.Severity)}) +
			d.run(title, runProps{bold: true, sizeHP: 26, color: "6B34DB"})
		d.body.WriteString(d.para(runs, paraProps{spacingPt: 14}))

		if s := strings.TrimSpace(f.Summary); s != "" {
			d.plain(s, paraProps{spacingPt: 6})
		}

		q := f.Q
		d.proofStrengthBullets(q)
		d.owaspReferenceBullet(f.VulnClass)

		if f.PoC != "" {
			d.body.WriteString(d.para(d.run(d.s.lblPoC, runProps{bold: true}), paraProps{spacingPt: 10}))
			d.codeBlock(f.PoC)
		}

		if s := strings.TrimSpace(q.ConfidenceRationale); s != "" {
			d.body.WriteString(d.para(d.run(d.s.lblConfidence, runProps{bold: true}), paraProps{spacingPt: 10}))
			d.markdownBlock(s)
		}
		if s := strings.TrimSpace(q.Counterevidence); s != "" {
			d.body.WriteString(d.para(d.run(d.s.lblCounterevidence, runProps{bold: true}), paraProps{spacingPt: 10}))
			d.markdownBlock(s)
		}
		if q.ReportStale() {
			d.plain(d.s.staleNotice, paraProps{spacingPt: 8})
		}
		if body := strings.TrimSpace(detailedReport(q.Report, "")); body != "" {
			d.body.WriteString(d.para(d.run(d.s.lblDetailedReport, runProps{bold: true}), paraProps{spacingPt: 10}))
			d.markdownBlock(body)
		}
	}
}

// proofStrengthBullets mirrors qualityBullets()'s exact logic (same three
// special-cased states, same field order) but emits docx bullets directly
// instead of parsing qualityBullets()'s Markdown string back apart, so a
// future change to that function's wording cannot desync the two renderers'
// *structure* while still keeping their *field order and labels* identical by
// inspection.
func (d *docxBuilder) proofStrengthBullets(q Quality) {
	if q.Unavailable {
		d.bulletKV(d.s.lblVerification, d.s.verifUnavailable)
		return
	}
	if q.Missing {
		d.bulletKV(d.s.lblVerification, d.s.verifMissing)
		return
	}
	if q.RecordID > 0 {
		d.bulletKV(d.s.lblFindingRecord, "#"+strconv.FormatInt(q.RecordID, 10))
	}
	d.bulletKV(d.s.lblPoE, strconv.Itoa(q.PoE))
	d.bulletKV(d.s.lblVerification, d.s.verificationDisplay(q.Verification))
	if q.TrafficCount > 0 {
		d.bulletKV(d.s.lblProof, fmt.Sprintf(d.s.proofBoundFmt, q.TrafficCount))
	} else {
		d.bulletKV(d.s.lblProof, d.s.proofNone)
	}
	if note := oneLine(q.VerificationNote); note != "" {
		d.bulletKV(d.s.lblVerificationNote, note)
	}
	if label := d.s.statusDisplay(q.Status); label != "" {
		d.bulletKV(d.s.lblStatus, label)
	}
}

// owaspReferenceBullet renders the OWASP Top 10:2021 mapping bullet for a
// finding's vulnclass, with the same honest-gap fallback Markdown uses
// (report.go) when nothing matches.
func (d *docxBuilder) owaspReferenceBullet(vulnClass string) {
	if category, url, ok := owaspReference(vulnClass); ok {
		d.bulletKV(d.s.lblOWASP, category+" ("+url+")")
	} else {
		d.bulletKV(d.s.lblOWASP, d.s.owaspUnmapped)
	}
}

func (d *docxBuilder) renderCoverageAppendix(in Input) {
	c := in.Coverage
	if c == nil {
		return
	}
	d.pageBreak()
	d.heading1(d.s.coverageHeading)
	if c.Completeness != nil {
		d.bulletKV(d.s.lblCompleteness, c.Completeness.State+". "+c.Completeness.Caveat)
	}
	d.bulletKV(d.s.lblLedgerEntries, strconv.Itoa(len(c.Entries)))
	d.bulletKV(d.s.lblOpenGaps, strconv.Itoa(len(c.Gaps)))
	for i, g := range c.Gaps {
		if i == reportMaxGaps {
			d.body.WriteString(d.para(d.run(fmt.Sprintf(d.s.coverageMoreFmt, len(c.Gaps)-reportMaxGaps), runProps{italic: true}), paraProps{}))
			break
		}
		d.bullet(g.String())
	}
}

// --- tables -----------------------------------------------------------

func (d *docxBuilder) tableOpen() {
	d.body.WriteString(`<w:tbl><w:tblPr><w:tblW w:w="0" w:type="auto"/><w:tblBorders>` +
		`<w:top w:val="single" w:sz="4" w:color="BFBFBF"/><w:left w:val="single" w:sz="4" w:color="BFBFBF"/>` +
		`<w:bottom w:val="single" w:sz="4" w:color="BFBFBF"/><w:right w:val="single" w:sz="4" w:color="BFBFBF"/>` +
		`<w:insideH w:val="single" w:sz="4" w:color="BFBFBF"/><w:insideV w:val="single" w:sz="4" w:color="BFBFBF"/>` +
		`</w:tblBorders></w:tblPr>`)
}

func (d *docxBuilder) tableClose() {
	d.body.WriteString(`</w:tbl>`)
	d.body.WriteString(`<w:p/>`) // a paragraph must follow a table in word/document.xml
}

func (d *docxBuilder) tableRow(cells []string, header bool) {
	d.body.WriteString("<w:tr>")
	for _, cell := range cells {
		shd := ""
		bold := false
		if header {
			shd = `<w:shd w:val="clear" w:color="auto" w:fill="6B34DB"/>`
			bold = true
		}
		color := ""
		if header {
			color = "FFFFFF"
		}
		runs := d.run(cell, runProps{bold: bold, color: color})
		d.body.WriteString(`<w:tc><w:tcPr><w:tcMar/>` + shd + `</w:tcPr>` + d.para(runs, paraProps{}) + `</w:tc>`)
	}
	d.body.WriteString("</w:tr>")
}

func (d *docxBuilder) severityTable(counts map[string]int) {
	d.tableOpen()
	d.tableRow([]string{d.s.tblSeverity, d.s.tblCount}, true)
	for _, sev := range []string{"critical", "high", "medium", "low", ""} {
		label := d.s.severityDisplay(sev)
		if sev == "" {
			label = d.s.tblInfoUnclassified
		}
		d.tableRow([]string{label, strconv.Itoa(counts[sev])}, false)
	}
	total := 0
	for _, n := range counts {
		total += n
	}
	d.tableRow([]string{d.s.tblTotal, strconv.Itoa(total)}, false)
	d.tableClose()
}

// findingsSummaryTable renders the "# | Severity | Finding | Verification"
// table. Each findingView already carries its own Quality (f.Q), attached by
// sortedFindingViews, so this needs no separate quality map.
func (d *docxBuilder) findingsSummaryTable(fs []findingView) {
	d.tableOpen()
	d.tableRow([]string{d.s.tblNum, d.s.tblSeverity, d.s.tblFinding, d.s.tblVerification}, true)
	for i, f := range fs {
		d.tableRow([]string{
			strconv.Itoa(i + 1),
			d.s.severityDisplay(f.Severity),
			nz(f.Name, nz(f.VulnClass, "Uncategorized")),
			d.s.verificationDisplay(f.Q.Verification),
		}, false)
	}
	d.tableClose()
}

// sortedFindingViews parses and severity-sorts in.Findings exactly as
// Markdown() does (same sevRank, same stable sort), with each view's Quality
// already attached — the one place both renderers must agree on ordering.
func sortedFindingViews(in Input) []findingView {
	fs := make([]findingView, 0, len(in.Findings))
	for _, n := range in.Findings {
		v := parseFinding(n)
		v.Q = qualityFromRows(n.ID, in.Quality)
		fs = append(fs, v)
	}
	sort.SliceStable(fs, func(i, j int) bool { return sevRank[fs[i].Severity] < sevRank[fs[j].Severity] })
	return fs
}

func humanizeAssetType(t string) string {
	return strings.ToUpper(t[:1]) + strings.ReplaceAll(t[1:], "_", " ")
}

// truncate shortens s to at most n bytes without splitting a multi-byte rune,
// the same rune-safety rule detailedReportLimit (quality.go) applies to a
// capped report body.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	cut := s[:n]
	for len(cut) > 0 && !utf8.ValidString(cut) {
		cut = cut[:len(cut)-1]
	}
	return strings.TrimSpace(cut) + "…"
}

// --- OOXML package assembly ------------------------------------------------

func (d *docxBuilder) build(in Input) ([]byte, error) {
	buf := &bytes.Buffer{}
	zw := zip.NewWriter(buf)

	files := map[string]string{
		"[Content_Types].xml":          contentTypesXML,
		"_rels/.rels":                  rootRelsXML,
		"docProps/core.xml":            corePropsXML(in, d.s),
		"docProps/app.xml":             appPropsXML,
		"word/_rels/document.xml.rels": documentRelsXML,
		"word/styles.xml":              stylesXML,
		"word/header1.xml":             headerXML(in, d.s),
		"word/footer1.xml":             footerXML(d.s),
		"word/document.xml":            documentXML(d.body.String()),
	}
	// Deterministic order: a map above would otherwise randomize the zip's
	// entry order on every call, which is harmless for Word but makes the
	// output non-reproducible and awkward to diff/test.
	order := []string{
		"[Content_Types].xml", "_rels/.rels", "docProps/core.xml", "docProps/app.xml",
		"word/_rels/document.xml.rels", "word/styles.xml", "word/header1.xml", "word/footer1.xml", "word/document.xml",
	}
	for _, name := range order {
		fw, err := zw.Create(name)
		if err != nil {
			return nil, fmt.Errorf("docx: create %s: %w", name, err)
		}
		if _, err := fw.Write([]byte(files[name])); err != nil {
			return nil, fmt.Errorf("docx: write %s: %w", name, err)
		}
	}
	if err := zw.Close(); err != nil {
		return nil, fmt.Errorf("docx: close zip: %w", err)
	}
	return buf.Bytes(), nil
}

const contentTypesXML = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
<Default Extension="xml" ContentType="application/xml"/>
<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
<Override PartName="/word/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml"/>
<Override PartName="/word/header1.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.header+xml"/>
<Override PartName="/word/footer1.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.footer+xml"/>
<Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>
<Override PartName="/docProps/app.xml" ContentType="application/vnd.openxmlformats-officedocument.extended-properties+xml"/>
</Types>`

const rootRelsXML = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/>
<Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/extended-properties" Target="docProps/app.xml"/>
</Relationships>`

const documentRelsXML = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>
<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/header" Target="header1.xml"/>
<Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/footer" Target="footer1.xml"/>
</Relationships>`

const appPropsXML = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties">
<Application>ARTEX</Application>
</Properties>`

func corePropsXML(in Input, s reportStrings) string {
	created := in.GeneratedAt.UTC().Format(time.RFC3339)
	return `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
<dc:title>` + escXML(s.docTitlePrefix+nz(in.Title, "Unnamed task")) + `</dc:title>
<dc:creator>ARTEX</dc:creator>
<cp:lastModifiedBy>ARTEX</cp:lastModifiedBy>
<dcterms:created xsi:type="dcterms:W3CDTF">` + created + `</dcterms:created>
<dcterms:modified xsi:type="dcterms:W3CDTF">` + created + `</dcterms:modified>
</cp:coreProperties>`
}

func headerXML(in Input, s reportStrings) string {
	return `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:hdr xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
<w:p><w:pPr><w:pBdr><w:bottom w:val="single" w:sz="6" w:space="4" w:color="BFBFBF"/></w:pBdr></w:pPr>
<w:r><w:rPr><w:sz w:val="16"/><w:color w:val="808080"/></w:rPr><w:t xml:space="preserve">` +
		escXML(s.docTitlePrefix+nz(in.Title, "Unnamed task")) + `</w:t></w:r></w:p>
</w:hdr>`
}

func footerXML(s reportStrings) string {
	return `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:ftr xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
<w:p><w:pPr><w:pBdr><w:top w:val="single" w:sz="6" w:space="4" w:color="BFBFBF"/></w:pBdr><w:tabs><w:tab w:val="right" w:pos="9360"/></w:tabs></w:pPr>
<w:r><w:rPr><w:sz w:val="16"/><w:color w:val="808080"/></w:rPr><w:t xml:space="preserve">` + escXML(s.footerConfidential) + `</w:t></w:r>
<w:r><w:tab/></w:r>
<w:r><w:rPr><w:sz w:val="16"/><w:color w:val="808080"/></w:rPr><w:t xml:space="preserve">` + escXML(s.footerPagePrefix) + `</w:t></w:r>
<w:fldSimple w:instr="PAGE"><w:r><w:rPr><w:sz w:val="16"/><w:color w:val="808080"/></w:rPr><w:t>1</w:t></w:r></w:fldSimple>
<w:r><w:rPr><w:sz w:val="16"/><w:color w:val="808080"/></w:rPr><w:t xml:space="preserve">` + escXML(s.footerPageOf) + `</w:t></w:r>
<w:fldSimple w:instr="NUMPAGES"><w:r><w:rPr><w:sz w:val="16"/><w:color w:val="808080"/></w:rPr><w:t>1</w:t></w:r></w:fldSimple>
</w:p>
</w:ftr>`
}

func documentXML(body string) string {
	return `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
<w:body>` + body + `
<w:sectPr>
<w:headerReference w:type="default" r:id="rId2" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"/>
<w:footerReference w:type="default" r:id="rId3" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"/>
<w:pgSz w:w="11906" w:h="16838"/>
<w:pgMar w:top="1417" w:right="1417" w:bottom="1417" w:left="1417" w:header="709" w:footer="709"/>
</w:sectPr>
</w:body>
</w:document>`
}

const stylesXML = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:styles xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
<w:docDefaults>
<w:rPrDefault><w:rPr><w:rFonts w:ascii="Calibri" w:hAnsi="Calibri" w:cs="Calibri"/><w:sz w:val="22"/><w:lang w:val="en-US"/></w:rPr></w:rPrDefault>
</w:docDefaults>
<w:style w:type="paragraph" w:default="1" w:styleId="Normal"><w:name w:val="Normal"/></w:style>
</w:styles>`
