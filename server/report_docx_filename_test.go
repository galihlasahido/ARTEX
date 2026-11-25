package server

import (
	"strings"
	"testing"
	"time"
)

func TestSlugifyFilenameSegment(t *testing.T) {
	cases := []struct{ in, want string }{
		{"Red Team: Subdomain Sweep & Pivot", "Red-Team-Subdomain-Sweep-Pivot"},
		{"  leading/trailing spaces  ", "leading-trailing-spaces"},
		{"", ""},
		{"---", ""},
		{`quote"path/../traversal`, "quote-path-traversal"},
		{"already-has-dashes", "already-has-dashes"},
		{"unicode — em dash and emoji 🚀", "unicode-em-dash-and-emoji"},
	}
	for _, c := range cases {
		if got := slugifyFilenameSegment(c.in); got != c.want {
			t.Errorf("slugifyFilenameSegment(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestReportDocxFilename(t *testing.T) {
	when := time.Date(2026, 3, 7, 12, 0, 0, 0, time.UTC)

	if got, want := reportDocxFilename("", "42", when, "en"), "ARTEX-pentest-report-task42-20260307-en.docx"; got != want {
		t.Errorf("empty name: got %q, want %q", got, want)
	}

	if got, want := reportDocxFilename("Full-Scope CVE-Aware Autonomous Pentest", "1", when, "id"),
		"ARTEX-Full-Scope-CVE-Aware-Autonomous-Pentest-task1-20260307-id.docx"; got != want {
		t.Errorf("normal name: got %q, want %q", got, want)
	}

	// A name long enough to exceed the 40-char cap must still produce a
	// well-formed filename: no trailing dash left by a cut mid-separator, and
	// the task id/date/lang suffix must survive intact.
	long := strings.Repeat("Very Long Finding Class ", 5)
	got := reportDocxFilename(long, "7", when, "en")
	if !strings.HasSuffix(got, "-task7-20260307-en.docx") {
		t.Fatalf("long name: suffix missing or mangled: %q", got)
	}
	if strings.Contains(got, "--") {
		t.Errorf("long name: filename has a double dash from the cap: %q", got)
	}
	if strings.HasSuffix(strings.TrimSuffix(got, "-task7-20260307-en.docx"), "-") {
		t.Errorf("long name: slug retains a trailing dash before the suffix: %q", got)
	}

	// Path-separator and quote characters in a task's own name must never
	// reach the Content-Disposition header unescaped.
	if got := reportDocxFilename(`../../etc/passwd" malicious`, "9", when, "id"); strings.ContainsAny(got, `"/\`) {
		t.Errorf("unsafe characters survived into the filename: %q", got)
	}
}

func TestReportLang(t *testing.T) {
	cases := []struct{ in, want string }{
		{"", "en"},
		{"en", "en"},
		{"id", "id"},
		{"ID", "id"},
		{" Indonesian ", "id"},
		{"fr", "en"}, // unsupported falls back to English
		{"garbage", "en"},
	}
	for _, c := range cases {
		if got := reportLang(c.in); got != c.want {
			t.Errorf("reportLang(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
