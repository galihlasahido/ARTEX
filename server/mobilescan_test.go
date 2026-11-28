package server

import (
	"bytes"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"path/filepath"
	"testing"
)

// newScan builds a multipart POST to /api/mobile/scan and returns the recorder
// plus request. An empty filename omits the file part entirely.
func newScan(filename string, body []byte) (*httptest.ResponseRecorder, *http.Request) {
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	if filename != "" {
		fw, _ := mw.CreateFormFile("file", filename)
		_, _ = fw.Write(body)
	}
	_ = mw.Close()
	req := httptest.NewRequest("POST", "/api/mobile/scan", &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	return httptest.NewRecorder(), req
}

// TestMobileScanEndpoint drives the handler directly (no auth layer): a valid
// upload runs apkscan.py and returns a JSON report even when the external tools
// are absent (the engine degrades to an empty report), proving the upload → run
// → report plumbing. Real findings are covered by the in-image end-to-end run.
func TestMobileScanEndpoint(t *testing.T) {
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 not available")
	}
	skills, err := filepath.Abs("../skills")
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{m: &Manager{dir: t.TempDir()}, skillDir: skills}

	rec, req := newScan("sample.apk", []byte("PK\x03\x04 not a real apk, tools degrade"))
	s.mobileScan(rec, req)
	if rec.Code != 200 {
		t.Fatalf("scan = %d %s", rec.Code, rec.Body.String())
	}
	var report struct {
		Summary map[string]any `json:"summary"`
		Meta    struct {
			Tools map[string]bool `json:"tools"`
		} `json:"meta"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &report); err != nil {
		t.Fatalf("report not JSON: %v (%s)", err, rec.Body.String())
	}
	if report.Summary == nil || report.Meta.Tools == nil {
		t.Fatalf("report missing summary/meta.tools: %s", rec.Body.String())
	}

	rec, req = newScan("", nil) // no file part
	s.mobileScan(rec, req)
	if rec.Code != 400 {
		t.Fatalf("no file = %d, want 400", rec.Code)
	}

	rec, req = newScan("notes.txt", []byte("x")) // wrong extension
	s.mobileScan(rec, req)
	if rec.Code != 400 {
		t.Fatalf("non-apk = %d, want 400", rec.Code)
	}
}
