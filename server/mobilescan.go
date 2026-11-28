package server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/Autumn-27/artex/agent"
)

// Direct static APK scan for the UI: upload an .apk, run the mobile-apk static
// engine (skills/mobile-apk/scripts/apkscan.py) and return its JSON report. This
// is the operator-facing counterpart to the agent-driven skill flow — no task,
// no agent, just upload → scan → results.
//
// The APK is untrusted input: it is only unpacked and read, and the scan runs as
// the executor identity (not the server) when isolation is enabled, in an
// ephemeral session dir that is removed afterwards. The app itself is never run.

const (
	maxAPKUpload   = 512 << 20 // 512 MiB, matches the chat upload cap
	apkScanTimeout = 6 * time.Minute
)

func (s *Server) mobileScan(w http.ResponseWriter, r *http.Request) {
	if s.m == nil || s.m.dir == "" {
		writeErr(w, 503, "workspace unavailable")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxAPKUpload+(1<<20))
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		var sizeErr *http.MaxBytesError
		if errors.As(err, &sizeErr) {
			writeErr(w, http.StatusRequestEntityTooLarge, "APK exceeds the 512 MiB limit")
			return
		}
		writeErr(w, 400, "failed to parse the upload: "+err.Error())
		return
	}
	defer r.MultipartForm.RemoveAll()

	files := r.MultipartForm.File["file"]
	if len(files) != 1 {
		writeErr(w, 400, "attach exactly one .apk file in the form field 'file'")
		return
	}
	hdr := files[0]
	if !strings.HasSuffix(strings.ToLower(filepath.Base(hdr.Filename)), ".apk") {
		writeErr(w, 400, "the file must be an .apk")
		return
	}
	if hdr.Size > maxAPKUpload {
		writeErr(w, http.StatusRequestEntityTooLarge, "APK exceeds the 512 MiB limit")
		return
	}

	// Ephemeral, executor-writable workspace (same machinery as chat sessions).
	idb := make([]byte, 8)
	if _, err := rand.Read(idb); err != nil {
		writeErr(w, 500, "scan id generation failed")
		return
	}
	base := agent.EnsureSessionDir(s.m.dir, "apkscan-"+hex.EncodeToString(idb))
	defer os.RemoveAll(base)

	apkPath := filepath.Join(base, "app.apk")
	if err := saveUploadedFile(hdr, apkPath); err != nil {
		writeErr(w, 500, "failed to store the APK: "+err.Error())
		return
	}
	workDir := filepath.Join(base, "work")
	if err := os.MkdirAll(workDir, 0o777); err != nil {
		writeErr(w, 500, "failed to prepare work dir: "+err.Error())
		return
	}
	outPath := filepath.Join(base, "report.json")

	script := filepath.Join(s.skillDir, "mobile-apk", "scripts", "apkscan.py")
	ctx, cancel := context.WithTimeout(r.Context(), apkScanTimeout)
	defer cancel()
	c := exec.CommandContext(ctx, "python3", script, "--apk", apkPath, "--out", outPath, "--work", workDir)
	c.Dir = base
	c.Env = agentProcessEnv(s.execPriv)
	applyExecCredential(c, s.execPriv)
	combined, runErr := c.CombinedOutput()

	data, err := os.ReadFile(outPath)
	if err != nil || !json.Valid(data) {
		msg := "the scan produced no report"
		if runErr != nil {
			msg += " (" + runErr.Error() + ")"
		}
		if tail := lastLines(string(combined), 8); tail != "" {
			msg += ": " + tail
		}
		writeErr(w, 500, msg)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)
	_, _ = w.Write(data)
}

func saveUploadedFile(hdr *multipart.FileHeader, dest string) error {
	src, err := hdr.Open()
	if err != nil {
		return err
	}
	defer src.Close()
	f, err := os.OpenFile(dest, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = io.Copy(f, src)
	return err
}

// lastLines returns the last n non-empty lines of s, joined with "; ".
func lastLines(s string, n int) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	out := make([]string, 0, n)
	for i := len(lines) - 1; i >= 0 && len(out) < n; i-- {
		if t := strings.TrimSpace(lines[i]); t != "" {
			out = append([]string{t}, out...)
		}
	}
	return strings.Join(out, "; ")
}
