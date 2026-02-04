package main

import (
	"archive/zip"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/argon2"
)

const (
	defaultRemoteFilename = "nekobox_sync.bin"

	headerMagic   = "NEKOSYNC"
	headerVersion = uint16(1)

	saltLen  = 16
	nonceLen = 12
	keyLen   = 32

	// Argon2id params (fixed for now; stored in header for future proofing).
	argonTime    = uint32(1)
	argonMemory  = uint32(64 * 1024) // KiB
	argonThreads = uint8(1)
)

type Request struct {
	Action    string       `json:"action"`
	ConfigDir string       `json:"config_dir"`
	WebDAV    WebDAVConfig `json:"webdav"`
	Crypto    CryptoConfig `json:"crypto"`
	State     SyncState    `json:"state"`
	Options   Options      `json:"options"`
}

type WebDAVConfig struct {
	URL      string `json:"url"`
	Username string `json:"username"`
	Password string `json:"password"`
}

type CryptoConfig struct {
	Password string `json:"password"`
}

type SyncState struct {
	LastLocalHash  string `json:"last_local_hash"`
	LastRemoteETag string `json:"last_remote_etag"`
}

type Options struct {
	RemoteFilename string `json:"remote_filename"`
	TimeoutSec     int    `json:"timeout_sec"`
	Force          bool   `json:"force"`
	Mode           string `json:"mode"` // pull: "apply"(default) | "backup"
	UserAgent      string `json:"user_agent"`
	DisableProxy   bool   `json:"disable_proxy"`
}

type Response struct {
	Ok           bool   `json:"ok"`
	Action       string `json:"action"`
	Message      string `json:"message,omitempty"`
	Error        string `json:"error,omitempty"`
	Conflict     bool   `json:"conflict,omitempty"`
	LocalHash    string `json:"local_hash,omitempty"`
	RemoteETag   string `json:"remote_etag,omitempty"`
	RemoteExists bool   `json:"remote_exists,omitempty"`
	ChangedLocal bool   `json:"changed_local,omitempty"`
	ChangedRemote bool  `json:"changed_remote,omitempty"`
	StatusCode   int    `json:"status_code,omitempty"`
	BackupDir    string `json:"backup_dir,omitempty"`
	Time         int64  `json:"time,omitempty"`
}

type fileEntry struct {
	RelPath string
	Data    []byte
}

func main() {
	reqBytes, err := io.ReadAll(os.Stdin)
	if err != nil {
		writeAndExit(Response{Ok: false, Action: "unknown", Error: err.Error()}, 1)
	}
	reqBytes = bytes.TrimSpace(reqBytes)
	if len(reqBytes) == 0 {
		msg := "expected JSON request on stdin"
		_, _ = fmt.Fprintln(os.Stderr, msg)
		writeAndExit(Response{Ok: false, Action: "unknown", Error: msg}, 1)
	}

	var req Request
	if err := json.Unmarshal(reqBytes, &req); err != nil {
		writeAndExit(Response{Ok: false, Action: "unknown", Error: "invalid json: " + err.Error()}, 1)
	}

	if strings.TrimSpace(req.ConfigDir) == "" {
		req.ConfigDir = "."
	}
	req.Action = strings.ToLower(strings.TrimSpace(req.Action))

	if req.Options.RemoteFilename == "" {
		req.Options.RemoteFilename = defaultRemoteFilename
	}
	if req.Options.TimeoutSec <= 0 {
		req.Options.TimeoutSec = 20
	}
	if req.Options.UserAgent == "" {
		req.Options.UserAgent = "NekoBoxSync/1"
	}
	if req.Options.Mode == "" {
		req.Options.Mode = "apply"
	}
	req.Options.Mode = strings.ToLower(strings.TrimSpace(req.Options.Mode))

	var resp Response
	var exitCode int
	switch req.Action {
	case "status":
		resp, exitCode = doStatus(req)
	case "test":
		resp, exitCode = doTest(req)
	case "push":
		resp, exitCode = doPush(req)
	case "pull":
		resp, exitCode = doPull(req)
	default:
		resp = Response{Ok: false, Action: req.Action, Error: "unknown action"}
		exitCode = 1
	}
	writeAndExit(resp, exitCode)
}

func writeAndExit(resp Response, code int) {
	b, _ := json.Marshal(resp)
	_, _ = os.Stdout.Write(append(b, '\n'))
	os.Exit(code)
}

func doStatus(req Request) (Response, int) {
	resp := Response{Ok: true, Action: req.Action, Time: time.Now().Unix()}

	entries, err := collectSnapshot(req.ConfigDir)
	if err != nil {
		resp.Ok = false
		resp.Error = err.Error()
		return resp, 1
	}
	localHash := snapshotHash(entries)
	resp.LocalHash = localHash

	remoteURL, err := remoteFileURL(req.WebDAV.URL, req.Options.RemoteFilename)
	if err != nil {
		resp.Ok = false
		resp.Error = err.Error()
		return resp, 1
	}

	client := newHTTPClient(time.Duration(req.Options.TimeoutSec)*time.Second, req.Options.DisableProxy)
	exists, etag, status, err := headETag(client, remoteURL, req.WebDAV, req.Options.UserAgent)
	if err != nil {
		resp.Ok = false
		resp.Error = err.Error()
		resp.StatusCode = status
		return resp, 1
	}
	resp.RemoteExists = exists
	resp.RemoteETag = etag
	resp.StatusCode = status

	resp.ChangedLocal = (req.State.LastLocalHash != "" && localHash != req.State.LastLocalHash)
	if exists {
		resp.ChangedRemote = (req.State.LastRemoteETag != "" && etag != req.State.LastRemoteETag)
	} else {
		resp.ChangedRemote = (req.State.LastRemoteETag != "")
	}
	return resp, 0
}

func doTest(req Request) (Response, int) {
	resp := Response{Ok: true, Action: req.Action, Time: time.Now().Unix()}
	remoteURL, err := remoteFileURL(req.WebDAV.URL, req.Options.RemoteFilename)
	if err != nil {
		resp.Ok = false
		resp.Error = err.Error()
		return resp, 1
	}
	client := newHTTPClient(time.Duration(req.Options.TimeoutSec)*time.Second, req.Options.DisableProxy)
	exists, etag, status, err := headETag(client, remoteURL, req.WebDAV, req.Options.UserAgent)
	if err != nil {
		resp.Ok = false
		resp.Error = err.Error()
		resp.StatusCode = status
		return resp, 1
	}
	resp.RemoteExists = exists
	resp.RemoteETag = etag
	resp.StatusCode = status
	if exists {
		resp.Message = "ok (remote file exists)"
	} else {
		resp.Message = "ok (remote file not found yet)"
	}
	return resp, 0
}

func doPush(req Request) (Response, int) {
	resp := Response{Ok: false, Action: req.Action, Time: time.Now().Unix()}
	if strings.TrimSpace(req.WebDAV.URL) == "" {
		resp.Error = "webdav.url is empty"
		return resp, 1
	}
	if strings.TrimSpace(req.WebDAV.Username) == "" {
		resp.Error = "webdav.username is empty"
		return resp, 1
	}
	if strings.TrimSpace(req.WebDAV.Password) == "" {
		resp.Error = "webdav.password is empty"
		return resp, 1
	}
	if strings.TrimSpace(req.Crypto.Password) == "" {
		resp.Error = "crypto.password is empty"
		return resp, 1
	}

	entries, err := collectSnapshot(req.ConfigDir)
	if err != nil {
		resp.Error = err.Error()
		return resp, 1
	}
	localHash := snapshotHash(entries)
	resp.LocalHash = localHash

	remoteURL, err := remoteFileURL(req.WebDAV.URL, req.Options.RemoteFilename)
	if err != nil {
		resp.Error = err.Error()
		return resp, 1
	}

	client := newHTTPClient(time.Duration(req.Options.TimeoutSec)*time.Second, req.Options.DisableProxy)
	remoteExists, remoteETag, status, err := headETag(client, remoteURL, req.WebDAV, req.Options.UserAgent)
	if err != nil {
		resp.Error = err.Error()
		resp.StatusCode = status
		return resp, 1
	}
	resp.RemoteExists = remoteExists
	resp.RemoteETag = remoteETag
	resp.StatusCode = status

	// No-op when local snapshot equals last recorded snapshot and we have no remote divergence.
	if !req.Options.Force && req.State.LastLocalHash != "" && localHash == req.State.LastLocalHash {
		if req.State.LastRemoteETag != "" && remoteExists && remoteETag == req.State.LastRemoteETag {
			resp.Ok = true
			resp.Message = "no changes"
			return resp, 0
		}
	}

	conflict, changedLocal, changedRemote, reason := conflictForPush(req, localHash, remoteExists, remoteETag)
	resp.ChangedLocal = changedLocal
	resp.ChangedRemote = changedRemote
	if conflict && !req.Options.Force {
		resp.Conflict = true
		resp.Ok = false
		resp.Message = reason
		return resp, 2
	}

	zipBytes, err := buildZip(entries)
	if err != nil {
		resp.Error = err.Error()
		return resp, 1
	}
	encBytes, err := encryptBlob(zipBytes, req.Crypto.Password)
	if err != nil {
		resp.Error = err.Error()
		return resp, 1
	}

	putStatus, putETag, err := putFile(client, remoteURL, req.WebDAV, req.Options.UserAgent, encBytes, req.Options.Force, remoteExists, req.State.LastRemoteETag)
	resp.StatusCode = putStatus
	if err != nil {
		// Precondition failed -> treat as conflict.
		if putStatus == http.StatusPreconditionFailed {
			resp.Conflict = true
			resp.Message = "remote changed (precondition failed)"
			return resp, 2
		}
		resp.Error = err.Error()
		return resp, 1
	}

	// Prefer ETag from PUT response, otherwise re-HEAD.
	if putETag == "" {
		_, etag2, status2, err2 := headETag(client, remoteURL, req.WebDAV, req.Options.UserAgent)
		if err2 == nil {
			putETag = etag2
			resp.StatusCode = status2
		}
	}

	resp.Ok = true
	resp.RemoteExists = true
	resp.RemoteETag = putETag
	resp.Message = "uploaded"
	return resp, 0
}

func doPull(req Request) (Response, int) {
	resp := Response{Ok: false, Action: req.Action, Time: time.Now().Unix()}
	if strings.TrimSpace(req.WebDAV.URL) == "" {
		resp.Error = "webdav.url is empty"
		return resp, 1
	}
	if strings.TrimSpace(req.WebDAV.Username) == "" {
		resp.Error = "webdav.username is empty"
		return resp, 1
	}
	if strings.TrimSpace(req.WebDAV.Password) == "" {
		resp.Error = "webdav.password is empty"
		return resp, 1
	}
	if strings.TrimSpace(req.Crypto.Password) == "" {
		resp.Error = "crypto.password is empty"
		return resp, 1
	}

	remoteURL, err := remoteFileURL(req.WebDAV.URL, req.Options.RemoteFilename)
	if err != nil {
		resp.Error = err.Error()
		return resp, 1
	}
	client := newHTTPClient(time.Duration(req.Options.TimeoutSec)*time.Second, req.Options.DisableProxy)

	remoteExists, remoteETag, status, err := headETag(client, remoteURL, req.WebDAV, req.Options.UserAgent)
	if err != nil {
		resp.Error = err.Error()
		resp.StatusCode = status
		return resp, 1
	}
	if !remoteExists {
		resp.Error = "remote file not found"
		resp.StatusCode = status
		resp.RemoteExists = false
		return resp, 1
	}
	resp.RemoteExists = true
	resp.RemoteETag = remoteETag
	resp.StatusCode = status

	// Conflict guard: if local changed since last sync, require force (unless user explicitly pulls a backup).
	entries, err := collectSnapshot(req.ConfigDir)
	if err != nil {
		resp.Error = err.Error()
		return resp, 1
	}
	localHashCurrent := snapshotHash(entries)
	resp.LocalHash = localHashCurrent
	localChanged := req.State.LastLocalHash != "" && localHashCurrent != req.State.LastLocalHash
	remoteChanged := req.State.LastRemoteETag != "" && remoteETag != req.State.LastRemoteETag
	resp.ChangedLocal = localChanged
	resp.ChangedRemote = remoteChanged
	if req.Options.Mode != "backup" && localChanged && !req.Options.Force {
		resp.Conflict = true
		resp.Message = "local changed since last sync"
		return resp, 2
	}

	blob, getStatus, err := getFile(client, remoteURL, req.WebDAV, req.Options.UserAgent)
	resp.StatusCode = getStatus
	if err != nil {
		resp.Error = err.Error()
		return resp, 1
	}
	plainZip, err := decryptBlob(blob, req.Crypto.Password)
	if err != nil {
		resp.Error = err.Error()
		return resp, 1
	}
	files, err := unzipSnapshot(plainZip)
	if err != nil {
		resp.Error = err.Error()
		return resp, 1
	}

	backupDir, appliedHash, err := applySnapshot(req.ConfigDir, files, req.Options.Mode)
	if err != nil {
		resp.Error = err.Error()
		return resp, 1
	}
	resp.BackupDir = backupDir
	if req.Options.Mode != "backup" {
		resp.LocalHash = appliedHash
	}
	resp.Ok = true
	if req.Options.Mode == "backup" {
		resp.Message = "downloaded to backup"
	} else {
		resp.Message = "downloaded and applied"
	}
	return resp, 0
}

func newHTTPClient(timeout time.Duration, disableProxy bool) *http.Client {
	tr := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
	}
	if disableProxy {
		tr.Proxy = nil
	}
	return &http.Client{Timeout: timeout, Transport: tr}
}

func remoteFileURL(baseURL string, filename string) (string, error) {
	baseURL = strings.TrimSpace(baseURL)
	if baseURL == "" {
		return "", errors.New("webdav.url is empty")
	}
	u, err := url.Parse(baseURL)
	if err != nil {
		return "", fmt.Errorf("invalid webdav.url: %w", err)
	}
	// If user ends with '/', treat it as directory.
	// Also, many users paste a directory URL without trailing '/'; be tolerant and append a default filename.
	lastSeg := path.Base(u.Path)
	if strings.HasSuffix(baseURL, "/") || (!strings.Contains(lastSeg, ".") && lastSeg != "/" && lastSeg != ".") {
		u.Path = path.Join(u.Path, filename)
	}
	return u.String(), nil
}

func headETag(client *http.Client, remoteURL string, cfg WebDAVConfig, userAgent string) (exists bool, etag string, status int, err error) {
	// First try HEAD.
	req, err := http.NewRequest(http.MethodHead, remoteURL, nil)
	if err != nil {
		return false, "", 0, err
	}
	req.SetBasicAuth(cfg.Username, cfg.Password)
	req.Header.Set("User-Agent", userAgent)
	rsp, err := client.Do(req)
	if err != nil {
		return false, "", 0, err
	}
	defer rsp.Body.Close()
	status = rsp.StatusCode
	switch status {
	case http.StatusOK:
		return true, rsp.Header.Get("ETag"), status, nil
	case http.StatusNotFound:
		return false, "", status, nil
	case http.StatusUnauthorized, http.StatusForbidden:
		return false, "", status, fmt.Errorf("auth failed: %s", rsp.Status)
	case http.StatusMethodNotAllowed, http.StatusNotImplemented:
		// fallthrough to range GET.
	default:
		// Some WebDAV returns 301/302 or other. Treat as error for now.
	}

	// Range GET fallback (for servers that don't support HEAD).
	req2, err := http.NewRequest(http.MethodGet, remoteURL, nil)
	if err != nil {
		return false, "", status, err
	}
	req2.SetBasicAuth(cfg.Username, cfg.Password)
	req2.Header.Set("User-Agent", userAgent)
	req2.Header.Set("Range", "bytes=0-0")
	rsp2, err := client.Do(req2)
	if err != nil {
		return false, "", status, err
	}
	defer rsp2.Body.Close()
	status = rsp2.StatusCode
	switch status {
	case http.StatusOK, http.StatusPartialContent:
		return true, rsp2.Header.Get("ETag"), status, nil
	case http.StatusNotFound:
		return false, "", status, nil
	case http.StatusUnauthorized, http.StatusForbidden:
		return false, "", status, fmt.Errorf("auth failed: %s", rsp2.Status)
	default:
		return false, "", status, fmt.Errorf("unexpected status: %s", rsp2.Status)
	}
}

func putFile(client *http.Client, remoteURL string, cfg WebDAVConfig, userAgent string, data []byte, force bool, remoteExists bool, lastRemoteETag string) (status int, etag string, err error) {
	req, err := http.NewRequest(http.MethodPut, remoteURL, bytes.NewReader(data))
	if err != nil {
		return 0, "", err
	}
	req.SetBasicAuth(cfg.Username, cfg.Password)
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Content-Type", "application/octet-stream")

	// Precondition to avoid blind overwrite.
	if !force {
		if remoteExists && strings.TrimSpace(lastRemoteETag) != "" {
			req.Header.Set("If-Match", lastRemoteETag)
		}
		if !remoteExists {
			req.Header.Set("If-None-Match", "*")
		}
	}

	rsp, err := client.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer rsp.Body.Close()
	status = rsp.StatusCode
	etag = rsp.Header.Get("ETag")

	switch status {
	case http.StatusOK, http.StatusCreated, http.StatusNoContent:
		_, _ = io.Copy(io.Discard, rsp.Body)
		return status, etag, nil
	case http.StatusPreconditionFailed:
		_, _ = io.Copy(io.Discard, rsp.Body)
		return status, etag, fmt.Errorf("precondition failed: %s", rsp.Status)
	case http.StatusUnauthorized, http.StatusForbidden:
		b, _ := io.ReadAll(rsp.Body)
		return status, etag, fmt.Errorf("auth failed: %s (%s)", rsp.Status, strings.TrimSpace(string(b)))
	default:
		b, _ := io.ReadAll(rsp.Body)
		return status, etag, fmt.Errorf("upload failed: %s (%s)", rsp.Status, strings.TrimSpace(string(b)))
	}
}

func getFile(client *http.Client, remoteURL string, cfg WebDAVConfig, userAgent string) ([]byte, int, error) {
	req, err := http.NewRequest(http.MethodGet, remoteURL, nil)
	if err != nil {
		return nil, 0, err
	}
	req.SetBasicAuth(cfg.Username, cfg.Password)
	req.Header.Set("User-Agent", userAgent)
	rsp, err := client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer rsp.Body.Close()
	status := rsp.StatusCode
	switch status {
	case http.StatusOK:
		b, err := io.ReadAll(rsp.Body)
		return b, status, err
	case http.StatusUnauthorized, http.StatusForbidden:
		b, _ := io.ReadAll(rsp.Body)
		return nil, status, fmt.Errorf("auth failed: %s (%s)", rsp.Status, strings.TrimSpace(string(b)))
	default:
		b, _ := io.ReadAll(rsp.Body)
		return nil, status, fmt.Errorf("download failed: %s (%s)", rsp.Status, strings.TrimSpace(string(b)))
	}
}

func collectSnapshot(configDir string) ([]fileEntry, error) {
	var out []fileEntry

	addDirFiles := func(relDir string, accept func(name string) bool) error {
		absDir := filepath.Join(configDir, relDir)
		entries, err := os.ReadDir(absDir)
		if err != nil {
			// missing directory is ok
			if os.IsNotExist(err) {
				return nil
			}
			return err
		}
		for _, de := range entries {
			if de.IsDir() {
				continue
			}
			name := de.Name()
			if !accept(name) {
				continue
			}
			abs := filepath.Join(absDir, name)
			b, err := os.ReadFile(abs)
			if err != nil {
				return err
			}
			out = append(out, fileEntry{RelPath: filepath.ToSlash(filepath.Join(relDir, name)), Data: b})
		}
		return nil
	}

	// profiles/*.json
	if err := addDirFiles("profiles", func(name string) bool {
		return strings.HasSuffix(strings.ToLower(name), ".json")
	}); err != nil {
		return nil, err
	}

	// groups/pm.json and groups/<number>.json
	if err := addDirFiles("groups", func(name string) bool {
		l := strings.ToLower(name)
		if l == "pm.json" {
			return true
		}
		if l == "nekobox.json" {
			return false
		}
		if !strings.HasSuffix(l, ".json") {
			return false
		}
		base := strings.TrimSuffix(l, ".json")
		_, err := strconv.Atoi(base)
		return err == nil
	}); err != nil {
		return nil, err
	}

	// routes_box/*
	if err := addDirFiles("routes_box", func(name string) bool {
		// keep everything (json/preset/etc), but only files.
		return true
	}); err != nil {
		return nil, err
	}

	sort.Slice(out, func(i, j int) bool { return out[i].RelPath < out[j].RelPath })
	return out, nil
}

func snapshotHash(entries []fileEntry) string {
	h := sha256.New()
	for _, e := range entries {
			sum := sha256.Sum256(e.Data)
			_, _ = h.Write([]byte(e.RelPath))
			_, _ = h.Write([]byte{0})
			_, _ = h.Write(sum[:])
		}
		return hex.EncodeToString(h.Sum(nil))
	}

func buildZip(entries []fileEntry) ([]byte, error) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, e := range entries {
		h := &zip.FileHeader{
			Name:   e.RelPath,
			Method: zip.Deflate,
		}
		h.Modified = time.Unix(0, 0)
		h.SetMode(0644)
		w, err := zw.CreateHeader(h)
		if err != nil {
			_ = zw.Close()
			return nil, err
		}
		if _, err := w.Write(e.Data); err != nil {
			_ = zw.Close()
			return nil, err
		}
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func unzipSnapshot(zipBytes []byte) (map[string][]byte, error) {
	r, err := zip.NewReader(bytes.NewReader(zipBytes), int64(len(zipBytes)))
	if err != nil {
		return nil, err
	}
	out := make(map[string][]byte)
	for _, f := range r.File {
		name := filepath.ToSlash(f.Name)
		name = strings.TrimPrefix(name, "/")
		name = strings.TrimPrefix(name, "./")
		clean := path.Clean(name)
		if clean == "." || clean == "" || strings.HasPrefix(clean, "../") || strings.Contains(clean, "/../") {
			return nil, fmt.Errorf("invalid path in archive: %q", f.Name)
		}
		if !allowedRelPath(clean) {
			// Ignore unknown paths to avoid overwriting non-sync configs.
			continue
		}
		if f.FileInfo().IsDir() {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return nil, err
		}
		b, err := io.ReadAll(rc)
		_ = rc.Close()
		if err != nil {
			return nil, err
		}
		out[clean] = b
	}
	return out, nil
}

func allowedRelPath(rel string) bool {
	rel = filepath.ToSlash(rel)
	if strings.HasPrefix(rel, "profiles/") && strings.HasSuffix(strings.ToLower(rel), ".json") {
		return true
	}
	if rel == "groups/pm.json" {
		return true
	}
	if strings.HasPrefix(rel, "groups/") && strings.HasSuffix(strings.ToLower(rel), ".json") {
		base := strings.TrimSuffix(strings.TrimPrefix(rel, "groups/"), ".json")
		_, err := strconv.Atoi(base)
		return err == nil
	}
	if strings.HasPrefix(rel, "routes_box/") {
		// accept all files under routes_box/
		if strings.Contains(rel[len("routes_box/"):], "/") {
			return false // no nested dirs
		}
		return true
	}
	return false
}

func conflictForPush(req Request, localHash string, remoteExists bool, remoteETag string) (conflict bool, changedLocal bool, changedRemote bool, reason string) {
	lastLocalKnown := strings.TrimSpace(req.State.LastLocalHash) != ""
	lastRemoteKnown := strings.TrimSpace(req.State.LastRemoteETag) != ""

	changedLocal = lastLocalKnown && localHash != req.State.LastLocalHash
	changedRemote = false
	if remoteExists {
		changedRemote = lastRemoteKnown && remoteETag != req.State.LastRemoteETag
	} else {
		changedRemote = lastRemoteKnown
	}

	// First sync is ok only when remote does not exist and we have no recorded states.
	if !lastLocalKnown && !lastRemoteKnown && !remoteExists {
		return false, true, false, ""
	}

	if remoteExists && !lastRemoteKnown {
		return true, changedLocal || !lastLocalKnown, true, "remote exists but last_remote_etag is empty"
	}
	if !remoteExists && lastRemoteKnown {
		return true, changedLocal || !lastLocalKnown, true, "remote deleted or moved"
	}
	if remoteExists && lastRemoteKnown && remoteETag != req.State.LastRemoteETag {
		return true, changedLocal || !lastLocalKnown, true, "remote changed"
	}

	// If we don't know local state, require manual decision unless remote is empty (handled above).
	if !lastLocalKnown {
		return true, true, changedRemote, "local state unknown (no last_local_hash)"
	}

	return false, changedLocal, changedRemote, ""
}

func encryptBlob(plain []byte, password string) ([]byte, error) {
	salt := make([]byte, saltLen)
	nonce := make([]byte, nonceLen)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	key := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, keyLen)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	hdr, err := encodeHeader(salt, nonce)
	if err != nil {
		return nil, err
	}
	ciphertext := aead.Seal(nil, nonce, plain, hdr)
	return append(hdr, ciphertext...), nil
}

func decryptBlob(blob []byte, password string) ([]byte, error) {
	hdrLen := headerLen()
	if len(blob) < hdrLen {
		return nil, errors.New("invalid blob: too small")
	}
	hdr := blob[:hdrLen]
	salt, nonce, err := decodeHeader(hdr)
	if err != nil {
		return nil, err
	}
	key := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, keyLen)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	plain, err := aead.Open(nil, nonce, blob[hdrLen:], hdr)
	if err != nil {
		return nil, errors.New("decrypt failed (wrong password or corrupted data)")
	}
	return plain, nil
}

func headerLen() int {
	// magic(8) + ver(2) + salt(16) + nonce(12) + argonTime(4) + argonMemory(4) + argonThreads(1)
	return 8 + 2 + saltLen + nonceLen + 4 + 4 + 1
}

func encodeHeader(salt, nonce []byte) ([]byte, error) {
	if len(salt) != saltLen || len(nonce) != nonceLen {
		return nil, errors.New("invalid salt/nonce length")
	}
	h := make([]byte, 0, headerLen())
	h = append(h, []byte(headerMagic)...)
	var tmp [2]byte
	binary.BigEndian.PutUint16(tmp[:], headerVersion)
	h = append(h, tmp[:]...)
	h = append(h, salt...)
	h = append(h, nonce...)
	var u32 [4]byte
	binary.BigEndian.PutUint32(u32[:], argonTime)
	h = append(h, u32[:]...)
	binary.BigEndian.PutUint32(u32[:], argonMemory)
	h = append(h, u32[:]...)
	h = append(h, argonThreads)
	return h, nil
}

func decodeHeader(hdr []byte) (salt []byte, nonce []byte, err error) {
	if len(hdr) < headerLen() {
		return nil, nil, errors.New("invalid header length")
	}
	if string(hdr[:8]) != headerMagic {
		return nil, nil, errors.New("invalid magic")
	}
	ver := binary.BigEndian.Uint16(hdr[8:10])
	if ver != headerVersion {
		return nil, nil, fmt.Errorf("unsupported version: %d", ver)
	}
	off := 10
	salt = append([]byte(nil), hdr[off:off+saltLen]...)
	off += saltLen
	nonce = append([]byte(nil), hdr[off:off+nonceLen]...)
	off += nonceLen

	// Read (and verify) KDF params, but ignore for now (fixed values).
	t := binary.BigEndian.Uint32(hdr[off : off+4])
	off += 4
	m := binary.BigEndian.Uint32(hdr[off : off+4])
	off += 4
	p := hdr[off]
	if t != argonTime || m != argonMemory || p != argonThreads {
		return nil, nil, fmt.Errorf("kdf params mismatch (tool updated?): time=%d mem=%d threads=%d", t, m, p)
	}

	return salt, nonce, nil
}

func applySnapshot(configDir string, files map[string][]byte, mode string) (backupDir string, newHash string, err error) {
	ts := time.Now().Format("20060102-150405")
	backupDir = filepath.Join(configDir, "sync_backups", ts)
	if err := os.MkdirAll(backupDir, 0755); err != nil {
		return "", "", err
	}

	// Always keep a local backup of current synced files.
	localBefore := filepath.Join(backupDir, "local_before")
	if err := backupCurrent(configDir, localBefore); err != nil {
		return "", "", err
	}

	if mode == "backup" {
		dst := filepath.Join(backupDir, "remote_snapshot")
		if err := writeSnapshotFiles(dst, files); err != nil {
			return backupDir, "", err
		}
		return backupDir, snapshotHashFromMap(files), nil
	}

	// Apply: delete current synced files, then write new snapshot.
	if err := clearCurrentSynced(configDir); err != nil {
		return backupDir, "", err
	}
	if err := writeSnapshotFiles(configDir, files); err != nil {
		return backupDir, "", err
	}
	return backupDir, snapshotHashFromMap(files), nil
}

func backupCurrent(configDir, dstRoot string) error {
	entries, err := collectSnapshot(configDir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		dst := filepath.Join(dstRoot, filepath.FromSlash(e.RelPath))
		if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
			return err
		}
		if err := writeFileAtomic(dst, e.Data, 0644); err != nil {
			return err
		}
	}
	return nil
}

func clearCurrentSynced(configDir string) error {
	// profiles/*.json
	if err := removeDirFiles(filepath.Join(configDir, "profiles"), func(name string) bool {
		return strings.HasSuffix(strings.ToLower(name), ".json")
	}); err != nil {
		return err
	}
	// groups/<number>.json + groups/pm.json
	if err := removeDirFiles(filepath.Join(configDir, "groups"), func(name string) bool {
		l := strings.ToLower(name)
		if l == "pm.json" {
			return true
		}
		if l == "nekobox.json" {
			return false
		}
		if !strings.HasSuffix(l, ".json") {
			return false
		}
		base := strings.TrimSuffix(l, ".json")
		_, err := strconv.Atoi(base)
		return err == nil
	}); err != nil {
		return err
	}
	// routes_box/*
	if err := removeDirFiles(filepath.Join(configDir, "routes_box"), func(name string) bool { return true }); err != nil {
		return err
	}
	return nil
}

func removeDirFiles(absDir string, accept func(name string) bool) error {
	entries, err := os.ReadDir(absDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	for _, de := range entries {
		if de.IsDir() {
			continue
		}
		if !accept(de.Name()) {
			continue
		}
		if err := os.Remove(filepath.Join(absDir, de.Name())); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	return nil
}

func writeSnapshotFiles(configDir string, files map[string][]byte) error {
	paths := make([]string, 0, len(files))
	for p := range files {
		paths = append(paths, p)
	}
	sort.Strings(paths)

	for _, rel := range paths {
		if !allowedRelPath(rel) {
			continue
		}
		dst := filepath.Join(configDir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
			return err
		}
		if err := writeFileAtomic(dst, files[rel], 0644); err != nil {
			return err
		}
	}
	return nil
}

func writeFileAtomic(dst string, data []byte, perm os.FileMode) error {
	tmp := dst + ".tmp"
	if err := os.WriteFile(tmp, data, perm); err != nil {
		return err
	}
	return os.Rename(tmp, dst)
}

func snapshotHashFromMap(files map[string][]byte) string {
	paths := make([]string, 0, len(files))
	for p := range files {
		if allowedRelPath(p) {
			paths = append(paths, p)
		}
	}
	sort.Strings(paths)
	h := sha256.New()
	for _, p := range paths {
			sum := sha256.Sum256(files[p])
			_, _ = h.Write([]byte(p))
			_, _ = h.Write([]byte{0})
			_, _ = h.Write(sum[:])
		}
		return hex.EncodeToString(h.Sum(nil))
	}

// keep errors.New in one place for Go < 1.20 compatibility
var _ = errors.New
