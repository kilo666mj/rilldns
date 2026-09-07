package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/kilo666mj/rilldns/internal/refreshstatus"
	"github.com/kilo666mj/rilldns/internal/statusfile"
)

const maxDownload = 100 << 20

type config struct{ Sources, Allow, Deny []string }

func main() {
	dir := flag.String("blocking-dir", "/var/lib/rilldns/blocking", "blocking data directory")
	statusPath := flag.String("status-file", "/var/lib/rilldns/status/blocklists.json", "status output")
	merger := flag.String("merge-binary", "/usr/local/bin/rill-blocklist-merge", "merge binary")
	configURL := flag.String("config-url", os.Getenv("RILLDNS_BLOCKLIST_CONFIG_URL"), "optional configuration URL")
	minimum := flag.Int("minimum-domains", 100000, "minimum safe publication size")
	flag.Parse()
	if err := run(context.Background(), *dir, *statusPath, *merger, *configURL, *minimum); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(ctx context.Context, dir, statusPath, merger, configURL string, minimum int) (err error) {
	attempt := time.Now().UTC()
	previous := loadBlocklistStatus(statusPath)
	fail := func(cause error) error {
		previous.Kind = "blocklists"
		previous.Success = false
		previous.LastAttempt = attempt
		previous.Error = cause.Error()
		_ = statusfile.WriteJSON(statusPath, previous, 0440)
		return cause
	}
	if err := os.MkdirAll(dir, 0750); err != nil {
		return fail(err)
	}
	client := &http.Client{
		Timeout: 3 * time.Minute,
		CheckRedirect: func(request *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return fmt.Errorf("too many redirects")
			}
			return validateRemoteURL(request.URL)
		},
	}
	if configURL != "" {
		var cfg config
		if err := downloadJSON(ctx, client, configURL, &cfg); err != nil {
			return fail(fmt.Errorf("sync config: %w", err))
		}
		if len(cfg.Sources) == 0 {
			return fail(fmt.Errorf("synced config has no sources"))
		}
		for name, values := range map[string][]string{"sources.txt": cfg.Sources, "allow.txt": cfg.Allow, "deny.txt": cfg.Deny} {
			if err := writeLines(filepath.Join(dir, name), values); err != nil {
				return fail(err)
			}
		}
	}
	sources, err := readLines(filepath.Join(dir, "sources.txt"))
	if err != nil {
		return fail(err)
	}
	if len(sources) == 0 {
		return fail(fmt.Errorf("no blocklist sources configured"))
	}
	work, err := os.MkdirTemp(dir, ".refresh-")
	if err != nil {
		return fail(err)
	}
	// Best effort: a leftover scratch directory is not worth failing the run.
	defer func() { _ = os.RemoveAll(work) }()
	inputs := []string{filepath.Join(dir, "deny.txt")}
	for i, source := range sources {
		path := filepath.Join(work, fmt.Sprintf("source-%d.txt", i))
		if err := download(ctx, client, source, path); err != nil {
			return fail(fmt.Errorf("download %s: %w", source, err))
		}
		inputs = append(inputs, path)
	}
	output := filepath.Join(work, "merged.hosts")
	args := []string{"-allow", filepath.Join(dir, "allow.txt"), "-output", output}
	args = append(args, inputs...)
	if out, err := exec.CommandContext(ctx, merger, args...).CombinedOutput(); err != nil {
		return fail(fmt.Errorf("merge: %w: %s", err, strings.TrimSpace(string(out))))
	}
	count, sum, err := inspectHosts(output)
	if err != nil {
		return fail(err)
	}
	if count < minimum {
		return fail(fmt.Errorf("refusing blocklist with only %d domains", count))
	}
	if err := os.Chmod(output, 0440); err != nil {
		return fail(err)
	}
	if err := os.Rename(output, filepath.Join(dir, "merged.hosts")); err != nil {
		return fail(err)
	}
	now := time.Now().UTC()
	return statusfile.WriteJSON(statusPath, refreshstatus.Status{Kind: "blocklists", Success: true, LastAttempt: attempt, LastSuccess: now, Domains: count, Sources: len(sources), SHA256: sum}, 0440)
}

func downloadJSON(ctx context.Context, client *http.Client, url string, value any) error {
	tmp, err := os.CreateTemp("", "rill-config-")
	if err != nil {
		return err
	}
	path := tmp.Name()
	// Closed immediately to hand the bare path to the downloader, which
	// recreates it.
	_ = tmp.Close()
	defer func() { _ = os.Remove(path) }()
	if err := downloadWithParser(ctx, client, url, path, parseConfigURL); err != nil {
		return err
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	// Read-only: nothing was written, so a close failure changes nothing.
	defer func() { _ = f.Close() }()
	return json.NewDecoder(f).Decode(value)
}
func download(ctx context.Context, client *http.Client, url, path string) (err error) {
	return downloadWithParser(ctx, client, url, path, parseRemoteURL)
}

func downloadWithParser(ctx context.Context, client *http.Client, rawURL, path string, parser func(string) (*url.URL, error)) error {
	parsed, err := parser(rawURL)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, parsed.String(), nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer closeWithError(&err, "close response body", resp.Body.Close)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("HTTP %s", resp.Status)
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	n, copyErr := io.Copy(f, io.LimitReader(resp.Body, maxDownload+1))
	closeErr := f.Close()
	if copyErr != nil {
		return copyErr
	}
	if closeErr != nil {
		return closeErr
	}
	if n > maxDownload {
		return fmt.Errorf("response exceeds %d bytes", maxDownload)
	}
	return nil
}

func loadBlocklistStatus(path string) refreshstatus.Status {
	content, err := os.ReadFile(path)
	if err != nil {
		return refreshstatus.Status{}
	}
	var status refreshstatus.Status
	if json.Unmarshal(content, &status) != nil {
		return refreshstatus.Status{}
	}
	return status
}

func parseRemoteURL(raw string) (*url.URL, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return nil, fmt.Errorf("invalid URL: %w", err)
	}
	if err := validateRemoteURL(parsed); err != nil {
		return nil, err
	}
	return parsed, nil
}

func parseConfigURL(raw string) (*url.URL, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return nil, fmt.Errorf("invalid URL: %w", err)
	}
	if parsed.Scheme == "http" && parsed.User == nil {
		ip := net.ParseIP(parsed.Hostname())
		if ip != nil && (ip.IsPrivate() || ip.IsLoopback()) {
			return parsed, nil
		}
	}
	if err := validateRemoteURL(parsed); err != nil {
		return nil, err
	}
	return parsed, nil
}

func validateRemoteURL(parsed *url.URL) error {
	if parsed.Scheme != "https" || parsed.Hostname() == "" || parsed.User != nil {
		return fmt.Errorf("remote URL must be absolute HTTPS without user information")
	}
	return nil
}
func readLines(path string) ([]string, error) {
	f, e := os.Open(path)
	if e != nil {
		return nil, e
	}
	// Read-only: nothing was written, so a close failure changes nothing.
	defer func() { _ = f.Close() }()
	var out []string
	s := bufio.NewScanner(f)
	for s.Scan() {
		v := strings.TrimSpace(strings.SplitN(s.Text(), "#", 2)[0])
		if v != "" {
			out = append(out, v)
		}
	}
	return out, s.Err()
}
func writeLines(path string, values []string) error {
	f, e := os.CreateTemp(filepath.Dir(path), ".config-")
	if e != nil {
		return e
	}
	tmp := f.Name()
	// Best effort: on success the rename has already consumed this name.
	defer func() { _ = os.Remove(tmp) }()
	for _, v := range values {
		if _, e = fmt.Fprintln(f, v); e != nil {
			return errors.Join(e, closeError("close temporary blocklist", f.Close))
		}
	}
	if e = f.Chmod(0640); e == nil {
		e = f.Close()
	} else {
		e = errors.Join(e, closeError("close temporary blocklist", f.Close))
	}
	if e != nil {
		return e
	}
	return os.Rename(tmp, path)
}
func inspectHosts(path string) (int, string, error) {
	f, e := os.Open(path)
	if e != nil {
		return 0, "", e
	}
	h := sha256.New()
	s := bufio.NewScanner(io.TeeReader(f, h))
	n := 0
	for s.Scan() {
		if strings.HasPrefix(s.Text(), "0.0.0.0 ") {
			n++
		}
	}
	e = s.Err()
	// Read-only: nothing was written, so a close failure changes nothing.
	_ = f.Close()
	return n, hex.EncodeToString(h.Sum(nil)), e
}

// closeError runs a cleanup function and labels its failure.
func closeError(context string, closeFn func() error) error {
	if err := closeFn(); err != nil {
		return fmt.Errorf("%s: %w", context, err)
	}
	return nil
}

// closeWithError joins a cleanup failure onto a named error return without
// discarding the primary error.
func closeWithError(errp *error, context string, closeFn func() error) {
	*errp = errors.Join(*errp, closeError(context, closeFn))
}
