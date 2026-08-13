package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
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
	fail := func(cause error) error {
		_ = statusfile.WriteJSON(statusPath, refreshstatus.Status{Kind: "blocklists", LastAttempt: attempt, Error: cause.Error()}, 0440)
		return cause
	}
	if err := os.MkdirAll(dir, 0750); err != nil {
		return fail(err)
	}
	client := &http.Client{Timeout: 3 * time.Minute}
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
	defer os.RemoveAll(work)
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
	tmp.Close()
	defer os.Remove(path)
	if err := download(ctx, client, url, path); err != nil {
		return err
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return json.NewDecoder(f).Decode(value)
}
func download(ctx context.Context, client *http.Client, url, path string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
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
func readLines(path string) ([]string, error) {
	f, e := os.Open(path)
	if e != nil {
		return nil, e
	}
	defer f.Close()
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
	defer os.Remove(tmp)
	for _, v := range values {
		if _, e = fmt.Fprintln(f, v); e != nil {
			f.Close()
			return e
		}
	}
	if e = f.Chmod(0640); e == nil {
		e = f.Close()
	} else {
		f.Close()
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
	f.Close()
	return n, hex.EncodeToString(h.Sum(nil)), e
}
