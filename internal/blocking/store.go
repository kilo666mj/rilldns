package blocking

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/miekg/dns"
)

var (
	ErrInvalid          = errors.New("invalid blocklist configuration")
	ErrRevisionMismatch = errors.New("blocklist configuration revision mismatch")
)

type Config struct {
	Sources  []string `json:"sources"`
	Allow    []string `json:"allow"`
	Deny     []string `json:"deny"`
	Revision string   `json:"revision"`
}

type UpdateRequest struct {
	Sources          []string `json:"sources"`
	Allow            []string `json:"allow"`
	Deny             []string `json:"deny"`
	ExpectedRevision string   `json:"expected_revision"`
	DryRun           bool     `json:"dry_run"`
}

type UpdateResult struct {
	Config           Config `json:"config"`
	PreviousRevision string `json:"previous_revision"`
	DryRun           bool   `json:"dry_run"`
	Published        bool   `json:"published"`
	RequestID        string `json:"request_id"`
}

type Store struct {
	dir string
	mu  sync.Mutex
}

func NewStore(dir string) *Store { return &Store{dir: dir} }

func (s *Store) Get() (Config, error) {
	sources, err := readLines(filepath.Join(s.dir, "sources.txt"))
	if err != nil {
		return Config{}, err
	}
	allow, err := readLines(filepath.Join(s.dir, "allow.txt"))
	if err != nil {
		return Config{}, err
	}
	deny, err := readLines(filepath.Join(s.dir, "deny.txt"))
	if err != nil {
		return Config{}, err
	}
	config, err := normalize(sources, allow, deny)
	if err != nil {
		return Config{}, err
	}
	config.Revision = revision(config)
	return config, nil
}

func (s *Store) Update(request UpdateRequest, requestID string) (UpdateResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	current, err := s.Get()
	if err != nil {
		return UpdateResult{}, err
	}
	if request.ExpectedRevision == "" || request.ExpectedRevision != current.Revision {
		return UpdateResult{}, ErrRevisionMismatch
	}
	next, err := normalize(request.Sources, request.Allow, request.Deny)
	if err != nil {
		return UpdateResult{}, err
	}
	next.Revision = revision(next)
	result := UpdateResult{Config: next, PreviousRevision: current.Revision, DryRun: request.DryRun, RequestID: requestID}
	if request.DryRun {
		return result, nil
	}
	for name, values := range map[string][]string{"sources.txt": next.Sources, "allow.txt": next.Allow, "deny.txt": next.Deny} {
		if err := writeAtomic(filepath.Join(s.dir, name), values); err != nil {
			return UpdateResult{}, err
		}
	}
	result.Published = true
	return result, nil
}

func normalize(sources, allow, deny []string) (Config, error) {
	if len(sources) == 0 || len(sources) > 32 {
		return Config{}, fmt.Errorf("%w: 1 to 32 sources are required", ErrInvalid)
	}
	normalizedSources := unique(sources, func(value string) (string, error) {
		parsed, err := url.Parse(strings.TrimSpace(value))
		if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil {
			return "", fmt.Errorf("%w: source must be an HTTPS URL", ErrInvalid)
		}
		return parsed.String(), nil
	})
	if normalizedSources.err != nil {
		return Config{}, normalizedSources.err
	}
	normalizeDomain := func(value string) (string, error) {
		value = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(value), "."))
		if value == "" || value == "localhost" || !validDomain(value) {
			return "", fmt.Errorf("%w: invalid domain %q", ErrInvalid, value)
		}
		return value, nil
	}
	normalizedAllow := unique(allow, normalizeDomain)
	if normalizedAllow.err != nil {
		return Config{}, normalizedAllow.err
	}
	normalizedDeny := unique(deny, normalizeDomain)
	if normalizedDeny.err != nil {
		return Config{}, normalizedDeny.err
	}
	return Config{Sources: normalizedSources.values, Allow: normalizedAllow.values, Deny: normalizedDeny.values}, nil
}

type normalized struct {
	values []string
	err    error
}

func unique(values []string, normalize func(string) (string, error)) normalized {
	seen := map[string]struct{}{}
	result := make([]string, 0, len(values))
	for _, value := range values {
		value, err := normalize(value)
		if err != nil {
			return normalized{err: err}
		}
		if _, exists := seen[value]; !exists {
			seen[value] = struct{}{}
			result = append(result, value)
		}
	}
	sort.Strings(result)
	return normalized{values: result}
}

func validDomain(value string) bool {
	_, ok := dns.IsDomainName(dns.Fqdn(value))
	return ok && !strings.ContainsAny(value, " /:#")
}

func readLines(path string) ([]string, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	result := make([]string, 0)
	for _, line := range strings.Split(string(content), "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			result = append(result, line)
		}
	}
	return result, nil
}

func revision(config Config) string {
	hash := sha256.New()
	for _, values := range [][]string{config.Sources, config.Allow, config.Deny} {
		for _, value := range values {
			hash.Write([]byte(value + "\n"))
		}
		hash.Write([]byte{0})
	}
	return hex.EncodeToString(hash.Sum(nil))
}

func writeAtomic(path string, values []string) error {
	content := []byte(strings.Join(values, "\n") + "\n")
	temporary, err := os.CreateTemp(filepath.Dir(path), ".blocking-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if _, err = temporary.Write(content); err == nil {
		err = temporary.Chmod(0o640)
	}
	if closeErr := temporary.Close(); err == nil {
		err = closeErr
	}
	if err == nil {
		err = os.Rename(temporaryPath, path)
	}
	return err
}
