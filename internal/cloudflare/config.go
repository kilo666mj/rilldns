package cloudflare

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type Config struct {
	Zones    []string `json:"zones"`
	Revision string   `json:"revision"`
}

func LoadConfig(path string, fallback []string) (Config, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return MakeConfig(fallback), nil
	}
	if err != nil {
		return Config{}, err
	}
	var config Config
	if err := json.Unmarshal(data, &config); err != nil {
		return Config{}, err
	}
	return MakeConfig(config.Zones), nil
}

func SaveConfig(path string, zones []string) (Config, error) {
	config := MakeConfig(zones)
	data, _ := json.MarshalIndent(config, "", "  ")
	data = append(data, '\n')
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return Config{}, err
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".cloudflare-zones-*")
	if err != nil {
		return Config{}, err
	}
	name := temporary.Name()
	// Best effort: on the success path the rename has already consumed
	// this name, so the remove is expected to fail with ENOENT.
	defer func() { _ = os.Remove(name) }()
	if err := temporary.Chmod(0o640); err != nil {
		return Config{}, errors.Join(err, closeError("close temporary cloudflare config", temporary.Close))
	}
	if _, err := temporary.Write(data); err != nil {
		return Config{}, errors.Join(err, closeError("close temporary cloudflare config", temporary.Close))
	}
	if err := temporary.Sync(); err != nil {
		return Config{}, errors.Join(err, closeError("close temporary cloudflare config", temporary.Close))
	}
	if err := temporary.Close(); err != nil {
		return Config{}, err
	}
	if err := os.Rename(name, path); err != nil {
		return Config{}, err
	}
	return config, nil
}

func MakeConfig(zones []string) Config {
	seen := make(map[string]bool)
	normalized := make([]string, 0, len(zones))
	for _, zone := range zones {
		zone = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(zone), "."))
		if zone != "" && !seen[zone] {
			seen[zone] = true
			normalized = append(normalized, zone)
		}
	}
	sort.Strings(normalized)
	data, _ := json.Marshal(normalized)
	sum := sha256.Sum256(data)
	return Config{Zones: normalized, Revision: hex.EncodeToString(sum[:])}
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
