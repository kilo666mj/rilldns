package statusfile

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// WriteJSON atomically replaces path with an indented JSON document.
func WriteJSON(path string, value any, mode os.FileMode) (err error) {
	if err := os.MkdirAll(filepath.Dir(path), 0750); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+"-")
	if err != nil {
		return err
	}
	tmp := f.Name()
	// Best effort: on the success path the rename has already consumed this
	// name, so the remove is expected to fail with ENOENT.
	defer func() { _ = os.Remove(tmp) }()
	if err := f.Chmod(mode); err != nil {
		return errors.Join(err, closeError("close temporary status file", f.Close))
	}
	if err := json.NewEncoder(f).Encode(value); err != nil {
		return errors.Join(err, closeError("close temporary status file", f.Close))
	}
	if err := f.Sync(); err != nil {
		return errors.Join(err, closeError("close temporary status file", f.Close))
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("publish %s: %w", path, err)
	}
	return nil
}

// closeError runs a cleanup function and labels its failure.
func closeError(context string, closeFn func() error) error {
	if err := closeFn(); err != nil {
		return fmt.Errorf("%s: %w", context, err)
	}
	return nil
}
