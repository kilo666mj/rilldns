package blocking

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

// RefreshRequestFile is watched by rilldns-refresh-blocklists.path, which
// starts the refresh service whenever the file is written. The API therefore
// needs no privilege to control systemd.
const RefreshRequestFile = "refresh.request"

type RefreshRequest struct {
	RequestedAt time.Time `json:"requested_at"`
	Actor       string    `json:"actor"`
	RequestID   string    `json:"request_id"`
}

// RequestRefresh records a refresh request. The file is rewritten in place
// rather than renamed into position so that the path unit observes a
// close-after-write on the watched name.
func (s *Store) RequestRefresh(actor, requestID string, now time.Time) (RefreshRequest, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	request := RefreshRequest{RequestedAt: now.UTC(), Actor: actor, RequestID: requestID}
	content, err := json.Marshal(request)
	if err != nil {
		return RefreshRequest{}, err
	}
	if err := os.WriteFile(filepath.Join(s.dir, RefreshRequestFile), append(content, '\n'), 0o640); err != nil {
		return RefreshRequest{}, err
	}
	return request, nil
}
