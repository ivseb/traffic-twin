package sourceclient

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
)

// File names inside the state directory.
const (
	fileEnrollment  = "enrollment.json"
	fileClientKey   = "client.key"
	filePolicyCache = "policy-cache.json"
)

// StateDir is the local state of a source: enrollment (certificate, CA chain,
// pinned signing keys), the client private key and the policy cache with the
// kill switch. The directory is 0700 and every file 0600; files are replaced
// atomically.
type StateDir struct {
	dir string
}

// OpenState creates the directory if needed.
func OpenState(dir string) (*StateDir, error) {
	if dir == "" {
		return nil, fmt.Errorf("sourceclient: empty state directory")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("sourceclient: state directory: %w", err)
	}
	// Best effort: the directory may belong to somebody else (read-only
	// volume); the files are still written 0600.
	_ = os.Chmod(dir, 0o700)
	return &StateDir{dir: dir}, nil
}

// Dir returns the directory path.
func (s *StateDir) Dir() string { return s.dir }

// Read returns a file of the state; os.ErrNotExist when absent.
func (s *StateDir) Read(name string) ([]byte, error) {
	return os.ReadFile(filepath.Join(s.dir, name))
}

// Write replaces a file atomically with mode 0600.
func (s *StateDir) Write(name string, data []byte) error {
	f, err := os.CreateTemp(s.dir, "."+name+".*.tmp")
	if err != nil {
		return err
	}
	tmp := f.Name()
	ok := false
	defer func() {
		if !ok {
			_ = os.Remove(tmp)
		}
	}()
	if err := f.Chmod(0o600); err != nil {
		_ = f.Close()
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, filepath.Join(s.dir, name)); err != nil {
		return err
	}
	ok = true
	return nil
}

// Remove deletes a file; a missing file is not an error.
func (s *StateDir) Remove(name string) {
	_ = os.Remove(filepath.Join(s.dir, name))
}

// DefaultStateDir derives a per-installation directory under the user's home
// (the same layout as the Node SDK: ~/.traffic-twin/<hash>), falling back to
// the temporary directory when there is no home.
func DefaultStateDir(enrollURL, serviceName string) string {
	sum := sha256.Sum256([]byte(enrollURL + "\x00" + serviceName))
	id := hex.EncodeToString(sum[:])[:16]
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		return filepath.Join(home, ".traffic-twin", id)
	}
	return filepath.Join(os.TempDir(), fmt.Sprintf("traffic-twin-%d", os.Getuid()), id)
}
