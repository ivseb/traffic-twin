package core

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/ivseb/traffic-twin/internal/auth"
)

// SetupTokenFile is the name, inside the data directory, of the file that
// holds the one-time setup token. A service manager keeps stdout in its log
// (the systemd journal), so the token is not printed there by default.
const SetupTokenFile = "setup-token"

// WriteSetupToken stores the token in dir/setup-token (mode 0600, replaced
// at every start) and returns the path.
func WriteSetupToken(dir, token string) (string, error) {
	if dir == "" {
		return "", errors.New("core: no data directory")
	}
	path := filepath.Join(dir, SetupTokenFile)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(token+"\n"), 0o600); err != nil {
		return "", err
	}
	if err := os.Chmod(tmp, 0o600); err != nil {
		_ = os.Remove(tmp)
		return "", err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return "", err
	}
	return path, nil
}

// RemoveSetupTokenFile deletes a token file left by an earlier start, once
// an administrator exists. A missing file is not an error.
func RemoveSetupTokenFile(dir string) {
	if dir == "" {
		return
	}
	if err := os.Remove(filepath.Join(dir, SetupTokenFile)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return
	}
}

// PrintSetupTokenFile tells the operator where the setup token is, without
// printing it.
func PrintSetupTokenFile(w io.Writer, path, baseURL string) {
	fmt.Fprintln(w)
	fmt.Fprintln(w, "No administrator exists yet. A one-time setup token (the first administrator needs it) was written to:")
	fmt.Fprintf(w, "\n    %s   (mode 0600; valid %s, replaced at every restart until used)\n\n", path, auth.SetupTokenTTL)
	fmt.Fprintf(w, "Read it on this host (the console and the log never show it), then open %s/ or POST %s/api/v1/setup\n", baseURL, baseURL)
	fmt.Fprintln(w, "{\"setup_token\", \"username\", \"password\"}. Delete the file once the administrator exists.")
	fmt.Fprintln(w, "For a trial on a terminal you own, `tt core -print-setup-token` prints the token here instead.")
	fmt.Fprintln(w)
}
