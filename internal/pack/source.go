package pack

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// checkListing validates the manifest file list against the files found in
// the source (name -> size), before any of them is read: presence, exact
// declared size, no unlisted files, referenced files listed.
func checkListing(m *Manifest, sizes map[string]int64) error {
	listed := map[string]bool{}
	var total int64
	for _, f := range m.Files {
		if !relPathRE.MatchString(f.Path) || !sha256RE.MatchString(f.SHA256) || f.Bytes < 0 {
			return fmt.Errorf("%w: malformed files entry", ErrManifest)
		}
		if f.Path == manifestName || f.Path == sigName {
			return fmt.Errorf("%w: files must not list %s", ErrManifest, f.Path)
		}
		if listed[f.Path] {
			return fmt.Errorf("%w: duplicate files entry %q", ErrManifest, f.Path)
		}
		listed[f.Path] = true
		size, ok := sizes[f.Path]
		if !ok {
			return fmt.Errorf("%w: listed file %q is missing", ErrFiles, f.Path)
		}
		if size != f.Bytes {
			return fmt.Errorf("%w: %q has a different size", ErrFiles, f.Path)
		}
		if f.Bytes > maxFileBytes || total+f.Bytes > maxTotal {
			return fmt.Errorf("%w: pack is too large", ErrFiles)
		}
		total += f.Bytes
	}
	var extra []string
	for name := range sizes {
		if name == manifestName || name == sigName || listed[name] {
			continue
		}
		extra = append(extra, name)
	}
	if len(extra) > 0 {
		sort.Strings(extra)
		return fmt.Errorf("%w: file %q is not listed", ErrFiles, extra[0])
	}
	refs := []string{m.Rules.Path, m.World.Path, m.Faults, m.GateReport}
	for _, s := range m.Services {
		refs = append(refs, s.Contract)
	}
	if m.Scenarios != "" {
		refs = append(refs, m.Scenarios)
	}
	for _, r := range refs {
		if !listed[r] {
			return fmt.Errorf("%w: referenced file %q is not in files", ErrManifest, r)
		}
	}
	return nil
}

// checkHashes verifies the SHA-256 of every listed file read from the source.
func checkHashes(m *Manifest, files map[string][]byte) error {
	for _, f := range m.Files {
		data := files[f.Path]
		sum := sha256.Sum256(data)
		if int64(len(data)) != f.Bytes || hex.EncodeToString(sum[:]) != f.SHA256 {
			return fmt.Errorf("%w: %q has a different hash", ErrFiles, f.Path)
		}
	}
	return nil
}

// scanResult is what the first pass over a source finds: the size of every
// regular file and the (size-capped) manifest and signature. No other file
// content is read or kept.
type scanResult struct {
	sizes    map[string]int64
	manifest []byte // nil when absent
	sig      []byte // nil when absent
}

// source is a pack directory or archive, read in two passes so that the
// signature is verified before the bulk of the content is read.
type source interface {
	scan() (*scanResult, error)
	// read returns the content of the listed files into buffers sized from
	// the declared sizes; a file whose real size differs is an error.
	read(files []ManifestFile) (map[string][]byte, error)
}

func openSource(path string) (source, error) {
	st, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("pack: %w", err)
	}
	if st.Mode()&fs.ModeSymlink != 0 {
		// Resolve a top-level symlink explicitly requested by the operator.
		if st, err = os.Stat(path); err != nil {
			return nil, fmt.Errorf("pack: %w", err)
		}
	}
	if st.IsDir() {
		return dirSource(path), nil
	}
	return archiveSource(path), nil
}

// capFor returns the size cap of the two files read before verification.
func capFor(name string) int64 {
	switch name {
	case manifestName:
		return maxManifestBytes
	case sigName:
		return maxSigBytes
	}
	return 0
}

type dirSource string

func (root dirSource) scan() (*scanResult, error) {
	r := &scanResult{sizes: map[string]int64{}}
	var total int64
	err := filepath.WalkDir(string(root), func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if p == string(root) {
			return nil
		}
		if d.Type()&fs.ModeSymlink != 0 {
			return fmt.Errorf("%w: %q is a symbolic link", ErrFiles, d.Name())
		}
		if d.IsDir() {
			return nil
		}
		if !d.Type().IsRegular() {
			return fmt.Errorf("%w: %q is not a regular file", ErrFiles, d.Name())
		}
		rel, err := filepath.Rel(string(root), p)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if !relPathRE.MatchString(rel) {
			return fmt.Errorf("%w: file name %q is not allowed", ErrFiles, rel)
		}
		if len(r.sizes) >= maxFiles {
			return fmt.Errorf("%w: too many files", ErrFiles)
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		if info.Size() > maxFileBytes || total+info.Size() > maxTotal {
			return fmt.Errorf("%w: pack is too large", ErrFiles)
		}
		total += info.Size()
		r.sizes[rel] = info.Size()
		if limit := capFor(rel); limit > 0 {
			if info.Size() > limit {
				return fmt.Errorf("%w: %s is too large", ErrFiles, rel)
			}
			b, err := readExact(p, info.Size())
			if err != nil {
				return err
			}
			if rel == manifestName {
				r.manifest = b
			} else {
				r.sig = b
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return r, nil
}

func (root dirSource) read(files []ManifestFile) (map[string][]byte, error) {
	out := make(map[string][]byte, len(files))
	for _, f := range files {
		b, err := readExact(filepath.Join(string(root), filepath.FromSlash(f.Path)), f.Bytes)
		if err != nil {
			return nil, err
		}
		out[f.Path] = b
	}
	return out, nil
}

// readExact reads a regular file that must be exactly size bytes long into a
// buffer of that size.
func readExact(path string, size int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() || st.Size() != size {
		return nil, fmt.Errorf("%w: %q has a different size", ErrFiles, filepath.Base(path))
	}
	b := make([]byte, size)
	if _, err := io.ReadFull(f, b); err != nil {
		return nil, fmt.Errorf("%w: %q: %v", ErrFiles, filepath.Base(path), err)
	}
	var one [1]byte
	if n, _ := f.Read(one[:]); n != 0 {
		return nil, fmt.Errorf("%w: %q grew while it was read", ErrFiles, filepath.Base(path))
	}
	return b, nil
}

type archiveSource string

// limitReader fails (instead of stopping silently) after n bytes: the
// decompressed size of an archive is bounded, whatever its headers say.
type limitReader struct {
	r io.Reader
	n int64
}

func (l *limitReader) Read(p []byte) (int, error) {
	if l.n <= 0 {
		return 0, fmt.Errorf("%w: archive expands beyond %d bytes", ErrFiles, int64(maxTotal))
	}
	if int64(len(p)) > l.n {
		p = p[:l.n]
	}
	n, err := l.r.Read(p)
	l.n -= int64(n)
	return n, err
}

// expansionSlack covers tar headers and padding on top of maxTotal.
const expansionSlack = 64 << 20

// walk iterates the regular entries of the archive in order, with the
// structural checks of the first pass; fn may read the entry content from
// tr, anything it leaves unread is skipped without being buffered.
func (a archiveSource) walk(fn func(name string, h *tar.Header, tr *tar.Reader) error) error {
	f, err := os.Open(string(a))
	if err != nil {
		return fmt.Errorf("pack: %w", err)
	}
	defer f.Close()
	zr, err := gzip.NewReader(f)
	if err != nil {
		return fmt.Errorf("%w: not a gzip archive: %v", ErrFiles, err)
	}
	defer zr.Close()
	tr := tar.NewReader(&limitReader{r: zr, n: maxTotal + expansionSlack})
	seen := map[string]bool{}
	var total int64
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return fmt.Errorf("%w: %v", ErrFiles, err)
		}
		if h.Typeflag == tar.TypeDir {
			continue
		}
		if h.Typeflag != tar.TypeReg {
			return fmt.Errorf("%w: archive entry %q is not a regular file", ErrFiles, h.Name)
		}
		name := strings.TrimPrefix(h.Name, "./")
		if !relPathRE.MatchString(name) {
			return fmt.Errorf("%w: archive entry name %q is not allowed", ErrFiles, name)
		}
		if seen[name] {
			return fmt.Errorf("%w: duplicate archive entry %q", ErrFiles, name)
		}
		if len(seen) >= maxFiles || h.Size < 0 || h.Size > maxFileBytes || total+h.Size > maxTotal {
			return fmt.Errorf("%w: pack is too large", ErrFiles)
		}
		seen[name] = true
		total += h.Size
		if err := fn(name, h, tr); err != nil {
			return err
		}
	}
}

func (a archiveSource) scan() (*scanResult, error) {
	r := &scanResult{sizes: map[string]int64{}}
	err := a.walk(func(name string, h *tar.Header, tr *tar.Reader) error {
		r.sizes[name] = h.Size
		limit := capFor(name)
		if limit == 0 {
			return nil
		}
		if h.Size > limit {
			return fmt.Errorf("%w: %s is too large", ErrFiles, name)
		}
		b := make([]byte, h.Size)
		if _, err := io.ReadFull(tr, b); err != nil {
			return fmt.Errorf("%w: truncated archive entry %q", ErrFiles, name)
		}
		if name == manifestName {
			r.manifest = b
		} else {
			r.sig = b
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return r, nil
}

func (a archiveSource) read(files []ManifestFile) (map[string][]byte, error) {
	want := make(map[string]int64, len(files))
	for _, f := range files {
		want[f.Path] = f.Bytes
	}
	out := make(map[string][]byte, len(files))
	err := a.walk(func(name string, h *tar.Header, tr *tar.Reader) error {
		size, ok := want[name]
		if !ok {
			return nil
		}
		if h.Size != size {
			return fmt.Errorf("%w: %q has a different size", ErrFiles, name)
		}
		b := make([]byte, size)
		if _, err := io.ReadFull(tr, b); err != nil {
			return fmt.Errorf("%w: truncated archive entry %q", ErrFiles, name)
		}
		out[name] = b
		return nil
	})
	if err != nil {
		return nil, err
	}
	if len(out) != len(want) {
		return nil, fmt.Errorf("%w: archive changed while it was read", ErrFiles)
	}
	return out, nil
}
