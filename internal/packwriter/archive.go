package packwriter

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Archive renders a .ttpack (pack.md 1): POSIX ustar in gzip, files in byte
// order of path, mtime 0, owner 0:0, mode 0644, gzip header without mtime
// and name. The same files give the same bytes.
func Archive(files map[string][]byte) ([]byte, error) {
	paths := make([]string, 0, len(files))
	for p := range files {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	var buf bytes.Buffer
	zw, err := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	if err != nil {
		return nil, err
	}
	tw := tar.NewWriter(zw)
	for _, p := range paths {
		h := &tar.Header{Typeflag: tar.TypeReg, Name: p, Size: int64(len(files[p])), Mode: 0o644, ModTime: time.Unix(0, 0), Format: tar.FormatUSTAR}
		if err := tw.WriteHeader(h); err != nil {
			return nil, err
		}
		if _, err := tw.Write(files[p]); err != nil {
			return nil, err
		}
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// ReadArchive reads the regular files of a .ttpack.
func ReadArchive(b []byte) (map[string][]byte, error) {
	zr, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	tr := tar.NewReader(zr)
	out := map[string][]byte{}
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return out, nil
		}
		if err != nil {
			return nil, err
		}
		if h.Typeflag != tar.TypeReg || h.Size > 256<<20 {
			return nil, errors.New("packwriter: unexpected archive entry")
		}
		data, err := io.ReadAll(io.LimitReader(tr, h.Size))
		if err != nil {
			return nil, err
		}
		out[h.Name] = data
	}
}

// WriteDir writes the pack files under dir (created, 0700).
func WriteDir(dir string, files map[string][]byte) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	for p, b := range files {
		if strings.Contains(p, "..") || filepath.IsAbs(p) {
			return fmt.Errorf("packwriter: bad path")
		}
		full := filepath.Join(dir, filepath.FromSlash(p))
		if err := os.MkdirAll(filepath.Dir(full), 0o700); err != nil {
			return err
		}
		if err := os.WriteFile(full, b, 0o600); err != nil {
			return err
		}
	}
	return nil
}
