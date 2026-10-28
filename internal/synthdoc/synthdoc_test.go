package synthdoc

import (
	"archive/zip"
	"bytes"
	"image/gif"
	"image/jpeg"
	"image/png"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

// detect is the type recognition of docs/spec/sanitizer.md 22.4 point 3.
func detect(b []byte) string {
	switch {
	case bytes.HasPrefix(b, []byte("%PDF-")):
		return "pdf"
	case bytes.HasPrefix(b, []byte{0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a}):
		return "png"
	case bytes.HasPrefix(b, []byte{0xff, 0xd8, 0xff}):
		return "jpeg"
	case bytes.HasPrefix(b, []byte("GIF87a")), bytes.HasPrefix(b, []byte("GIF89a")):
		return "gif"
	case len(b) >= 12 && bytes.HasPrefix(b, []byte("RIFF")) && string(b[8:12]) == "WEBP":
		return "webp"
	case bytes.HasPrefix(b, []byte{0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1}):
		return "ole"
	case bytes.HasPrefix(b, []byte("PK\x03\x04")):
		switch {
		case bytes.Contains(b, []byte("word/document.xml")):
			return "docx"
		case bytes.Contains(b, []byte("xl/workbook.xml")):
			return "xlsx"
		case bytes.Contains(b, []byte("ppt/presentation.xml")):
			return "pptx"
		}
		return "zip"
	}
	return ""
}

func classOf(n int) string {
	switch {
	case n <= 1024:
		return "l1k"
	case n <= 16384:
		return "l16k"
	case n <= 131072:
		return "l128k"
	case n <= 1<<20:
		return "l1m"
	case n <= 8<<20:
		return "l8m"
	}
	return "lmax"
}

var sample = Text{Customer: "Ada Rossi", Refs: []string{"ORD-SYN-0042", "CUS-SYN-0007"}, Date: time.Date(2026, 10, 27, 9, 0, 0, 0, time.UTC)}

func TestEveryKindIsValidAndRecognized(t *testing.T) {
	for _, k := range Kinds {
		b, err := Generate(k, "", sample)
		if err != nil {
			t.Fatalf("%s: %v", k, err)
		}
		if got := detect(b); got != k {
			t.Fatalf("%s: recognized as %q", k, got)
		}
		switch k {
		case "png":
			if _, err := png.Decode(bytes.NewReader(b)); err != nil {
				t.Fatalf("png: %v", err)
			}
		case "jpeg":
			if _, err := jpeg.Decode(bytes.NewReader(b)); err != nil {
				t.Fatalf("jpeg: %v", err)
			}
		case "gif":
			if _, err := gif.Decode(bytes.NewReader(b)); err != nil {
				t.Fatalf("gif: %v", err)
			}
		case "docx", "xlsx", "pptx", "zip":
			zr, err := zip.NewReader(bytes.NewReader(b), int64(len(b)))
			if err != nil {
				t.Fatalf("%s: %v", k, err)
			}
			text := ""
			for _, f := range zr.File {
				rc, err := f.Open()
				if err != nil {
					t.Fatal(err)
				}
				var buf bytes.Buffer
				_, _ = buf.ReadFrom(rc)
				rc.Close()
				text += buf.String()
			}
			if k != "pptx" && !strings.Contains(text, "ORD-SYN-0042") {
				t.Fatalf("%s: text not found", k)
			}
		case "pdf":
			checkPDF(t, b)
		}
		if MediaType(k) == "" || KindOfMedia(MediaType(k)) != k {
			t.Fatalf("%s: media type round trip", k)
		}
	}
}

func checkPDF(t *testing.T, b []byte) {
	t.Helper()
	s := string(b)
	if !strings.HasSuffix(s, "%%EOF\n") {
		t.Fatal("pdf: no EOF marker")
	}
	m := regexp.MustCompile(`startxref\n(\d+)\n`).FindStringSubmatch(s)
	if m == nil {
		t.Fatal("pdf: no startxref")
	}
	x, _ := strconv.Atoi(m[1])
	if !strings.HasPrefix(s[x:], "xref\n0 7\n") {
		t.Fatalf("pdf: startxref does not point at xref: %q", s[x:x+10])
	}
	entries := regexp.MustCompile(`(\d{10}) 00000 n `).FindAllStringSubmatch(s[x:], -1)
	if len(entries) != 6 {
		t.Fatalf("pdf: %d xref entries", len(entries))
	}
	for i, e := range entries {
		off, _ := strconv.Atoi(e[1])
		if !strings.HasPrefix(s[off:], strconv.Itoa(i+1)+" 0 obj") {
			t.Fatalf("pdf: object %d offset wrong", i+1)
		}
	}
	li := regexp.MustCompile(`/Length (\d+) >>\nstream\n`).FindStringSubmatchIndex(s)
	n, _ := strconv.Atoi(s[li[2]:li[3]])
	if !strings.HasPrefix(s[li[1]+n:], "endstream") {
		t.Fatal("pdf: stream length wrong")
	}
	for _, want := range []string{"(Customer: Ada Rossi) Tj", "(Reference: ORD-SYN-0042) Tj", "(Date: 2026-10-27) Tj"} {
		if !strings.Contains(s, want) {
			t.Fatalf("pdf: missing %q", want)
		}
	}
}

func TestSizeClasses(t *testing.T) {
	for _, k := range []string{"pdf", "png", "jpeg", "gif", "docx", "xlsx", "zip"} {
		for _, c := range []string{"l1k", "l16k", "l128k", "l1m"} {
			b, err := Generate(k, c, sample)
			if err != nil {
				t.Fatal(err)
			}
			if got := classOf(len(b)); got != c && !(c == "l1k" && (k == "docx" || k == "xlsx")) {
				t.Fatalf("%s %s: %d bytes is %s", k, c, len(b), got)
			}
			if detect(b) != k {
				t.Fatalf("%s %s: not recognized", k, c)
			}
			if k == "pdf" {
				checkPDF(t, b)
			}
			if k == "png" {
				if _, err := png.Decode(bytes.NewReader(b)); err != nil {
					t.Fatalf("png %s: %v", c, err)
				}
			}
			if k == "jpeg" {
				if _, err := jpeg.Decode(bytes.NewReader(b)); err != nil {
					t.Fatalf("jpeg %s: %v", c, err)
				}
			}
			if k == "gif" {
				if _, err := gif.Decode(bytes.NewReader(b)); err != nil {
					t.Fatalf("gif %s: %v", c, err)
				}
			}
			if k == "docx" || k == "zip" || k == "xlsx" {
				if _, err := zip.NewReader(bytes.NewReader(b), int64(len(b))); err != nil {
					t.Fatalf("%s %s: %v", k, c, err)
				}
			}
		}
	}
	if b, _ := Generate("pdf", "lmax", sample); len(b) > MaxBytes+1024 {
		t.Fatalf("lmax not capped: %d", len(b))
	}
}

func TestLinesAreASCIIAndDeterministic(t *testing.T) {
	l := Lines(Text{Customer: "Zoë Ünal", Refs: []string{"B", "A", "A"}})
	if l[2] != "Customer: Zo? ?nal" || l[3] != "Reference: A" || l[4] != "Reference: B" || len(l) != 5 {
		t.Fatalf("%q", l)
	}
	a, _ := Generate("docx", "l16k", sample)
	b, _ := Generate("docx", "l16k", sample)
	if !bytes.Equal(a, b) {
		t.Fatal("not deterministic")
	}
}
