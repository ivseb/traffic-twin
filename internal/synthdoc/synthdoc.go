// Package synthdoc generates small, valid synthetic documents (PDF, images,
// ZIP and Office Open XML packages) for the mock (docs/spec/mock.md 2.9).
//
// The documents carry only synthetic text: the lines of Lines, built from a
// fixed product template and the synthetic values of the world (customer
// name, object ids, the virtual date). Nothing is read from traffic. The
// generators use the standard library only.
package synthdoc

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"image"
	"image/color"
	"image/gif"
	"image/jpeg"
	"image/png"
	"sort"
	"strings"
	"time"
)

// Kinds are the document types of the sanitizer shapes drop:doc:<type>:<class>
// (docs/spec/sanitizer.md 22.4) that the mock can generate.
var Kinds = []string{"pdf", "png", "jpeg", "gif", "webp", "ole", "docx", "xlsx", "pptx", "zip"}

var mediaOf = map[string]string{
	"pdf":  "application/pdf",
	"png":  "image/png",
	"jpeg": "image/jpeg",
	"gif":  "image/gif",
	"webp": "image/webp",
	"ole":  "application/x-ole-storage",
	"docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
	"xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
	"pptx": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
	"zip":  "application/zip",
}

var extOf = map[string]string{"jpeg": "jpg", "ole": "doc"}

// kindOfMedia maps media types (lower case, without parameters) to a kind.
var kindOfMedia = map[string]string{
	"application/x-pdf":            "pdf",
	"image/jpg":                    "jpeg",
	"image/pjpeg":                  "jpeg",
	"application/x-zip-compressed": "zip",
	"application/msword":           "ole",
	"application/vnd.ms-excel":     "ole",
}

func init() {
	for k, mt := range mediaOf {
		kindOfMedia[mt] = k
	}
}

// Known reports whether kind is a document type the package generates.
func Known(kind string) bool { _, ok := mediaOf[kind]; return ok }

// MediaType is the media type of a kind ("" when unknown).
func MediaType(kind string) string { return mediaOf[kind] }

// Ext is the file name extension of a kind.
func Ext(kind string) string {
	if e, ok := extOf[kind]; ok {
		return e
	}
	return kind
}

// KindOfMedia returns the kind of a media type ("application/pdf;
// charset=x" -> "pdf"), "" when it is not a document type.
func KindOfMedia(mt string) string {
	mt = strings.ToLower(strings.TrimSpace(strings.SplitN(mt, ";", 2)[0]))
	return kindOfMedia[mt]
}

// Size classes of the documents (docs/spec/sanitizer.md 22.4): the upper
// bound of each class in bytes (lmax has none).
var classMax = map[string]int{"l1k": 1024, "l16k": 16384, "l128k": 131072, "l1m": 1 << 20, "l8m": 8 << 20}

// MaxBytes caps the size a class asks for: a document of class lmax (or l8m)
// comes out at most this large (docs/spec/mock.md 2.9, known limit).
const MaxBytes = 2 << 20

// TargetSize is the size a generated document aims at for a class: just over
// the lower bound of the class, so the document falls in it; 0 (no padding)
// for an unknown class or l1k.
func TargetSize(class string) int {
	order := []string{"l1k", "l16k", "l128k", "l1m", "l8m", "lmax"}
	for i, c := range order {
		if c != class {
			continue
		}
		if i == 0 {
			return 0
		}
		t := classMax[order[i-1]] + 1
		if t > MaxBytes {
			t = MaxBytes
		}
		return t
	}
	return 0
}

// Text is the synthetic content of a document.
type Text struct {
	// Customer is the synthetic customer name (world profile), "" if none.
	Customer string
	// Refs are synthetic object ids (the id of the request path, the
	// created object, the session customer id).
	Refs []string
	// Date is the virtual clock of the mock.
	Date time.Time
}

// Lines are the text lines of a document: a fixed template plus the
// synthetic values of t, ASCII only (other characters become '?').
func Lines(t Text) []string {
	out := []string{"Synthetic document - traffic-twin", "Test data only: no real person or object."}
	if t.Customer != "" {
		out = append(out, "Customer: "+t.Customer)
	}
	refs := append([]string(nil), t.Refs...)
	sort.Strings(refs)
	seen := map[string]bool{}
	for _, r := range refs {
		if r == "" || seen[r] || len(seen) >= 8 {
			continue
		}
		seen[r] = true
		out = append(out, "Reference: "+r)
	}
	if !t.Date.IsZero() {
		out = append(out, "Date: "+t.Date.UTC().Format("2006-01-02"))
	}
	for i, l := range out {
		out[i] = ascii(l)
	}
	return out
}

// Values are the inserted (non-template) strings of t, for the gate.
func Values(t Text) []string {
	var out []string
	if t.Customer != "" {
		out = append(out, t.Customer)
	}
	for _, r := range t.Refs {
		if r != "" {
			out = append(out, r)
		}
	}
	return out
}

func ascii(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= 0x20 && r < 0x7f {
			b.WriteRune(r)
		} else {
			b.WriteByte('?')
		}
	}
	if b.Len() > 120 {
		return b.String()[:120]
	}
	return b.String()
}

// Generate builds a valid document of kind with the text of t, padded to the
// size class when one is given ("" = as small as possible).
func Generate(kind, class string, t Text) ([]byte, error) {
	lines := Lines(t)
	target := TargetSize(class)
	switch kind {
	case "pdf":
		return pdf(lines, target), nil
	case "png":
		return pngDoc(lines, target)
	case "jpeg":
		return jpegDoc(lines, target)
	case "gif":
		return gifDoc(lines, target)
	case "webp":
		return append([]byte(nil), webp1x1...), nil
	case "ole":
		return ole(), nil
	case "docx", "xlsx", "pptx", "zip":
		return ooxml(kind, lines, target)
	}
	return nil, fmt.Errorf("synthdoc: unknown document type %q", kind)
}

// ---- PDF ----

func pdfEscape(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `(`, `\(`, `)`, `\)`)
	return r.Replace(s)
}

// pdf writes a one-page PDF 1.4 with the lines in Helvetica and a correct
// cross-reference table.
func pdf(lines []string, target int) []byte {
	var content strings.Builder
	content.WriteString("BT /F1 12 Tf 16 TL 72 770 Td\n")
	for i, l := range lines {
		if i > 0 {
			content.WriteString("T* ")
		}
		fmt.Fprintf(&content, "(%s) Tj\n", pdfEscape(l))
	}
	content.WriteString("ET\n")
	objs := []string{
		"<< /Type /Catalog /Pages 2 0 R >>",
		"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
		"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>",
		"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>",
		fmt.Sprintf("<< /Length %d >>\nstream\n%sendstream", content.Len(), content.String()),
		"<< /Producer (traffic-twin synthetic) /Title (Synthetic document) >>",
	}
	var b bytes.Buffer
	b.WriteString("%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
	offs := make([]int, len(objs))
	for i, o := range objs {
		offs[i] = b.Len()
		fmt.Fprintf(&b, "%d 0 obj\n%s\nendobj\n", i+1, o)
	}
	// padding: comment lines, allowed wherever white space is
	tail := 64 + 20*(len(objs)+1)
	for b.Len()+tail < target {
		n := target - b.Len() - tail
		if n > 120 {
			n = 120
		}
		if n < 2 {
			n = 2
		}
		b.WriteString("%" + strings.Repeat("0", n-2) + "\n")
	}
	xref := b.Len()
	fmt.Fprintf(&b, "xref\n0 %d\n0000000000 65535 f \n", len(objs)+1)
	for _, o := range offs {
		fmt.Fprintf(&b, "%010d 00000 n \n", o)
	}
	fmt.Fprintf(&b, "trailer\n<< /Size %d /Root 1 0 R /Info 6 0 R >>\nstartxref\n%d\n%%%%EOF\n", len(objs)+1, xref)
	return b.Bytes()
}

// ---- images ----

// placeholder is a light image with a frame and one dark bar per text line:
// a recognizable placeholder, not rendered text.
func placeholder(lines []string, w, h int) *image.RGBA {
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	bg := color.RGBA{0xf2, 0xf4, 0xf7, 0xff}
	fg := color.RGBA{0x5b, 0x6b, 0x82, 0xff}
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			c := bg
			if x < 2 || y < 2 || x >= w-2 || y >= h-2 {
				c = fg
			}
			img.SetRGBA(x, y, c)
		}
	}
	for i, l := range lines {
		y0 := h/10 + i*(h/10)
		if y0+h/24+1 >= h-4 {
			break
		}
		bw := (8 + len(l)*2) * w / 160
		if bw > w-w/6 {
			bw = w - w/6
		}
		for y := y0; y < y0+h/24+1; y++ {
			for x := w / 12; x < w/12+bw; x++ {
				img.SetRGBA(x, y, fg)
			}
		}
	}
	return img
}

func pngDoc(lines []string, target int) ([]byte, error) {
	var b bytes.Buffer
	if err := png.Encode(&b, placeholder(lines, 160, 120)); err != nil {
		return nil, err
	}
	out := b.Bytes()
	// text chunks before IEND (the last 12 bytes): the lines, then padding
	iend := out[len(out)-12:]
	body := append([]byte(nil), out[:len(out)-12]...)
	text := "Comment\x00" + strings.Join(lines, "\n")
	body = appendChunk(body, "tEXt", []byte(text))
	if pad := target - len(body) - 12 - 12 - len("Comment\x00"); pad > 0 {
		body = appendChunk(body, "tEXt", append([]byte("Comment\x00"), bytes.Repeat([]byte{'0'}, pad)...))
	}
	return append(body, iend...), nil
}

func appendChunk(dst []byte, typ string, data []byte) []byte {
	var l [4]byte
	binary.BigEndian.PutUint32(l[:], uint32(len(data)))
	dst = append(dst, l[:]...)
	start := len(dst)
	dst = append(dst, typ...)
	dst = append(dst, data...)
	var c [4]byte
	binary.BigEndian.PutUint32(c[:], crc32.ChecksumIEEE(dst[start:]))
	return append(dst, c[:]...)
}

func jpegDoc(lines []string, target int) ([]byte, error) {
	var b bytes.Buffer
	if err := jpeg.Encode(&b, placeholder(lines, 24, 16), &jpeg.Options{Quality: 40}); err != nil {
		return nil, err
	}
	enc := b.Bytes()
	// COM segments right after SOI: the lines, then padding
	out := append([]byte(nil), enc[:2]...)
	out = appendCOM(out, []byte(strings.Join(lines, "\n")))
	for len(out)+len(enc)-2 < target {
		n := target - len(out) - (len(enc) - 2) - 4
		if n > 65000 {
			n = 65000
		}
		if n < 1 {
			n = 1
		}
		out = appendCOM(out, bytes.Repeat([]byte{'0'}, n))
	}
	return append(out, enc[2:]...), nil
}

func appendCOM(dst, data []byte) []byte {
	dst = append(dst, 0xff, 0xfe)
	var l [2]byte
	binary.BigEndian.PutUint16(l[:], uint16(len(data)+2))
	dst = append(dst, l[:]...)
	return append(dst, data...)
}

func gifDoc(lines []string, target int) ([]byte, error) {
	src := placeholder(lines, 160, 120)
	pal := image.NewPaletted(src.Bounds(), color.Palette{color.RGBA{0xf2, 0xf4, 0xf7, 0xff}, color.RGBA{0x5b, 0x6b, 0x82, 0xff}})
	for y := src.Bounds().Min.Y; y < src.Bounds().Max.Y; y++ {
		for x := src.Bounds().Min.X; x < src.Bounds().Max.X; x++ {
			pal.Set(x, y, src.At(x, y))
		}
	}
	var b bytes.Buffer
	if err := gif.Encode(&b, pal, nil); err != nil {
		return nil, err
	}
	enc := b.Bytes()
	out := append([]byte(nil), enc[:len(enc)-1]...) // without the trailer 0x3B
	out = appendGIFComment(out, []byte(strings.Join(lines, "\n")))
	for len(out)+1 < target {
		n := target - len(out) - 1
		if n > 60000 {
			n = 60000
		}
		out = appendGIFComment(out, bytes.Repeat([]byte{'0'}, n))
	}
	return append(out, 0x3b), nil
}

func appendGIFComment(dst, data []byte) []byte {
	dst = append(dst, 0x21, 0xfe)
	for len(data) > 0 {
		n := min(len(data), 255)
		dst = append(dst, byte(n))
		dst = append(dst, data[:n]...)
		data = data[n:]
	}
	return append(dst, 0)
}

// webp1x1 is a 1x1 lossless WebP (VP8L). WebP documents are not padded to
// their class (known limit).
var webp1x1 = []byte{
	'R', 'I', 'F', 'F', 0x1a, 0, 0, 0, 'W', 'E', 'B', 'P', 'V', 'P', '8', 'L',
	0x0d, 0, 0, 0, 0x2f, 0, 0, 0, 0x10, 0x07, 0x10, 0x11, 0x11, 0x88, 0x88, 0xfe, 0x07, 0,
}

// ole is the header sector of an empty compound file: the signature of the
// old Office formats, not a document Office can open (known limit).
func ole() []byte {
	b := make([]byte, 512)
	copy(b, []byte{0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1})
	binary.LittleEndian.PutUint16(b[24:], 0x003e) // minor version
	binary.LittleEndian.PutUint16(b[26:], 0x0003) // major version 3
	binary.LittleEndian.PutUint16(b[28:], 0xfffe) // byte order
	binary.LittleEndian.PutUint16(b[30:], 0x0009) // sector shift
	binary.LittleEndian.PutUint16(b[32:], 0x0006) // mini sector shift
	binary.LittleEndian.PutUint32(b[48:], 0xfffffffe)
	binary.LittleEndian.PutUint32(b[56:], 0x1000)
	binary.LittleEndian.PutUint32(b[60:], 0xfffffffe)
	binary.LittleEndian.PutUint32(b[68:], 0xfffffffe)
	for i := 76; i < 512; i += 4 {
		binary.LittleEndian.PutUint32(b[i:], 0xffffffff)
	}
	return b
}

// ---- ZIP and Office Open XML ----

func xmlEscape(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;").Replace(s)
}

const xmlHead = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` + "\n"

func ooxml(kind string, lines []string, target int) ([]byte, error) {
	var files [][2]string
	ct := func(over string) string {
		return xmlHead + `<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">` +
			`<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>` +
			`<Default Extension="xml" ContentType="application/xml"/>` +
			`<Default Extension="txt" ContentType="text/plain"/>` + over + `</Types>`
	}
	rels := func(typ, target string) string {
		return xmlHead + `<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">` +
			`<Relationship Id="rId1" Type="` + typ + `" Target="` + target + `"/></Relationships>`
	}
	const officeDoc = "http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument"
	switch kind {
	case "docx":
		var body strings.Builder
		for _, l := range lines {
			body.WriteString(`<w:p><w:r><w:t xml:space="preserve">` + xmlEscape(l) + `</w:t></w:r></w:p>`)
		}
		files = [][2]string{
			{"[Content_Types].xml", ct(`<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>`)},
			{"_rels/.rels", rels(officeDoc, "word/document.xml")},
			{"word/document.xml", xmlHead + `<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body>` + body.String() + `</w:body></w:document>`},
		}
	case "xlsx":
		var rows strings.Builder
		for i, l := range lines {
			fmt.Fprintf(&rows, `<row r="%d"><c r="A%d" t="inlineStr"><is><t>%s</t></is></c></row>`, i+1, i+1, xmlEscape(l))
		}
		files = [][2]string{
			{"[Content_Types].xml", ct(`<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>` +
				`<Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>`)},
			{"_rels/.rels", rels(officeDoc, "xl/workbook.xml")},
			{"xl/workbook.xml", xmlHead + `<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets><sheet name="Sheet1" sheetId="1" r:id="rId1"/></sheets></workbook>`},
			{"xl/_rels/workbook.xml.rels", rels("http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet", "worksheets/sheet1.xml")},
			{"xl/worksheets/sheet1.xml", xmlHead + `<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData>` + rows.String() + `</sheetData></worksheet>`},
		}
	case "pptx":
		// Recognizable package with the text as a part; not a presentation
		// PowerPoint opens (known limit: no slide master or theme).
		files = [][2]string{
			{"[Content_Types].xml", ct(`<Override PartName="/ppt/presentation.xml" ContentType="application/vnd.openxmlformats-officedocument.presentationml.presentation.main+xml"/>`)},
			{"_rels/.rels", rels(officeDoc, "ppt/presentation.xml")},
			{"ppt/presentation.xml", xmlHead + `<p:presentation xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main"/>`},
			{"docProps/synthetic.txt", strings.Join(lines, "\n") + "\n"},
		}
	default: // zip
		files = [][2]string{{"synthetic.txt", strings.Join(lines, "\n") + "\n"}}
	}
	write := func(pad int) ([]byte, error) {
		var b bytes.Buffer
		zw := zip.NewWriter(&b)
		all := files
		if pad > 0 {
			name := "padding.txt"
			if kind != "zip" {
				name = "docProps/padding.txt"
			}
			all = append(append([][2]string(nil), files...), [2]string{name, strings.Repeat("0", pad)})
		}
		for i, f := range all {
			// fixed times keep the bytes deterministic; the padding is stored
			method := zip.Deflate
			if i >= len(files) {
				method = zip.Store
			}
			w, err := zw.CreateHeader(&zip.FileHeader{Name: f[0], Method: method})
			if err != nil {
				return nil, err
			}
			if _, err := w.Write([]byte(f[1])); err != nil {
				return nil, err
			}
		}
		if err := zw.Close(); err != nil {
			return nil, err
		}
		return b.Bytes(), nil
	}
	out, err := write(0)
	if err != nil || len(out) >= target {
		return out, err
	}
	// the padding entry costs two headers and its name: aim, then correct
	pad := max(1, target-len(out)-2*(46+len("docProps/padding.txt")))
	for i := 0; i < 3; i++ {
		if out, err = write(pad); err != nil || len(out) >= target {
			return out, err
		}
		pad += target - len(out)
	}
	return out, nil
}
