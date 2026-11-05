package fileanalysis

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func TestAnalyzeLegitimateDocumentReportsNoObservedFindings(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "notes.txt")
	data := []byte("quarterly planning notes\n")
	if err := os.WriteFile(p, data, 0600); err != nil {
		t.Fatal(err)
	}
	r, err := Analyze(context.Background(), p, Options{ApprovedRoot: dir, Limits: DefaultLimits()})
	if err != nil {
		t.Fatal(err)
	}
	want := sha256.Sum256(data)
	if r.SHA256 != hex.EncodeToString(want[:]) {
		t.Fatalf("hash = %s", r.SHA256)
	}
	if r.Classification != NoFindingsObserved {
		t.Fatalf("classification = %s", r.Classification)
	}
	if len(r.Indicators) != 0 {
		t.Fatalf("indicators = %#v", r.Indicators)
	}
}

func TestAnalyzeRenamedExecutableAndDoubleExtension(t *testing.T) {
	dir := t.TempDir()
	double := filepath.Join(dir, "invoice.pdf.exe")
	if err := os.WriteFile(double, append([]byte("MZ"), make([]byte, 128)...), 0600); err != nil {
		t.Fatal(err)
	}
	r, err := Analyze(context.Background(), double, Options{ApprovedRoot: dir, Limits: DefaultLimits()})
	if err != nil {
		t.Fatal(err)
	}
	assertIndicator(t, r, "DOUBLE_EXTENSION")
	if r.DetectedType != "PE_EXECUTABLE" {
		t.Fatalf("type = %s", r.DetectedType)
	}
	renamed := filepath.Join(dir, "invoice.pdf")
	if err := os.WriteFile(renamed, append([]byte("MZ"), make([]byte, 128)...), 0600); err != nil {
		t.Fatal(err)
	}
	r, err = Analyze(context.Background(), renamed, Options{ApprovedRoot: dir, Limits: DefaultLimits()})
	if err != nil {
		t.Fatal(err)
	}
	assertIndicator(t, r, "EXTENSION_CONTENT_MISMATCH")
}

func TestAnalyzeZIPMetadataWithoutExtraction(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "invoice.zip")
	f, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(f)
	for name, content := range map[string]string{"invoice.pdf": "harmless", "nested/payload.exe": "MZ", "more/archive.zip": "PK"} {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	r, err := Analyze(context.Background(), p, Options{ApprovedRoot: dir, Limits: DefaultLimits()})
	if err != nil {
		t.Fatal(err)
	}
	if r.Archive == nil || r.Archive.EntryCount != 3 {
		t.Fatalf("archive = %#v", r.Archive)
	}
	assertIndicator(t, r, "ARCHIVE_HIGH_RISK_CONTENT")
	assertIndicator(t, r, "NESTED_ARCHIVE")
}

func TestAnalyzeBoundedNestedZIP(t *testing.T) {
	dir := t.TempDir()
	var nested bytes.Buffer
	nestedWriter := zip.NewWriter(&nested)
	w, _ := nestedWriter.Create("payload.exe")
	_, _ = w.Write([]byte("MZ harmless fixture"))
	_ = nestedWriter.Close()
	p := filepath.Join(dir, "outer.zip")
	f, _ := os.Create(p)
	outer := zip.NewWriter(f)
	entry, _ := outer.Create("nested.zip")
	_, _ = entry.Write(nested.Bytes())
	_ = outer.Close()
	_ = f.Close()
	r, err := Analyze(context.Background(), p, Options{ApprovedRoot: dir, Limits: DefaultLimits()})
	if err != nil {
		t.Fatal(err)
	}
	if r.Archive == nil || r.Archive.NestedInspectedCount != 1 {
		t.Fatalf("nested inspection not recorded: %#v", r.Archive)
	}
	assertIndicator(t, r, "NESTED_ARCHIVE_HIGH_RISK_CONTENT")
}

func TestAnalyzeISO9660MetadataWithoutMounting(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "fixture.iso")
	data := make([]byte, 18*2048)
	pvd := data[16*2048 : 17*2048]
	pvd[0] = 1
	copy(pvd[1:6], "CD001")
	pvd[6] = 1
	root := pvd[156:190]
	root[0] = 34
	binary.LittleEndian.PutUint32(root[2:6], 17)
	binary.LittleEndian.PutUint32(root[10:14], 2048)
	root[25] = 2
	root[32] = 1
	dirEntry := data[17*2048:]
	name := []byte("payload.exe")
	dirEntry[0] = byte(33 + len(name))
	binary.LittleEndian.PutUint32(dirEntry[2:6], 18)
	binary.LittleEndian.PutUint32(dirEntry[10:14], 10)
	dirEntry[32] = byte(len(name))
	copy(dirEntry[33:], name)
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
	r, err := Analyze(context.Background(), p, Options{ApprovedRoot: dir, Limits: DefaultLimits()})
	if err != nil {
		t.Fatal(err)
	}
	if r.Archive == nil || r.Archive.EntryCount != 1 {
		t.Fatalf("ISO metadata not parsed: %#v", r.Archive)
	}
	assertIndicator(t, r, "ISO_HIGH_RISK_CONTENT")
}

func TestOfficeOpenXMLContainerIsNotAnExtensionMismatch(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "legitimate.docx")
	writeZIP(t, p, map[string]string{"[Content_Types].xml": "<Types />", "word/document.xml": "<document />"})
	r, err := Analyze(context.Background(), p, Options{ApprovedRoot: dir, Limits: DefaultLimits()})
	if err != nil {
		t.Fatal(err)
	}
	for _, indicator := range r.Indicators {
		if indicator.ID == "EXTENSION_CONTENT_MISMATCH" {
			t.Fatalf("legitimate OOXML flagged: %#v", r.Indicators)
		}
	}
}

func TestArchiveTraversalNameIsReportedWithoutExtraction(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "traversal.zip")
	writeZIP(t, p, map[string]string{"../outside.txt": "harmless fixture"})
	r, err := Analyze(context.Background(), p, Options{ApprovedRoot: dir, Limits: DefaultLimits()})
	if err != nil {
		t.Fatal(err)
	}
	assertIndicator(t, r, "ARCHIVE_PATH_TRAVERSAL")
}

func TestAnalyzePasswordProtectedZIPReportsInconclusive(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "protected.zip")
	writeZIP(t, p, map[string]string{"invoice.pdf": "synthetic harmless content"})
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i+10 < len(b); i++ {
		switch binary.LittleEndian.Uint32(b[i : i+4]) {
		case 0x04034b50:
			binary.LittleEndian.PutUint16(b[i+6:i+8], binary.LittleEndian.Uint16(b[i+6:i+8])|1)
		case 0x02014b50:
			binary.LittleEndian.PutUint16(b[i+8:i+10], binary.LittleEndian.Uint16(b[i+8:i+10])|1)
		}
	}
	if err := os.WriteFile(p, b, 0600); err != nil {
		t.Fatal(err)
	}
	r, err := Analyze(context.Background(), p, Options{ApprovedRoot: dir, Limits: DefaultLimits()})
	if err != nil {
		t.Fatal(err)
	}
	assertIndicator(t, r, "PASSWORD_PROTECTED_ARCHIVE")
	if r.Archive == nil || r.Archive.EncryptedEntryCount != 1 {
		t.Fatalf("archive = %#v", r.Archive)
	}
}

func TestAnalyzeArchiveExpansionLimit(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "large-expansion.zip")
	writeZIP(t, p, map[string]string{"large.txt": string(make([]byte, 4096))})
	limits := DefaultLimits()
	limits.MaxArchiveUncompressedBytes = 100
	r, err := Analyze(context.Background(), p, Options{ApprovedRoot: dir, Limits: limits})
	if err != nil {
		t.Fatal(err)
	}
	assertIndicator(t, r, "ARCHIVE_RESOURCE_LIMIT")
}

func TestMagicTypesAreDetectedWithoutOpeningContent(t *testing.T) {
	dir := t.TempDir()
	fixtures := map[string]struct {
		data   []byte
		offset int64
		want   string
	}{
		"disk.iso":      {[]byte("CD001"), 0x8001, "ISO9660"},
		"shortcut.lnk":  {[]byte{0x4c, 0, 0, 0, 1, 0x14, 2, 0, 0, 0, 0, 0, 0xc0, 0, 0, 0, 0, 0, 0, 0x46}, 0, "WINDOWS_LNK"},
		"installer.msi": {[]byte{0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1}, 0, "MSI_OLE"},
		"document.pdf":  {[]byte("%PDF-1.7\n"), 0, "PDF"},
	}
	for name, fixture := range fixtures {
		t.Run(name, func(t *testing.T) {
			p := filepath.Join(dir, name)
			f, err := os.Create(p)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := f.WriteAt(fixture.data, fixture.offset); err != nil {
				t.Fatal(err)
			}
			if err := f.Close(); err != nil {
				t.Fatal(err)
			}
			r, err := Analyze(context.Background(), p, Options{ApprovedRoot: dir, Limits: DefaultLimits()})
			if err != nil {
				t.Fatal(err)
			}
			if r.DetectedType != fixture.want {
				t.Fatalf("type = %s, want %s", r.DetectedType, fixture.want)
			}
		})
	}
}

func TestAnalyzeRejectsOutsideScopeAndOversizedFiles(t *testing.T) {
	root := t.TempDir()
	outside := filepath.Join(t.TempDir(), "file.bin")
	if err := os.WriteFile(outside, []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Analyze(context.Background(), outside, Options{ApprovedRoot: root, Limits: DefaultLimits()}); err == nil {
		t.Fatal("expected scope rejection")
	}
	inside := filepath.Join(root, "large.bin")
	if err := os.WriteFile(inside, make([]byte, 32), 0600); err != nil {
		t.Fatal(err)
	}
	limits := DefaultLimits()
	limits.MaxFileBytes = 16
	if _, err := Analyze(context.Background(), inside, Options{ApprovedRoot: root, Limits: limits}); err == nil {
		t.Fatal("expected size rejection")
	}
}

func TestAnalyzeOfflineHashAndPatternIntelligence(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "sample.js")
	data := []byte("function harmless_marker() {}")
	if err := os.WriteFile(p, data, 0600); err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(data)
	hash := hex.EncodeToString(h[:])
	r, err := Analyze(context.Background(), p, Options{ApprovedRoot: dir, Limits: DefaultLimits(), HashIntelligence: map[string]HashIntelligence{hash: {Label: "synthetic test IOC", Severity: "HIGH", Source: "test fixture", Confidence: "CONFIRMED"}}, Patterns: []PatternRule{{ID: "TEST_MARKER", Description: "Synthetic marker observed", Pattern: "harmless_marker", Severity: "LOW"}}})
	if err != nil {
		t.Fatal(err)
	}
	assertIndicator(t, r, "HASH_INTELLIGENCE_MATCH")
	assertIndicator(t, r, "OFFLINE_RULE_TEST_MARKER")
	if r.Classification != ConfirmedDetection {
		t.Fatalf("classification = %s", r.Classification)
	}
}

func assertIndicator(t *testing.T, r *Result, id string) {
	t.Helper()
	for _, i := range r.Indicators {
		if i.ID == id {
			return
		}
	}
	t.Fatalf("indicator %s missing from %#v", id, r.Indicators)
}

func writeZIP(t *testing.T, path string, entries map[string]string) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(f)
	for name, content := range entries {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}
