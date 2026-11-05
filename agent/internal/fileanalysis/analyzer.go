// Package fileanalysis performs bounded, read-only inspection of an explicitly
// approved local file. It never executes, mounts, extracts, uploads, deletes,
// or quarantines the target.
package fileanalysis

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"debug/pe"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	pathpkg "path"
	"path/filepath"
	"sort"
	"strings"
)

const (
	ConfirmedDetection  = "CONFIRMED_DETECTION"
	SuspiciousIndicator = "SUSPICIOUS_INDICATOR"
	Inconclusive        = "INCONCLUSIVE"
	NoFindingsObserved  = "NO_FINDINGS_OBSERVED"
	Unsupported         = "UNSUPPORTED"
)

type Limits struct {
	MaxFileBytes                int64
	MaxArchiveEntries           int
	MaxArchiveUncompressedBytes uint64
	MaxCompressionRatio         float64
}

func DefaultLimits() Limits {
	return Limits{128 << 20, 512, 512 << 20, 200}
}

type HashIntelligence struct {
	Label      string `json:"label"`
	Severity   string `json:"severity"`
	Source     string `json:"source"`
	Confidence string `json:"confidence"`
}

type PatternRule struct {
	ID          string `json:"id"`
	Description string `json:"description"`
	Pattern     string `json:"pattern"`
	Severity    string `json:"severity"`
}

type Options struct {
	ApprovedRoot     string
	Limits           Limits
	HashIntelligence map[string]HashIntelligence
	Patterns         []PatternRule
}

type Indicator struct {
	ID             string `json:"id"`
	Classification string `json:"classification"`
	Severity       string `json:"severity"`
	Evidence       string `json:"evidence"`
}

type ArchiveEntry struct {
	Name              string `json:"name"`
	CompressedBytes   uint64 `json:"compressedBytes"`
	UncompressedBytes uint64 `json:"uncompressedBytes"`
	Encrypted         bool   `json:"encrypted"`
	HighRiskType      bool   `json:"highRiskType"`
}

type ArchiveSummary struct {
	EntryCount             int            `json:"entryCount"`
	Entries                []ArchiveEntry `json:"entries"`
	EncryptedEntryCount    int            `json:"encryptedEntryCount"`
	NestedArchiveCount     int            `json:"nestedArchiveCount"`
	HighRiskEntryCount     int            `json:"highRiskEntryCount"`
	TotalCompressedBytes   uint64         `json:"totalCompressedBytes"`
	TotalUncompressedBytes uint64         `json:"totalUncompressedBytes"`
	InspectionTruncated    bool           `json:"inspectionTruncated"`
}

type Result struct {
	FileName          string          `json:"fileName"`
	SizeBytes         int64           `json:"sizeBytes"`
	SHA256            string          `json:"sha256"`
	Extension         string          `json:"extension"`
	DetectedType      string          `json:"detectedType"`
	SignatureMetadata string          `json:"signatureMetadata"`
	Classification    string          `json:"classification"`
	Indicators        []Indicator     `json:"indicators"`
	Archive           *ArchiveSummary `json:"archive,omitempty"`
	Limitations       []string        `json:"limitations"`
}

func Analyze(ctx context.Context, path string, opts Options) (*Result, error) {
	if opts.ApprovedRoot == "" {
		return nil, errors.New("an approved root is required")
	}
	root, err := filepath.Abs(opts.ApprovedRoot)
	if err != nil {
		return nil, fmt.Errorf("approved root: %w", err)
	}
	target, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("target path: %w", err)
	}
	realRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return nil, fmt.Errorf("resolve approved root: %w", err)
	}
	realTarget, err := filepath.EvalSymlinks(target)
	if err != nil {
		return nil, fmt.Errorf("resolve target path: %w", err)
	}
	rel, err := filepath.Rel(realRoot, realTarget)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) || filepath.IsAbs(rel) {
		return nil, errors.New("target is outside the approved root")
	}
	info, err := os.Lstat(target)
	if err != nil {
		return nil, fmt.Errorf("inspect target: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("target must be a regular file")
	}
	limits := opts.Limits
	defaults := DefaultLimits()
	if limits.MaxFileBytes <= 0 {
		limits.MaxFileBytes = defaults.MaxFileBytes
	}
	if limits.MaxArchiveEntries <= 0 {
		limits.MaxArchiveEntries = defaults.MaxArchiveEntries
	}
	if limits.MaxArchiveUncompressedBytes <= 0 {
		limits.MaxArchiveUncompressedBytes = defaults.MaxArchiveUncompressedBytes
	}
	if limits.MaxCompressionRatio <= 0 {
		limits.MaxCompressionRatio = defaults.MaxCompressionRatio
	}
	if info.Size() > limits.MaxFileBytes {
		return nil, fmt.Errorf("file exceeds the %d-byte inspection limit", limits.MaxFileBytes)
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	f, err := os.Open(target)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, &contextReader{ctx: ctx, r: io.LimitReader(f, limits.MaxFileBytes+1)}); err != nil {
		return nil, err
	}
	hash := hex.EncodeToString(h.Sum(nil))
	head := make([]byte, 64*1024)
	n, err := f.ReadAt(head, 0)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	head = head[:n]
	ext := strings.ToLower(filepath.Ext(target))
	typ := detectType(f, head, ext)
	r := &Result{FileName: filepath.Base(target), SizeBytes: info.Size(), SHA256: hash, Extension: ext, DetectedType: typ, SignatureMetadata: "NOT_APPLICABLE", Classification: NoFindingsObserved, Indicators: []Indicator{}, Limitations: []string{"No result proves a file is safe; only observed evidence is reported."}}

	if mismatch(ext, typ) {
		r.add("EXTENSION_CONTENT_MISMATCH", SuspiciousIndicator, "HIGH", fmt.Sprintf("Extension %q does not match detected content type %s.", ext, typ))
	}
	if doubleExtension(filepath.Base(target)) {
		r.add("DOUBLE_EXTENSION", SuspiciousIndicator, "HIGH", "Filename uses a document/image lure extension before a high-risk executable or script extension.")
	}
	if intel, ok := opts.HashIntelligence[hash]; ok {
		classification := ConfirmedDetection
		if !strings.EqualFold(intel.Confidence, "CONFIRMED") {
			classification = SuspiciousIndicator
		}
		r.add("HASH_INTELLIGENCE_MATCH", classification, defaultString(intel.Severity, "HIGH"), fmt.Sprintf("SHA-256 matched %s from %s (confidence %s).", intel.Label, defaultString(intel.Source, "approved local feed"), defaultString(intel.Confidence, "UNKNOWN")))
	}
	for _, rule := range matchPatterns(head, opts.Patterns) {
		r.add("OFFLINE_RULE_"+rule.ID, SuspiciousIndicator, defaultString(rule.Severity, "MEDIUM"), rule.Description)
	}
	if len(opts.Patterns) > 0 {
		r.Limitations = append(r.Limitations, "Offline literal rules inspect only the first 64 KiB; they are not a full YARA engine.")
	}

	switch typ {
	case "ZIP":
		a, indicators, limitations := inspectZIP(target, limits)
		r.Archive = a
		r.Indicators = append(r.Indicators, indicators...)
		r.Limitations = append(r.Limitations, limitations...)
	case "ISO9660":
		r.Classification = maxClass(r.Classification, Inconclusive)
		r.Limitations = append(r.Limitations, "ISO image detected but not mounted or traversed; only container metadata was inspected.")
	case "PE_EXECUTABLE", "PE_DLL":
		r.SignatureMetadata = peSignatureMetadata(target)
		if r.SignatureMetadata == "NOT_PRESENT" {
			r.add("PE_SIGNATURE_ABSENT", SuspiciousIndicator, "MEDIUM", "PE certificate table is absent; this is not proof of malware.")
		}
	case "MSI_OLE":
		r.SignatureMetadata = "UNSUPPORTED"
		r.Limitations = append(r.Limitations, "MSI Authenticode validation is not implemented; no installer content was executed.")
	}
	for _, i := range r.Indicators {
		r.Classification = maxClass(r.Classification, i.Classification)
	}
	return r, nil
}

func (r *Result) add(id, classification, severity, evidence string) {
	r.Indicators = append(r.Indicators, Indicator{id, classification, severity, evidence})
}

func detectType(f *os.File, head []byte, ext string) string {
	if len(head) >= 4 && head[0] == 'P' && head[1] == 'K' && ((head[2] == 3 && head[3] == 4) || (head[2] == 5 && head[3] == 6) || (head[2] == 7 && head[3] == 8)) {
		return "ZIP"
	}
	if len(head) >= 8 && bytes.Equal(head[:8], []byte{0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1}) {
		if ext == ".msi" {
			return "MSI_OLE"
		}
		return "OLE_COMPOUND"
	}
	if len(head) >= 20 && bytes.Equal(head[:20], []byte{0x4c, 0, 0, 0, 1, 0x14, 2, 0, 0, 0, 0, 0, 0xc0, 0, 0, 0, 0, 0, 0, 0x46}) {
		return "WINDOWS_LNK"
	}
	if len(head) >= 2 && head[0] == 'M' && head[1] == 'Z' {
		if pf, err := pe.NewFile(f); err == nil {
			defer pf.Close()
			if pf.FileHeader.Characteristics&0x2000 != 0 {
				return "PE_DLL"
			}
		}
		return "PE_EXECUTABLE"
	}
	iso := make([]byte, 5)
	if _, err := f.ReadAt(iso, 0x8001); err == nil && string(iso) == "CD001" {
		return "ISO9660"
	}
	if len(head) >= 4 && string(head[:4]) == "%PDF" {
		return "PDF"
	}
	if len(head) >= 5 && string(head[:5]) == "{\\rtf" {
		return "RTF"
	}
	if len(head) >= 2 && string(head[:2]) == "#!" {
		return "SCRIPT"
	}
	if isScriptExt(ext) {
		return "SCRIPT"
	}
	return "UNKNOWN"
}

func mismatch(ext, typ string) bool {
	expected := map[string][]string{"ZIP": {".zip", ".docx", ".xlsx", ".pptx", ".jar", ".apk", ".odt", ".ods", ".epub"}, "ISO9660": {".iso"}, "PE_EXECUTABLE": {".exe", ".scr", ".com"}, "PE_DLL": {".dll", ".ocx", ".cpl"}, "MSI_OLE": {".msi"}, "WINDOWS_LNK": {".lnk"}, "PDF": {".pdf"}, "RTF": {".rtf"}}
	allowed, ok := expected[typ]
	if !ok {
		return false
	}
	for _, x := range allowed {
		if ext == x {
			return false
		}
	}
	return true
}

func doubleExtension(name string) bool {
	parts := strings.Split(strings.ToLower(name), ".")
	if len(parts) < 3 {
		return false
	}
	lure := map[string]bool{"pdf": true, "doc": true, "docx": true, "xls": true, "xlsx": true, "jpg": true, "jpeg": true, "png": true, "txt": true, "invoice": true}
	high := map[string]bool{"exe": true, "dll": true, "msi": true, "lnk": true, "js": true, "jse": true, "vbs": true, "vbe": true, "ps1": true, "bat": true, "cmd": true, "scr": true, "iso": true}
	return lure[parts[len(parts)-2]] && high[parts[len(parts)-1]]
}

func isScriptExt(ext string) bool {
	switch ext {
	case ".ps1", ".psm1", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".sh", ".py", ".pl":
		return true
	}
	return false
}

func highRiskName(name string) bool {
	ext := strings.ToLower(filepath.Ext(name))
	return isScriptExt(ext) || ext == ".exe" || ext == ".dll" || ext == ".msi" || ext == ".lnk" || ext == ".scr" || ext == ".iso"
}

func archiveName(name string) bool {
	switch strings.ToLower(filepath.Ext(name)) {
	case ".zip", ".7z", ".rar", ".iso", ".tar", ".gz":
		return true
	}
	return false
}

func inspectZIP(path string, limits Limits) (*ArchiveSummary, []Indicator, []string) {
	z, err := zip.OpenReader(path)
	if err != nil {
		return nil, []Indicator{{"ZIP_PARSE_FAILED", Inconclusive, "MEDIUM", "ZIP metadata could not be parsed: " + err.Error()}}, nil
	}
	defer z.Close()
	a := &ArchiveSummary{Entries: []ArchiveEntry{}}
	var indicators []Indicator
	var limitations []string
	for idx, f := range z.File {
		a.EntryCount++
		a.TotalCompressedBytes += f.CompressedSize64
		a.TotalUncompressedBytes += f.UncompressedSize64
		encrypted := f.Flags&1 != 0
		if encrypted {
			a.EncryptedEntryCount++
		}
		high := highRiskName(f.Name)
		if high {
			a.HighRiskEntryCount++
		}
		if archiveName(f.Name) {
			a.NestedArchiveCount++
		}
		if idx < limits.MaxArchiveEntries {
			a.Entries = append(a.Entries, ArchiveEntry{truncate(f.Name, 300), f.CompressedSize64, f.UncompressedSize64, encrypted, high})
		} else {
			a.InspectionTruncated = true
		}
		clean := pathpkg.Clean(strings.ReplaceAll(f.Name, "\\", "/"))
		if strings.HasPrefix(clean, "../") || pathpkg.IsAbs(clean) || (len(clean) >= 2 && clean[1] == ':') {
			indicators = append(indicators, Indicator{"ARCHIVE_PATH_TRAVERSAL", SuspiciousIndicator, "HIGH", "Archive contains a path-traversal or absolute entry name."})
		}
	}
	if a.EncryptedEntryCount > 0 {
		indicators = append(indicators, Indicator{"PASSWORD_PROTECTED_ARCHIVE", Inconclusive, "MEDIUM", fmt.Sprintf("%d encrypted archive entries cannot be inspected without a password; no password bypass was attempted.", a.EncryptedEntryCount)})
		limitations = append(limitations, "Encrypted entry contents were not read.")
	}
	if a.HighRiskEntryCount > 0 {
		indicators = append(indicators, Indicator{"ARCHIVE_HIGH_RISK_CONTENT", SuspiciousIndicator, "HIGH", fmt.Sprintf("Archive metadata lists %d executable, script, shortcut, installer, or disk-image entries.", a.HighRiskEntryCount)})
	}
	if a.NestedArchiveCount > 0 {
		indicators = append(indicators, Indicator{"NESTED_ARCHIVE", SuspiciousIndicator, "MEDIUM", fmt.Sprintf("Archive metadata lists %d nested archive or disk-image entries.", a.NestedArchiveCount)})
	}
	if a.EntryCount > limits.MaxArchiveEntries || a.TotalUncompressedBytes > limits.MaxArchiveUncompressedBytes || (a.TotalCompressedBytes > 0 && float64(a.TotalUncompressedBytes)/float64(a.TotalCompressedBytes) > limits.MaxCompressionRatio) {
		a.InspectionTruncated = true
		indicators = append(indicators, Indicator{"ARCHIVE_RESOURCE_LIMIT", Inconclusive, "HIGH", "Archive metadata exceeds configured entry, expansion, or compression-ratio limits; contents were not extracted."})
	}
	return a, dedupe(indicators), limitations
}

func peSignatureMetadata(path string) string {
	f, err := pe.Open(path)
	if err != nil {
		return "UNREADABLE"
	}
	defer f.Close()
	var size uint32
	switch h := f.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		size = h.DataDirectory[4].Size
	case *pe.OptionalHeader64:
		size = h.DataDirectory[4].Size
	}
	if size > 0 {
		return "PRESENT_NOT_VALIDATED"
	}
	return "NOT_PRESENT"
}

func matchPatterns(data []byte, rules []PatternRule) []PatternRule {
	var out []PatternRule
	for _, r := range rules {
		if r.ID == "" || r.Pattern == "" || len(r.Pattern) > 128 {
			continue
		}
		if bytes.Contains(bytes.ToLower(data), bytes.ToLower([]byte(r.Pattern))) {
			out = append(out, r)
		}
	}
	return out
}

func dedupe(in []Indicator) []Indicator {
	seen := map[string]bool{}
	out := make([]Indicator, 0, len(in))
	for _, i := range in {
		if !seen[i.ID] {
			seen[i.ID] = true
			out = append(out, i)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func maxClass(a, b string) string {
	rank := map[string]int{NoFindingsObserved: 0, Unsupported: 1, Inconclusive: 2, SuspiciousIndicator: 3, ConfirmedDetection: 4}
	if rank[b] > rank[a] {
		return b
	}
	return a
}
func defaultString(v, d string) string {
	if strings.TrimSpace(v) == "" {
		return d
	}
	return v
}
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

type contextReader struct {
	ctx context.Context
	r   io.Reader
}

func (r *contextReader) Read(p []byte) (int, error) {
	select {
	case <-r.ctx.Done():
		return 0, r.ctx.Err()
	default:
		return r.r.Read(p)
	}
}
