package fileanalysis

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io/fs"
	"path/filepath"
	"strings"
	"time"
)

const DetectorVersion = "1.1.0"

type ScopeLimits struct {
	MaxFiles       int
	MaxDirectories int
	MaxDuration    time.Duration
}

func DefaultScopeLimits() ScopeLimits {
	return ScopeLimits{MaxFiles: 500, MaxDirectories: 2000, MaxDuration: 15 * time.Minute}
}

type ScopeEvidence struct {
	EvidenceKey      string  `json:"evidenceKey"`
	RelativePathHash string  `json:"relativePathHash"`
	ObservedAt       string  `json:"observedAt"`
	DetectorID       string  `json:"detectorId"`
	DetectorVersion  string  `json:"detectorVersion"`
	EvidenceSource   string  `json:"evidenceSource"`
	Confidence       string  `json:"confidence"`
	Severity         string  `json:"severity"`
	Result           *Result `json:"result"`
}

type ScopeScanResult struct {
	FilesObserved int             `json:"filesObserved"`
	FilesAnalyzed int             `json:"filesAnalyzed"`
	Evidence      []ScopeEvidence `json:"evidence"`
	Partial       bool            `json:"partial"`
	Limitations   []string        `json:"limitations"`
}

// ScanScope walks one locally approved root without following directory
// symlinks. Paths are never included in the returned evidence.
func ScanScope(ctx context.Context, root string, opts Options, scopeLimits ScopeLimits) (*ScopeScanResult, error) {
	if scopeLimits.MaxFiles <= 0 || scopeLimits.MaxDirectories <= 0 || scopeLimits.MaxDuration <= 0 {
		scopeLimits = DefaultScopeLimits()
	}
	realRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return nil, err
	}
	opts.ApprovedRoot = realRoot
	ctx, cancel := context.WithTimeout(ctx, scopeLimits.MaxDuration)
	defer cancel()
	out := &ScopeScanResult{Evidence: []ScopeEvidence{}, Limitations: []string{"Only bounded static metadata was inspected; no result proves files are safe.", "Directory symlinks and non-regular files were not followed."}}
	dirs := 0
	err = filepath.WalkDir(realRoot, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			out.Partial = true
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		if entry.IsDir() {
			dirs++
			if dirs > scopeLimits.MaxDirectories {
				out.Partial = true
				return fs.SkipDir
			}
			return nil
		}
		if entry.Type()&fs.ModeSymlink != 0 || !entry.Type().IsRegular() {
			return nil
		}
		out.FilesObserved++
		if !supportedCandidate(path) {
			return nil
		}
		if out.FilesAnalyzed >= scopeLimits.MaxFiles {
			out.Partial = true
			return nil
		}
		result, analyzeErr := Analyze(ctx, path, opts)
		if analyzeErr != nil {
			out.Partial = true
			return nil
		}
		out.FilesAnalyzed++
		rel, _ := filepath.Rel(realRoot, path)
		relHash := sha256.Sum256([]byte(filepath.ToSlash(rel)))
		keyHash := sha256.Sum256([]byte(result.SHA256 + "\n" + hex.EncodeToString(relHash[:])))
		sev, confidence := evidenceRating(result)
		out.Evidence = append(out.Evidence, ScopeEvidence{
			EvidenceKey: hex.EncodeToString(keyHash[:]), RelativePathHash: hex.EncodeToString(relHash[:]),
			ObservedAt: time.Now().UTC().Format(time.RFC3339), DetectorID: "NEXTAURA_STATIC_FILE_ANALYZER",
			DetectorVersion: DetectorVersion, EvidenceSource: "LOCAL_APPROVED_SCOPE_STATIC_ANALYSIS",
			Confidence: confidence, Severity: sev, Result: result,
		})
		return nil
	})
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		out.Partial = true
		out.Limitations = append(out.Limitations, "The scope time budget was reached before traversal completed.")
		return out, nil
	}
	if err != nil {
		return nil, err
	}
	if out.FilesAnalyzed >= scopeLimits.MaxFiles {
		out.Limitations = append(out.Limitations, "The per-scan file limit was reached.")
	}
	return out, nil
}

func supportedCandidate(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".zip", ".iso", ".exe", ".dll", ".msi", ".lnk", ".scr", ".com", ".bat", ".cmd", ".ps1", ".psm1", ".js", ".jse", ".vbs", ".vbe", ".wsf", ".pdf", ".rtf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".jar":
		return true
	}
	return false
}

func evidenceRating(result *Result) (string, string) {
	switch result.Classification {
	case ConfirmedDetection:
		return "CRITICAL", "HIGH"
	case SuspiciousIndicator:
		return "HIGH", "MEDIUM"
	case Inconclusive:
		return "MEDIUM", "LOW"
	case Unsupported:
		return "INFO", "LOW"
	default:
		return "INFO", "MEDIUM"
	}
}
