// Package model mirrors the server contract in
// artifacts/api-server/src/routes/agent/contract.ts. Keep both in sync.
package model

import "time"

const (
	CollectorSystemInfo         = "SYSTEM_INFO"
	CollectorSecurityPosture    = "SECURITY_POSTURE"
	CollectorAntivirusStatus    = "ANTIVIRUS_STATUS"
	CollectorSoftwareInventory  = "SOFTWARE_INVENTORY"
	CollectorStartupInventory   = "STARTUP_INVENTORY"
	CollectorSafeNetworkSummary = "SAFE_NETWORK_SUMMARY"
)

// AllCollectors is the fixed, audited list. The agent refuses anything else.
var AllCollectors = []string{
	CollectorSystemInfo,
	CollectorSecurityPosture,
	CollectorAntivirusStatus,
	CollectorSoftwareInventory,
	CollectorStartupInventory,
	CollectorSafeNetworkSummary,
}

// PostureCollectors run on the posture schedule; inventory collectors on the inventory schedule.
var PostureCollectors = []string{CollectorSystemInfo, CollectorSecurityPosture, CollectorAntivirusStatus, CollectorSafeNetworkSummary}
var InventoryCollectors = []string{CollectorSoftwareInventory, CollectorStartupInventory}

func IsKnownCollector(id string) bool {
	for _, c := range AllCollectors {
		if c == id {
			return true
		}
	}
	return false
}

const (
	StatusPass             = "PASS"
	StatusFail             = "FAIL"
	StatusWarning          = "WARNING"
	StatusUnknown          = "UNKNOWN"
	StatusUnsupported      = "UNSUPPORTED"
	StatusPermissionDenied = "PERMISSION_DENIED"
)

type Check struct {
	CheckID             string                 `json:"checkId"`
	Category            string                 `json:"category"`
	Title               string                 `json:"title"`
	Status              string                 `json:"status"`
	Evidence            string                 `json:"evidence"`
	DataSource          string                 `json:"dataSource"`
	Confidence          string                 `json:"confidence"`
	RequiredPermissions string                 `json:"requiredPermissions"`
	UnavailableReason   *string                `json:"unavailableReason,omitempty"`
	Details             map[string]interface{} `json:"details,omitempty"`
}

type SystemInfo struct {
	Hostname       string  `json:"hostname"`
	OSName         string  `json:"osName"`
	OSVersion      string  `json:"osVersion"`
	OSBuild        *string `json:"osBuild,omitempty"`
	Architecture   string  `json:"architecture"`
	CPUModel       *string `json:"cpuModel,omitempty"`
	TotalRAMMB     *int64  `json:"totalRamMb,omitempty"`
	Model          *string `json:"model,omitempty"`
	SerialRedacted *string `json:"serialRedacted,omitempty"`
}

type Antivirus struct {
	Product              *string `json:"product"`
	Status               string  `json:"status"`
	RealTimeProtection   string  `json:"realTimeProtection"`
	DefinitionsAgeDays   *int    `json:"definitionsAgeDays"`
	LastDefinitionUpdate *string `json:"lastDefinitionUpdate"`
	Source               *string `json:"source"`
	Note                 string  `json:"note"`
}

type Threat struct {
	ExternalID  *string `json:"externalId,omitempty"`
	ThreatName  string  `json:"threatName"`
	Severity    *string `json:"severity,omitempty"`
	DetectedAt  *string `json:"detectedAt,omitempty"`
	ActionTaken *string `json:"actionTaken,omitempty"`
	Product     string  `json:"product"`
	Source      string  `json:"source"`
}

type Software struct {
	Name        string  `json:"name"`
	Vendor      *string `json:"vendor,omitempty"`
	Version     *string `json:"version,omitempty"`
	InstalledAt *string `json:"installedAt,omitempty"`
	Source      string  `json:"source"`
}

type StartupItem struct {
	Name      string  `json:"name"`
	Location  string  `json:"location"`
	Kind      string  `json:"kind"`
	Enabled   *bool   `json:"enabled,omitempty"`
	Publisher *string `json:"publisher,omitempty"`
}

type CollectorResult struct {
	CollectorID      string        `json:"collectorId"`
	CollectorVersion string        `json:"collectorVersion"`
	Status           string        `json:"status"` // OK | FAILED | UNSUPPORTED | PERMISSION_DENIED
	Error            *string       `json:"error,omitempty"`
	CollectedAt      time.Time     `json:"collectedAt"`
	Checks           []Check       `json:"checks"`
	System           *SystemInfo   `json:"system,omitempty"`
	Antivirus        *Antivirus    `json:"antivirus,omitempty"`
	Threats          []Threat      `json:"threats,omitempty"`
	Software         []Software    `json:"software,omitempty"`
	StartupItems     []StartupItem `json:"startupItems,omitempty"`
}

type EnrollRequest struct {
	Code         string     `json:"code"`
	AgentVersion string     `json:"agentVersion"`
	OSType       string     `json:"osType"`
	System       SystemInfo `json:"system"`
}

type AgentConfig struct {
	HeartbeatIntervalMinutes int    `json:"heartbeatIntervalMinutes"`
	PostureIntervalHours     int    `json:"postureIntervalHours"`
	InventoryIntervalHours   int    `json:"inventoryIntervalHours"`
	MinimumAgentVersion      string `json:"minimumAgentVersion"`
}

type EnrollResponse struct {
	DeviceID         string      `json:"deviceId"`
	DeviceToken      string      `json:"deviceToken"`
	TokenExpiresAt   string      `json:"tokenExpiresAt"`
	OrganizationName string      `json:"organizationName"`
	Config           AgentConfig `json:"config"`
}

type CollectorError struct {
	CollectorID string    `json:"collectorId"`
	Message     string    `json:"message"`
	OccurredAt  time.Time `json:"occurredAt"`
}

type HeartbeatRequest struct {
	RequestID       string           `json:"requestId"`
	AgentVersion    string           `json:"agentVersion"`
	Timestamp       time.Time        `json:"timestamp"`
	UptimeSeconds   *int64           `json:"uptimeSeconds,omitempty"`
	CollectorErrors []CollectorError `json:"collectorErrors"`
}

type HeartbeatResponse struct {
	OK              bool        `json:"ok"`
	Config          AgentConfig `json:"config"`
	PendingRequests int         `json:"pendingRequests"`
}

type PendingRequest struct {
	ID         string   `json:"id"`
	Collectors []string `json:"collectors"`
	ExpiresAt  string   `json:"expiresAt"`
}

type RequestsResponse struct {
	Requests []PendingRequest `json:"requests"`
}

type AckRequest struct {
	RequestID string `json:"requestId"`
	Status    string `json:"status"`
	Reason    string `json:"reason,omitempty"`
}

type AssessmentRequest struct {
	IdempotencyKey string            `json:"idempotencyKey"`
	Trigger        string            `json:"trigger"`
	AgentVersion   string            `json:"agentVersion"`
	StartedAt      time.Time         `json:"startedAt"`
	CompletedAt    time.Time         `json:"completedAt"`
	AgentRequestID *string           `json:"agentRequestId,omitempty"`
	Collectors     []CollectorResult `json:"collectors"`
}

type AssessmentResponse struct {
	OK              bool   `json:"ok"`
	AssessmentID    string `json:"assessmentId"`
	Duplicate       bool   `json:"duplicate"`
	RiskScore       *int   `json:"riskScore"`
	CoveragePercent int    `json:"coveragePercent"`
}

func Str(s string) *string { return &s }
