//go:build darwin

package collectors

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/nextaura/agent/internal/model"
)

func registerPlatform(reg map[string]Collector) {
	reg[model.CollectorSystemInfo] = collectorFunc{model.CollectorSystemInfo, macSystemInfo}
	reg[model.CollectorSecurityPosture] = collectorFunc{model.CollectorSecurityPosture, macSecurityPosture}
	reg[model.CollectorAntivirusStatus] = collectorFunc{model.CollectorAntivirusStatus, macAntivirus}
	reg[model.CollectorSoftwareInventory] = collectorFunc{model.CollectorSoftwareInventory, macSoftware}
	reg[model.CollectorStartupInventory] = collectorFunc{model.CollectorStartupInventory, macStartup}
	reg[model.CollectorSafeNetworkSummary] = collectorFunc{model.CollectorSafeNetworkSummary, macNetwork}
}

func classify(b checkBuilder, err error) model.Check {
	if errors.Is(err, errPermission) {
		return b.denied(err.Error())
	}
	return b.unknown(err.Error())
}

func archName() string {
	switch runtime.GOARCH {
	case "amd64":
		return "amd64"
	case "arm64":
		return "arm64"
	}
	return "unknown"
}

func macSystemInfo(ctx context.Context, r *model.CollectorResult) error {
	host, _ := os.Hostname()
	sys := &model.SystemInfo{Hostname: host, OSName: "macOS", OSVersion: "unknown", Architecture: archName()}
	osc := ck("SYSTEM_OS_INFO", "SYSTEM", "Operating system identification", "sw_vers", "Standard user")
	if v, err := run(ctx, 10*time.Second, "sw_vers", "-productVersion"); err == nil {
		sys.OSVersion = v
		if b, err := run(ctx, 10*time.Second, "sw_vers", "-buildVersion"); err == nil {
			sys.OSBuild = model.Str(b)
		}
		if n, err := run(ctx, 10*time.Second, "sw_vers", "-productName"); err == nil && n != "" {
			sys.OSName = n
		}
		r.Checks = append(r.Checks, osc.pass(fmt.Sprintf("%s %s build %s", sys.OSName, sys.OSVersion, deref(sys.OSBuild))))
	} else {
		r.Checks = append(r.Checks, classify(osc, err))
	}
	if v, err := run(ctx, 10*time.Second, "sysctl", "-n", "machdep.cpu.brand_string"); err == nil && v != "" {
		sys.CPUModel = model.Str(v)
	}
	if v, err := run(ctx, 10*time.Second, "sysctl", "-n", "hw.memsize"); err == nil {
		if n, perr := strconv.ParseInt(v, 10, 64); perr == nil {
			mb := n / 1024 / 1024
			sys.TotalRAMMB = &mb
		}
	}
	if v, err := run(ctx, 10*time.Second, "sysctl", "-n", "hw.model"); err == nil && v != "" {
		sys.Model = model.Str(v)
	}
	if out, err := run(ctx, 20*time.Second, "system_profiler", "SPHardwareDataType", "-json"); err == nil {
		var sp struct {
			SPHardwareDataType []map[string]interface{} `json:"SPHardwareDataType"`
		}
		if json.Unmarshal([]byte(out), &sp) == nil && len(sp.SPHardwareDataType) > 0 {
			h := sp.SPHardwareDataType[0]
			if s, _ := h["serial_number"].(string); len(s) >= 4 {
				sys.SerialRedacted = model.Str("…" + s[len(s)-4:])
			}
			if m, _ := h["machine_name"].(string); m != "" {
				sys.Model = model.Str(m + " (" + deref(sys.Model) + ")")
			}
		}
	}
	r.System = sys
	return nil
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func macSecurityPosture(ctx context.Context, r *model.CollectorResult) error {
	// Application firewall
	fw := ck("FIREWALL_ENABLED", "FIREWALL", "macOS application firewall enabled", "socketfilterfw --getglobalstate", "Standard user")
	if out, err := run(ctx, 10*time.Second, "/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"); err != nil {
		r.Checks = append(r.Checks, classify(fw, err))
	} else if strings.Contains(strings.ToLower(out), "enabled") {
		r.Checks = append(r.Checks, fw.pass(firstLine(out)))
	} else if strings.Contains(strings.ToLower(out), "disabled") {
		r.Checks = append(r.Checks, fw.fail(firstLine(out)))
	} else {
		r.Checks = append(r.Checks, fw.unknown("Unexpected output: "+firstLine(out)))
	}

	// FileVault
	fv := ck("DISK_ENCRYPTION", "ENCRYPTION", "FileVault full-disk encryption enabled", "fdesetup status", "Administrator (root)")
	if out, err := run(ctx, 10*time.Second, "fdesetup", "status"); err != nil {
		r.Checks = append(r.Checks, classify(fv, err))
	} else if strings.Contains(out, "FileVault is On") {
		r.Checks = append(r.Checks, fv.pass(firstLine(out)))
	} else if strings.Contains(out, "FileVault is Off") {
		r.Checks = append(r.Checks, fv.fail(firstLine(out)))
	} else {
		r.Checks = append(r.Checks, fv.unknown("Unexpected output: "+firstLine(out)))
	}

	// System Integrity Protection
	sip := ck("SIP_ENABLED", "SECURITY_POSTURE", "System Integrity Protection enabled", "csrutil status", "Standard user")
	if out, err := run(ctx, 10*time.Second, "csrutil", "status"); err != nil {
		r.Checks = append(r.Checks, classify(sip, err))
	} else if strings.Contains(out, "status: enabled") {
		r.Checks = append(r.Checks, sip.pass(firstLine(out)))
	} else if strings.Contains(out, "status: disabled") {
		r.Checks = append(r.Checks, sip.fail(firstLine(out)))
	} else {
		r.Checks = append(r.Checks, sip.unknown("Unexpected output: "+firstLine(out)))
	}

	// Gatekeeper
	gk := ck("GATEKEEPER_ENABLED", "SECURITY_POSTURE", "Gatekeeper assessments enabled", "spctl --status", "Standard user")
	if out, err := run(ctx, 10*time.Second, "spctl", "--status"); err != nil && !strings.Contains(out, "assessments") {
		r.Checks = append(r.Checks, classify(gk, err))
	} else if strings.Contains(out, "assessments enabled") {
		r.Checks = append(r.Checks, gk.pass(firstLine(out)))
	} else if strings.Contains(out, "assessments disabled") {
		r.Checks = append(r.Checks, gk.fail(firstLine(out)))
	} else {
		r.Checks = append(r.Checks, gk.unknown("Unexpected output: "+firstLine(out)))
	}

	// OS updates: last successful check and pending updates
	upd := ck("OS_UPDATES", "UPDATES", "Software updates installed and none pending", "softwareupdate --list / com.apple.SoftwareUpdate", "Standard user")
	out, err := run(ctx, 90*time.Second, "softwareupdate", "--list", "--no-scan")
	if err != nil && !strings.Contains(out, "No new software available") {
		r.Checks = append(r.Checks, classify(upd, err))
	} else if strings.Contains(out, "No new software available") {
		r.Checks = append(r.Checks, upd.pass("softwareupdate --list --no-scan: No new software available (cached catalog)"))
	} else {
		labels := regexp.MustCompile(`\* Label: ([^\n]+)`).FindAllStringSubmatch(out, -1)
		var names []string
		for _, m := range labels {
			names = append(names, strings.TrimSpace(m[1]))
		}
		if len(names) == 0 {
			r.Checks = append(r.Checks, upd.unknown("Could not interpret softwareupdate output"))
		} else {
			r.Checks = append(r.Checks, upd.fail(fmt.Sprintf("%d pending update(s): %s", len(names), truncate(strings.Join(names, "; "), 800))))
		}
	}

	// OS support
	osc := ck("OS_SUPPORT", "OS_SUPPORT", "macOS version receives security updates from Apple", "sw_vers -productVersion", "Standard user")
	if v, err := run(ctx, 10*time.Second, "sw_vers", "-productVersion"); err != nil {
		r.Checks = append(r.Checks, classify(osc, err))
	} else {
		r.Checks = append(r.Checks, macOSSupportCheck(osc, v))
	}

	// Screen lock: askForPassword / delay (current user)
	sl := ck("SCREEN_LOCK", "SECURITY_POSTURE", "Password required after screen saver / sleep", "sysadminctl -screenLock status / com.apple.screensaver", "Standard user (current user only)")
	if u, _ := user.Current(); u != nil && u.Uid == "0" {
		r.Checks = append(r.Checks, sl.unknown("Running as root; per-user screen lock preference is not observable from the daemon context"))
	} else {
		ask, err1 := run(ctx, 10*time.Second, "defaults", "read", "com.apple.screensaver", "askForPassword")
		delay, _ := run(ctx, 10*time.Second, "defaults", "read", "com.apple.screensaver", "askForPasswordDelay")
		if err1 != nil {
			r.Checks = append(r.Checks, sl.unknown("com.apple.screensaver askForPassword not set for current user (macOS 10.13+ stores it in the keychain-protected user settings; verify via System Settings)"))
		} else if ask == "1" {
			r.Checks = append(r.Checks, sl.pass(fmt.Sprintf("askForPassword=1 askForPasswordDelay=%s seconds", delay)))
		} else {
			r.Checks = append(r.Checks, sl.fail(fmt.Sprintf("askForPassword=%s", ask)))
		}
	}

	// Secure Boot (Apple silicon / T2) via system_profiler SPiBridgeDataType
	sb := ck("SECURE_BOOT", "SECURITY_POSTURE", "Secure Boot set to Full Security", "system_profiler SPiBridgeDataType", "Standard user")
	if out, err := run(ctx, 30*time.Second, "system_profiler", "SPiBridgeDataType", "-json"); err != nil {
		r.Checks = append(r.Checks, classify(sb, err))
	} else {
		var sp struct {
			Items []map[string]interface{} `json:"SPiBridgeDataType"`
		}
		if json.Unmarshal([]byte(out), &sp) == nil && len(sp.Items) > 0 {
			lvl, _ := sp.Items[0]["ibridge_secure_boot"].(string)
			switch {
			case lvl == "":
				r.Checks = append(r.Checks, sb.unknown("ibridge_secure_boot not reported"))
			case strings.Contains(strings.ToLower(lvl), "full"):
				r.Checks = append(r.Checks, sb.pass("Secure Boot: "+lvl))
			default:
				r.Checks = append(r.Checks, sb.fail("Secure Boot: "+lvl))
			}
		} else {
			r.Checks = append(r.Checks, sb.unsupportedCheck("No Apple T2 / Apple silicon security chip reported; Secure Boot does not apply to this Mac"))
		}
	}

	// Guest account
	ga := ck("GUEST_ACCOUNT", "SECURITY_POSTURE", "Guest login disabled", "com.apple.loginwindow GuestEnabled", "Standard user")
	if out, err := run(ctx, 10*time.Second, "defaults", "read", "/Library/Preferences/com.apple.loginwindow", "GuestEnabled"); err != nil {
		r.Checks = append(r.Checks, ga.pass("GuestEnabled key absent (default: guest login disabled)"))
	} else if out == "1" {
		r.Checks = append(r.Checks, ga.fail("GuestEnabled=1"))
	} else {
		r.Checks = append(r.Checks, ga.pass("GuestEnabled="+out))
	}

	// Remote Login (SSH) and Screen Sharing
	ra := ck("REMOTE_ACCESS", "SECURITY_POSTURE", "Remote Login (SSH) / Screen Sharing disabled unless required", "launchctl print system", "Standard user")
	if out, err := run(ctx, 20*time.Second, "launchctl", "print", "system"); err != nil {
		r.Checks = append(r.Checks, classify(ra, err))
	} else {
		var on []string
		if strings.Contains(out, "com.openssh.sshd") {
			on = append(on, "Remote Login (sshd)")
		}
		if strings.Contains(out, "com.apple.screensharing") {
			on = append(on, "Screen Sharing")
		}
		if len(on) > 0 {
			r.Checks = append(r.Checks, ra.warn("Enabled remote access services: "+strings.Join(on, ", ")+"; confirm this is intended"))
		} else {
			r.Checks = append(r.Checks, ra.pass("Neither sshd nor screensharing is loaded in the system domain"))
		}
	}
	return nil
}

func macOSSupportCheck(b checkBuilder, version string) model.Check {
	major, _ := strconv.Atoi(strings.Split(version, ".")[0])
	switch major {
	case 27, 26, 15:
		return b.pass(fmt.Sprintf("macOS %s is one of the releases receiving Apple security updates as of 2026-11-04", version))
	case 0:
		return b.unknown("Could not parse version " + version)
	case 14:
		return b.fail(fmt.Sprintf("macOS %s (Sonoma) is no longer among Apple's three actively updated releases; upgrade", version))
	default:
		if major > 27 {
			return b.unknown(fmt.Sprintf("macOS %s is newer than this agent's 2026-11-04 support table; verify Apple security-update status", version))
		}
		return b.fail(fmt.Sprintf("macOS %s no longer receives routine Apple security updates", version))
	}
}

func macAntivirus(ctx context.Context, r *model.CollectorResult) error {
	av := &model.Antivirus{Status: "UNKNOWN", RealTimeProtection: model.StatusUnknown}
	prod := ck("AV_PRODUCT", "ANTIVIRUS", "Endpoint protection product installed", "/Applications bundle scan + XProtect", "Standard user")
	rt := ck("AV_REALTIME", "ANTIVIRUS", "Real-time protection enabled", "running security processes", "Standard user")
	defs := ck("AV_DEFINITIONS", "ANTIVIRUS", "Apple XProtect definitions present and recent", "XProtect bundle Info.plist", "Standard user")

	known := map[string]string{
		"CrowdStrike Falcon":     "/Applications/Falcon.app",
		"SentinelOne":            "/Applications/SentinelOne/SentinelOne Extensions.app",
		"Microsoft Defender":     "/Applications/Microsoft Defender.app",
		"Sophos Endpoint":        "/Applications/Sophos/Sophos Endpoint.app",
		"Bitdefender Endpoint":   "/Applications/Endpoint Security for Mac.app",
		"ESET Endpoint Security": "/Applications/ESET Endpoint Security.app",
		"Malwarebytes":           "/Applications/Malwarebytes.app",
		"Jamf Protect":           "/Applications/JamfProtect.app",
		"Avast Security":         "/Applications/Avast.app",
		"Norton 360":             "/Applications/Norton 360.app",
		"Kaspersky":              "/Applications/Kaspersky Internet Security.app",
		"Trend Micro Antivirus":  "/Applications/Trend Micro Antivirus.app",
	}
	var found []string
	for name, p := range known {
		if _, err := os.Stat(p); err == nil {
			found = append(found, name)
		}
	}
	if len(found) > 0 {
		av.Product = model.Str(strings.Join(found, "; "))
		av.Status = "THIRD_PARTY"
		av.Source = model.Str("application bundle present")
		av.RealTimeProtection = model.StatusUnknown
		av.Note = "A third-party product bundle is installed. The agent does not query vendor APIs, so its real-time state is not verified."
		r.Checks = append(r.Checks, prod.pass("Installed: "+strings.Join(found, "; ")))
		r.Checks = append(r.Checks, rt.unknown("Third-party product real-time state is not queried by the agent (vendor API required)"))
	} else {
		av.Product = model.Str("Apple XProtect (built-in)")
		av.Source = model.Str("XProtect")
		av.Status = "ACTIVE"
		av.Note = "Only Apple's built-in XProtect/XProtect Remediator was found. No third-party endpoint protection product is installed."
		r.Checks = append(r.Checks, prod.warn("No third-party endpoint protection product found; relying on Apple XProtect only"))
		if _, err := os.Stat("/Library/Apple/System/Library/CoreServices/XProtect.bundle"); err == nil {
			av.RealTimeProtection = model.StatusPass
			r.Checks = append(r.Checks, rt.pass("XProtect bundle present; Apple's built-in on-execution checks are always enabled when SIP is on"))
		} else {
			av.RealTimeProtection = model.StatusUnknown
			r.Checks = append(r.Checks, rt.unknown("XProtect bundle not found at the expected path"))
		}
	}
	// XProtect version/date
	if out, err := run(ctx, 10*time.Second, "defaults", "read", "/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Info.plist", "CFBundleShortVersionString"); err != nil {
		r.Checks = append(r.Checks, classify(defs, err))
	} else {
		st, serr := os.Stat("/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Info.plist")
		if serr == nil {
			age := int(time.Since(st.ModTime()).Hours() / 24)
			av.DefinitionsAgeDays = &age
			av.LastDefinitionUpdate = model.Str(st.ModTime().UTC().Format(time.RFC3339))
			ev := fmt.Sprintf("XProtect version %s, bundle updated %d days ago", out, age)
			c := defs.pass(ev)
			if age > 60 {
				c = defs.warn(ev + " (XProtect updates are infrequent; combine with OS update status)")
			}
			c.Details = map[string]interface{}{"ageDays": age, "lastUpdate": st.ModTime().UTC().Format(time.RFC3339)}
			r.Checks = append(r.Checks, c)
		} else {
			r.Checks = append(r.Checks, defs.pass("XProtect version "+out))
		}
	}
	for i := range r.Checks {
		if r.Checks[i].CheckID == "AV_PRODUCT" {
			r.Checks[i].Details = map[string]interface{}{"status": av.Status, "product": av.Product}
		}
	}
	r.Antivirus = av
	r.Checks = append(r.Checks, ck("THREAT_HISTORY", "ANTIVIRUS", "Antivirus detection history available", "n/a on macOS", "n/a").unsupportedCheck("macOS exposes no standard detection-history API; third-party product consoles hold this data"))
	return nil
}

func macSoftware(ctx context.Context, r *model.CollectorResult) error {
	out, err := run(ctx, 120*time.Second, "system_profiler", "SPApplicationsDataType", "-json")
	if err != nil {
		return err
	}
	var sp struct {
		Apps []map[string]interface{} `json:"SPApplicationsDataType"`
	}
	if err := json.Unmarshal([]byte(out), &sp); err != nil {
		return fmt.Errorf("parse system_profiler output: %w", err)
	}
	for _, a := range sp.Apps {
		name, _ := a["_name"].(string)
		if name == "" {
			continue
		}
		item := model.Software{Name: name, Source: "system_profiler SPApplicationsDataType"}
		if v, _ := a["version"].(string); v != "" {
			item.Version = model.Str(v)
		}
		if si, _ := a["signed_by"].([]interface{}); len(si) > 0 {
			if s, ok := si[0].(string); ok {
				item.Vendor = model.Str(strings.TrimPrefix(s, "Developer ID Application: "))
			}
		} else if ok, _ := a["obtained_from"].(string); ok == "apple" {
			item.Vendor = model.Str("Apple")
		}
		if lm, _ := a["lastModified"].(string); lm != "" {
			if t, perr := time.Parse("2006-01-02T15:04:05Z", lm); perr == nil {
				item.InstalledAt = model.Str(t.UTC().Format(time.RFC3339))
			}
		}
		r.Software = append(r.Software, item)
	}
	r.Checks = append(r.Checks, ck("SOFTWARE_INVENTORY_COLLECTED", "SYSTEM", "Installed software inventory collected", "system_profiler SPApplicationsDataType", "Standard user").pass(fmt.Sprintf("%d applications enumerated", len(r.Software))))
	return nil
}

func macStartup(ctx context.Context, r *model.CollectorResult) error {
	dirs := []struct {
		path string
		kind string
	}{
		{"/Library/LaunchDaemons", "LAUNCH_DAEMON"},
		{"/Library/LaunchAgents", "LAUNCH_AGENT"},
	}
	if home, err := os.UserHomeDir(); err == nil && home != "/var/root" {
		dirs = append(dirs, struct{ path, kind string }{filepath.Join(home, "Library/LaunchAgents"), "LAUNCH_AGENT"})
	}
	var denied []string
	for _, d := range dirs {
		entries, err := os.ReadDir(d.path)
		if err != nil {
			if errors.Is(err, os.ErrPermission) {
				denied = append(denied, d.path)
			}
			continue
		}
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".plist") {
				continue
			}
			item := model.StartupItem{Name: strings.TrimSuffix(e.Name(), ".plist"), Location: filepath.Join(d.path, e.Name()), Kind: d.kind}
			if out, err := run(ctx, 5*time.Second, "defaults", "read", filepath.Join(d.path, e.Name()), "Disabled"); err == nil {
				item.Enabled = boolPtr(out != "1")
			}
			r.StartupItems = append(r.StartupItems, item)
		}
	}
	// Login items (modern macOS stores these in BTM; list via sfltool is not read-only safe → use osascript-free approach: System Events requires automation consent, so we skip and record UNKNOWN)
	li := ck("STARTUP_LOGIN_ITEMS", "SYSTEM", "User login items enumerated", "Background Task Management", "Automation consent")
	r.Checks = append(r.Checks, li.unknown("Login items managed by Background Task Management require user automation consent to enumerate; LaunchAgents/LaunchDaemons are listed instead"))
	if len(denied) > 0 {
		r.Checks = append(r.Checks, ck("STARTUP_LAUNCHD_ACCESS", "SYSTEM", "launchd directories readable", "filesystem", "Standard user").denied("Could not read: "+strings.Join(denied, ", ")))
	}
	r.Checks = append(r.Checks, ck("STARTUP_INVENTORY_COLLECTED", "SYSTEM", "Startup persistence inventory collected", "/Library/LaunchDaemons, /Library/LaunchAgents, ~/Library/LaunchAgents", "Standard user").pass(fmt.Sprintf("%d launchd items enumerated", len(r.StartupItems))))
	return nil
}

func macNetwork(ctx context.Context, r *model.CollectorResult) error {
	stealth := ck("FIREWALL_STEALTH", "FIREWALL", "Firewall stealth mode enabled", "socketfilterfw --getstealthmode", "Standard user")
	if out, err := run(ctx, 10*time.Second, "/usr/libexec/ApplicationFirewall/socketfilterfw", "--getstealthmode"); err != nil {
		r.Checks = append(r.Checks, classify(stealth, err))
	} else if strings.Contains(strings.ToLower(out), "enabled") {
		r.Checks = append(r.Checks, stealth.pass(firstLine(out)))
	} else {
		r.Checks = append(r.Checks, stealth.warn(firstLine(out)))
	}
	blockAll := ck("FIREWALL_INBOUND_DEFAULT", "FIREWALL", "Firewall blocks all incoming connections", "socketfilterfw --getblockall", "Standard user")
	if out, err := run(ctx, 10*time.Second, "/usr/libexec/ApplicationFirewall/socketfilterfw", "--getblockall"); err != nil {
		r.Checks = append(r.Checks, classify(blockAll, err))
	} else if strings.Contains(strings.ToLower(out), "enabled") || strings.Contains(strings.ToLower(out), "block all") && !strings.Contains(strings.ToLower(out), "disabled") {
		r.Checks = append(r.Checks, blockAll.pass(firstLine(out)))
	} else {
		r.Checks = append(r.Checks, blockAll.status(model.StatusPass, firstLine(out)+" (per-app allow list in effect; informational)", "MEDIUM"))
	}
	// File sharing (SMB/AFP) exposure
	smb := ck("SMBV1", "NETWORK", "Legacy file sharing protocols disabled", "launchctl print system (smbd)", "Standard user")
	if out, err := run(ctx, 20*time.Second, "launchctl", "print", "system"); err != nil {
		r.Checks = append(r.Checks, classify(smb, err))
	} else if strings.Contains(out, "com.apple.smbd") {
		r.Checks = append(r.Checks, smb.warn("SMB file sharing (smbd) is loaded; macOS smbd does not serve SMBv1 but confirm sharing is intended"))
	} else {
		r.Checks = append(r.Checks, smb.pass("smbd not loaded; no SMB file sharing exposed"))
	}
	r.Checks = append(r.Checks, ck("NETWORK_PROFILE", "NETWORK", "Active network summary", "scutil --nwi", "Standard user").pass(func() string {
		out, err := run(ctx, 10*time.Second, "scutil", "--nwi")
		if err != nil {
			return "scutil unavailable: " + err.Error()
		}
		return truncate("Network interfaces summary (no traffic inspected): "+strings.ReplaceAll(firstLine(out), "\n", " "), 500)
	}()))
	return nil
}
