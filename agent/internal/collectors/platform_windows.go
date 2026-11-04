//go:build windows

package collectors

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/nextaura/agent/internal/model"
)

func registerPlatform(reg map[string]Collector) {
	reg[model.CollectorSystemInfo] = collectorFunc{model.CollectorSystemInfo, winSystemInfo}
	reg[model.CollectorSecurityPosture] = collectorFunc{model.CollectorSecurityPosture, winSecurityPosture}
	reg[model.CollectorAntivirusStatus] = collectorFunc{model.CollectorAntivirusStatus, winAntivirus}
	reg[model.CollectorSoftwareInventory] = collectorFunc{model.CollectorSoftwareInventory, winSoftware}
	reg[model.CollectorStartupInventory] = collectorFunc{model.CollectorStartupInventory, winStartup}
	reg[model.CollectorSafeNetworkSummary] = collectorFunc{model.CollectorSafeNetworkSummary, winNetwork}
}

// ps runs a read-only PowerShell expression and decodes JSON output into v.
// -NonInteractive and -NoProfile prevent any user profile script from running.
func ps(ctx context.Context, v interface{}, script string) error {
	out, err := run(ctx, 45*time.Second, "powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command",
		"$ProgressPreference='SilentlyContinue'; $ErrorActionPreference='Stop'; "+script+" | ConvertTo-Json -Depth 4 -Compress")
	if err != nil {
		return err
	}
	if out == "" || out == "null" {
		return nil
	}
	return json.Unmarshal([]byte(out), v)
}

// psList handles PowerShell's habit of emitting a bare object for a single result.
func psList(ctx context.Context, script string) ([]map[string]interface{}, error) {
	var raw json.RawMessage
	if err := ps(ctx, &raw, script); err != nil {
		return nil, err
	}
	if len(raw) == 0 {
		return nil, nil
	}
	var list []map[string]interface{}
	if err := json.Unmarshal(raw, &list); err == nil {
		return list, nil
	}
	var single map[string]interface{}
	if err := json.Unmarshal(raw, &single); err != nil {
		return nil, err
	}
	return []map[string]interface{}{single}, nil
}

func str(m map[string]interface{}, k string) string {
	if v, ok := m[k]; ok && v != nil {
		return strings.TrimSpace(fmt.Sprint(v))
	}
	return ""
}
func num(m map[string]interface{}, k string) (float64, bool) {
	if v, ok := m[k].(float64); ok {
		return v, true
	}
	return 0, false
}
func boolean(m map[string]interface{}, k string) (bool, bool) {
	if v, ok := m[k].(bool); ok {
		return v, true
	}
	return false, false
}

const psCimOS = "Get-CimInstance Win32_OperatingSystem | Select-Object Caption,Version,BuildNumber,TotalVisibleMemorySize,LastBootUpTime,OSArchitecture"

func winSystemInfo(ctx context.Context, r *model.CollectorResult) error {
	host, _ := os.Hostname()
	sys := &model.SystemInfo{Hostname: host, OSName: "Windows", OSVersion: "unknown", Architecture: archName()}
	var osInfo map[string]interface{}
	if err := ps(ctx, &osInfo, psCimOS); err != nil {
		r.Checks = append(r.Checks, ck("SYSTEM_OS_INFO", "SYSTEM", "Operating system identification", "Win32_OperatingSystem", "Standard user").unknown(err.Error()))
	} else {
		sys.OSName = str(osInfo, "Caption")
		sys.OSVersion = str(osInfo, "Version")
		if b := str(osInfo, "BuildNumber"); b != "" {
			sys.OSBuild = model.Str(b)
		}
		if kb, ok := num(osInfo, "TotalVisibleMemorySize"); ok {
			mb := int64(kb / 1024)
			sys.TotalRAMMB = &mb
		}
		r.Checks = append(r.Checks, ck("SYSTEM_OS_INFO", "SYSTEM", "Operating system identification", "Win32_OperatingSystem", "Standard user").pass(fmt.Sprintf("%s version %s build %s", sys.OSName, sys.OSVersion, str(osInfo, "BuildNumber"))))
	}
	var cs map[string]interface{}
	if err := ps(ctx, &cs, "Get-CimInstance Win32_ComputerSystem | Select-Object Manufacturer,Model"); err == nil {
		if m := strings.TrimSpace(str(cs, "Manufacturer") + " " + str(cs, "Model")); m != "" {
			sys.Model = model.Str(m)
		}
	}
	var cpu map[string]interface{}
	if err := ps(ctx, &cpu, "Get-CimInstance Win32_Processor | Select-Object -First 1 Name"); err == nil {
		if n := str(cpu, "Name"); n != "" {
			sys.CPUModel = model.Str(n)
		}
	}
	var bios map[string]interface{}
	if err := ps(ctx, &bios, "Get-CimInstance Win32_BIOS | Select-Object SerialNumber"); err == nil {
		if s := str(bios, "SerialNumber"); len(s) >= 4 {
			sys.SerialRedacted = model.Str("…" + s[len(s)-4:])
		}
	}
	r.System = sys
	return nil
}

func winSecurityPosture(ctx context.Context, r *model.CollectorResult) error {
	// Firewall profiles
	fw := ck("FIREWALL_ENABLED", "FIREWALL", "Windows Firewall enabled on all profiles", "Get-NetFirewallProfile", "Standard user")
	profiles, err := psList(ctx, "Get-NetFirewallProfile | Select-Object Name,Enabled")
	if err != nil {
		r.Checks = append(r.Checks, classify(fw, err))
	} else {
		var off []string
		for _, p := range profiles {
			if en, ok := boolean(p, "Enabled"); ok && !en {
				off = append(off, str(p, "Name"))
			} else if v, ok := num(p, "Enabled"); ok && v == 0 {
				off = append(off, str(p, "Name"))
			}
		}
		if len(profiles) == 0 {
			r.Checks = append(r.Checks, fw.unknown("Get-NetFirewallProfile returned no profiles"))
		} else if len(off) > 0 {
			r.Checks = append(r.Checks, fw.fail("Firewall disabled for profile(s): "+strings.Join(off, ", ")))
		} else {
			r.Checks = append(r.Checks, fw.pass(fmt.Sprintf("All %d firewall profiles report Enabled=True", len(profiles))))
		}
	}

	// BitLocker on the system drive (needs admin)
	bl := ck("DISK_ENCRYPTION", "ENCRYPTION", "System drive encrypted with BitLocker", "Get-BitLockerVolume", "Administrator")
	var vol map[string]interface{}
	if err := ps(ctx, &vol, "Get-BitLockerVolume -MountPoint $env:SystemDrive | Select-Object MountPoint,ProtectionStatus,VolumeStatus,EncryptionPercentage"); err != nil {
		r.Checks = append(r.Checks, classify(bl, err))
	} else if vol == nil {
		r.Checks = append(r.Checks, bl.unknown("Get-BitLockerVolume returned nothing for the system drive"))
	} else {
		ps_ := str(vol, "ProtectionStatus")
		vs := str(vol, "VolumeStatus")
		switch {
		case ps_ == "On" || ps_ == "1":
			r.Checks = append(r.Checks, bl.pass(fmt.Sprintf("%s ProtectionStatus=On VolumeStatus=%s", str(vol, "MountPoint"), vs)))
		case ps_ == "Off" || ps_ == "0":
			r.Checks = append(r.Checks, bl.fail(fmt.Sprintf("%s ProtectionStatus=Off VolumeStatus=%s EncryptionPercentage=%s", str(vol, "MountPoint"), vs, str(vol, "EncryptionPercentage"))))
		default:
			r.Checks = append(r.Checks, bl.unknown("Unrecognised ProtectionStatus "+ps_))
		}
	}

	// OS updates: last installed hotfix and pending reboot
	upd := ck("OS_UPDATES", "UPDATES", "Operating system updates installed recently", "Get-HotFix / Windows Update registry", "Standard user")
	var hf map[string]interface{}
	if err := ps(ctx, &hf, "Get-HotFix | Where-Object InstalledOn | Sort-Object InstalledOn -Descending | Select-Object -First 1 HotFixID,@{n='InstalledOn';e={$_.InstalledOn.ToString('o')}}"); err != nil {
		r.Checks = append(r.Checks, classify(upd, err))
	} else if hf == nil {
		r.Checks = append(r.Checks, upd.unknown("No hotfix with an install date was reported by Get-HotFix"))
	} else {
		t, perr := time.Parse(time.RFC3339, str(hf, "InstalledOn"))
		if perr != nil {
			r.Checks = append(r.Checks, upd.unknown("Could not parse hotfix install date "+str(hf, "InstalledOn")))
		} else {
			age := int(time.Since(t).Hours() / 24)
			ev := fmt.Sprintf("Most recent hotfix %s installed %d days ago (%s)", str(hf, "HotFixID"), age, t.Format("2006-01-02"))
			c := upd.pass(ev)
			if age > 60 {
				c = upd.fail(ev)
			} else if age > 35 {
				c = upd.warn(ev)
			}
			c.Details = map[string]interface{}{"ageDays": age}
			r.Checks = append(r.Checks, c)
		}
	}

	// OS support status
	osc := ck("OS_SUPPORT", "OS_SUPPORT", "Operating system version is supported by the vendor", "Win32_OperatingSystem build number", "Standard user")
	var osInfo map[string]interface{}
	if err := ps(ctx, &osInfo, psCimOS); err != nil {
		r.Checks = append(r.Checks, classify(osc, err))
	} else {
		r.Checks = append(r.Checks, windowsSupportCheck(osc, str(osInfo, "Caption"), str(osInfo, "BuildNumber")))
	}

	// Screen lock / inactivity timeout (user-scope policy)
	sl := ck("SCREEN_LOCK", "SECURITY_POSTURE", "Screen saver lock with inactivity timeout", "HKCU Control Panel\\Desktop", "Standard user (current user only)")
	var sld map[string]interface{}
	if err := ps(ctx, &sld, "$p='HKCU:\\Control Panel\\Desktop'; [pscustomobject]@{Secure=(Get-ItemProperty -Path $p -Name ScreenSaverIsSecure -ErrorAction SilentlyContinue).ScreenSaverIsSecure; Timeout=(Get-ItemProperty -Path $p -Name ScreenSaveTimeOut -ErrorAction SilentlyContinue).ScreenSaveTimeOut; Active=(Get-ItemProperty -Path $p -Name ScreenSaveActive -ErrorAction SilentlyContinue).ScreenSaveActive}"); err != nil {
		r.Checks = append(r.Checks, classify(sl, err))
	} else if sld == nil || (str(sld, "Secure") == "" && str(sld, "Timeout") == "") {
		r.Checks = append(r.Checks, sl.unknown("No screen saver policy values present for the current user (may be managed by Group Policy or not configured; service accounts have no interactive profile)"))
	} else {
		ev := fmt.Sprintf("ScreenSaverIsSecure=%s ScreenSaveTimeOut=%s ScreenSaveActive=%s", str(sld, "Secure"), str(sld, "Timeout"), str(sld, "Active"))
		if str(sld, "Secure") == "1" && str(sld, "Active") == "1" {
			r.Checks = append(r.Checks, sl.pass(ev))
		} else {
			r.Checks = append(r.Checks, sl.fail(ev))
		}
	}

	// Secure Boot
	sb := ck("SECURE_BOOT", "SECURITY_POSTURE", "UEFI Secure Boot enabled", "Confirm-SecureBootUEFI", "Administrator")
	var sbv interface{}
	if err := ps(ctx, &sbv, "Confirm-SecureBootUEFI"); err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "not supported on this platform") {
			r.Checks = append(r.Checks, sb.unsupportedCheck("Firmware is legacy BIOS; Secure Boot does not apply"))
		} else {
			r.Checks = append(r.Checks, classify(sb, err))
		}
	} else if b, ok := sbv.(bool); ok {
		if b {
			r.Checks = append(r.Checks, sb.pass("Confirm-SecureBootUEFI = True"))
		} else {
			r.Checks = append(r.Checks, sb.fail("Confirm-SecureBootUEFI = False"))
		}
	} else {
		r.Checks = append(r.Checks, sb.unknown("Unexpected output from Confirm-SecureBootUEFI"))
	}

	// UAC
	uac := ck("UAC_ENABLED", "SECURITY_POSTURE", "User Account Control enabled", "HKLM\\...\\Policies\\System EnableLUA", "Standard user")
	var uacv map[string]interface{}
	if err := ps(ctx, &uacv, "Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -Name EnableLUA,ConsentPromptBehaviorAdmin | Select-Object EnableLUA,ConsentPromptBehaviorAdmin"); err != nil {
		r.Checks = append(r.Checks, classify(uac, err))
	} else {
		ev := fmt.Sprintf("EnableLUA=%s ConsentPromptBehaviorAdmin=%s", str(uacv, "EnableLUA"), str(uacv, "ConsentPromptBehaviorAdmin"))
		if str(uacv, "EnableLUA") == "1" {
			r.Checks = append(r.Checks, uac.pass(ev))
		} else {
			r.Checks = append(r.Checks, uac.fail(ev))
		}
	}

	// Guest account
	ga := ck("GUEST_ACCOUNT", "SECURITY_POSTURE", "Built-in Guest account disabled", "Get-LocalUser", "Standard user")
	guests, err := psList(ctx, "Get-LocalUser | Where-Object { $_.SID -like 'S-1-5-21-*-501' } | Select-Object Name,Enabled")
	if err != nil {
		r.Checks = append(r.Checks, classify(ga, err))
	} else if len(guests) == 0 {
		r.Checks = append(r.Checks, ga.unknown("No account with the built-in Guest RID (501) was listed"))
	} else if en, _ := boolean(guests[0], "Enabled"); en {
		r.Checks = append(r.Checks, ga.fail(fmt.Sprintf("Account %q (RID 501) Enabled=True", str(guests[0], "Name"))))
	} else {
		r.Checks = append(r.Checks, ga.pass(fmt.Sprintf("Account %q (RID 501) Enabled=False", str(guests[0], "Name"))))
	}

	// Remote Desktop
	rd := ck("REMOTE_ACCESS", "SECURITY_POSTURE", "Remote Desktop disabled unless required", "HKLM\\...\\Terminal Server fDenyTSConnections", "Standard user")
	var rdp map[string]interface{}
	if err := ps(ctx, &rdp, "Get-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server' -Name fDenyTSConnections | Select-Object fDenyTSConnections"); err != nil {
		r.Checks = append(r.Checks, classify(rd, err))
	} else if str(rdp, "fDenyTSConnections") == "1" {
		r.Checks = append(r.Checks, rd.pass("fDenyTSConnections=1 (Remote Desktop disabled)"))
	} else {
		r.Checks = append(r.Checks, rd.warn("fDenyTSConnections=0 (Remote Desktop enabled); confirm this is intended and restricted"))
	}
	return nil
}

func windowsSupportCheck(b checkBuilder, caption, build string) model.Check {
	var n int
	fmt.Sscanf(build, "%d", &n)
	lc := strings.ToLower(caption)
	switch {
	case n == 0:
		return b.unknown("Build number not available")
	case strings.Contains(lc, "server"):
		if n < 17763 {
			return b.fail(fmt.Sprintf("%s build %d is past mainstream+extended support", caption, n))
		}
		return b.pass(fmt.Sprintf("%s build %d is in vendor support", caption, n))
	case n >= 22000: // Windows 11
		if n < 22631 {
			return b.fail(fmt.Sprintf("%s build %d (21H2/22H2) reached end of servicing; update to a supported feature release", caption, n))
		}
		return b.pass(fmt.Sprintf("%s build %d is a supported Windows 11 release", caption, n))
	case n >= 10240: // Windows 10
		return b.fail(fmt.Sprintf("%s build %d: Windows 10 reached end of support on 2025-10-14 (unless enrolled in ESU, which the agent cannot verify)", caption, n))
	default:
		return b.fail(fmt.Sprintf("%s build %d is unsupported", caption, n))
	}
}

func classify(b checkBuilder, err error) model.Check {
	if errors.Is(err, errPermission) {
		return b.denied(err.Error())
	}
	return b.unknown(err.Error())
}

func winAntivirus(ctx context.Context, r *model.CollectorResult) error {
	av := &model.Antivirus{Status: "UNKNOWN", RealTimeProtection: model.StatusUnknown, Note: ""}
	prod := ck("AV_PRODUCT", "ANTIVIRUS", "Antivirus product registered with Windows Security Center", "root/SecurityCenter2 AntiVirusProduct", "Standard user")
	rt := ck("AV_REALTIME", "ANTIVIRUS", "Real-time protection enabled", "Get-MpComputerStatus", "Standard user")
	defs := ck("AV_DEFINITIONS", "ANTIVIRUS", "Antivirus definitions are current", "Get-MpComputerStatus", "Standard user")

	products, perr := psList(ctx, "Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct | Select-Object displayName,productState")
	var defender map[string]interface{}
	derr := ps(ctx, &defender, "Get-MpComputerStatus | Select-Object AMProductVersion,AntivirusEnabled,RealTimeProtectionEnabled,AMServiceEnabled,AntivirusSignatureAge,@{n='AntivirusSignatureLastUpdated';e={$_.AntivirusSignatureLastUpdated.ToString('o')}},AMRunningMode")

	if perr == nil && len(products) > 0 {
		var names []string
		thirdParty := false
		for _, p := range products {
			n := str(p, "displayName")
			names = append(names, n)
			if !strings.Contains(strings.ToLower(n), "defender") {
				thirdParty = true
			}
		}
		av.Product = model.Str(strings.Join(names, "; "))
		av.Source = model.Str("root/SecurityCenter2")
		if thirdParty {
			av.Status = "THIRD_PARTY"
		}
		r.Checks = append(r.Checks, prod.pass("Registered product(s): "+strings.Join(names, "; ")))
	} else if perr != nil {
		r.Checks = append(r.Checks, classify(prod, perr))
	} else {
		r.Checks = append(r.Checks, prod.fail("No antivirus product is registered with Windows Security Center"))
		av.Status = "DISABLED"
	}

	if derr != nil {
		r.Checks = append(r.Checks, classify(rt, derr), classify(defs, derr))
		av.Note = "Get-MpComputerStatus unavailable: " + derr.Error()
	} else if defender == nil {
		r.Checks = append(r.Checks, rt.unknown("Get-MpComputerStatus returned nothing"), defs.unknown("Get-MpComputerStatus returned nothing"))
	} else {
		rtOn, _ := boolean(defender, "RealTimeProtectionEnabled")
		avOn, _ := boolean(defender, "AntivirusEnabled")
		mode := str(defender, "AMRunningMode")
		av.Source = model.Str("Get-MpComputerStatus")
		if av.Product == nil {
			av.Product = model.Str("Microsoft Defender Antivirus")
		}
		switch {
		case strings.EqualFold(mode, "Passive Mode") || strings.EqualFold(mode, "Passive"):
			av.Status = "PASSIVE"
			av.RealTimeProtection = model.StatusWarning
			if av.Status == "THIRD_PARTY" || len(products) > 1 {
				av.Status = "THIRD_PARTY"
			}
			r.Checks = append(r.Checks, rt.warn(fmt.Sprintf("Defender AMRunningMode=%s; real-time protection is delegated to the third-party product (not verified by the agent)", mode)))
		case rtOn && avOn:
			if av.Status != "THIRD_PARTY" {
				av.Status = "ACTIVE"
			}
			av.RealTimeProtection = model.StatusPass
			r.Checks = append(r.Checks, rt.pass(fmt.Sprintf("RealTimeProtectionEnabled=True AntivirusEnabled=True AMRunningMode=%s", mode)))
		default:
			if av.Status != "THIRD_PARTY" {
				av.Status = "DISABLED"
			}
			av.RealTimeProtection = model.StatusFail
			r.Checks = append(r.Checks, rt.fail(fmt.Sprintf("RealTimeProtectionEnabled=%v AntivirusEnabled=%v AMRunningMode=%s", rtOn, avOn, mode)))
		}
		if age, ok := num(defender, "AntivirusSignatureAge"); ok {
			d := int(age)
			av.DefinitionsAgeDays = &d
			if lu := str(defender, "AntivirusSignatureLastUpdated"); lu != "" {
				av.LastDefinitionUpdate = model.Str(lu)
			}
			ev := fmt.Sprintf("AntivirusSignatureAge=%d days (last updated %s)", d, str(defender, "AntivirusSignatureLastUpdated"))
			c := defs.pass(ev)
			if d > 7 {
				c = defs.fail(ev)
			} else if d > 3 {
				c = defs.warn(ev)
			}
			c.Details = map[string]interface{}{"ageDays": d, "lastUpdate": str(defender, "AntivirusSignatureLastUpdated")}
			r.Checks = append(r.Checks, c)
		} else {
			r.Checks = append(r.Checks, defs.unknown("AntivirusSignatureAge not reported"))
		}
	}
	// Attach the AV summary to the product check so the server can show it.
	for i := range r.Checks {
		if r.Checks[i].CheckID == "AV_PRODUCT" {
			r.Checks[i].Details = map[string]interface{}{"status": av.Status, "product": av.Product}
		}
	}
	r.Antivirus = av

	// Detection history (Defender only; third-party products are not queried).
	threats, terr := psList(ctx, "Get-MpThreatDetection | Sort-Object InitialDetectionTime -Descending | Select-Object -First 200 ThreatID,@{n='InitialDetectionTime';e={$_.InitialDetectionTime.ToString('o')}},ActionSuccess,CleaningActionID,ProcessName,@{n='Resources';e={($_.Resources -join '; ')}}")
	th := ck("THREAT_HISTORY", "ANTIVIRUS", "Antivirus detection history available", "Get-MpThreatDetection", "Standard user")
	if terr != nil {
		r.Checks = append(r.Checks, classify(th, terr))
	} else {
		for _, t := range threats {
			id := str(t, "ThreatID")
			name := "Defender threat ID " + id
			if names, nerr := psList(ctx, "Get-MpThreat -ThreatID "+sanitizeNum(id)+" | Select-Object ThreatName,SeverityID"); nerr == nil && len(names) > 0 {
				if n := str(names[0], "ThreatName"); n != "" {
					name = n
				}
			}
			det := str(t, "InitialDetectionTime")
			r.Threats = append(r.Threats, model.Threat{
				ExternalID:  model.Str(id + "@" + det),
				ThreatName:  name,
				DetectedAt:  nilIfEmpty(det),
				ActionTaken: model.Str("CleaningActionID=" + str(t, "CleaningActionID") + " ActionSuccess=" + str(t, "ActionSuccess")),
				Product:     "Microsoft Defender Antivirus",
				Source:      "Get-MpThreatDetection",
			})
		}
		r.Checks = append(r.Checks, th.pass(fmt.Sprintf("%d detection record(s) reported by Defender", len(threats))))
	}
	return nil
}

func sanitizeNum(s string) string {
	var b strings.Builder
	for _, c := range s {
		if c >= '0' && c <= '9' {
			b.WriteRune(c)
		}
	}
	if b.Len() == 0 {
		return "0"
	}
	return b.String()
}

func nilIfEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func winSoftware(ctx context.Context, r *model.CollectorResult) error {
	rows, err := psList(ctx, `$paths='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*','HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'; Get-ItemProperty -Path $paths -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -and -not $_.SystemComponent } | Select-Object DisplayName,DisplayVersion,Publisher,InstallDate | Sort-Object DisplayName -Unique`)
	if err != nil {
		return err
	}
	for _, row := range rows {
		item := model.Software{Name: str(row, "DisplayName"), Source: "registry:Uninstall"}
		if v := str(row, "DisplayVersion"); v != "" {
			item.Version = model.Str(v)
		}
		if p := str(row, "Publisher"); p != "" {
			item.Vendor = model.Str(p)
		}
		if d := str(row, "InstallDate"); len(d) == 8 {
			if t, perr := time.Parse("20060102", d); perr == nil {
				item.InstalledAt = model.Str(t.UTC().Format(time.RFC3339))
			}
		}
		r.Software = append(r.Software, item)
	}
	r.Checks = append(r.Checks, ck("SOFTWARE_INVENTORY_COLLECTED", "SYSTEM", "Installed software inventory collected", "registry Uninstall keys (HKLM, WOW6432Node, HKCU)", "Standard user").pass(fmt.Sprintf("%d installed applications enumerated", len(r.Software))))
	return nil
}

func winStartup(ctx context.Context, r *model.CollectorResult) error {
	runKeys, err := psList(ctx, `$keys='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run','HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run','HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run','HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'; foreach($k in $keys){ if(Test-Path $k){ $p=Get-ItemProperty $k; $p.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' } | ForEach-Object { [pscustomobject]@{Key=$k;Name=$_.Name;Value=[string]$_.Value} } } }`)
	if err != nil {
		r.Checks = append(r.Checks, classify(ck("STARTUP_RUN_KEYS", "SYSTEM", "Registry Run keys enumerated", "registry Run/RunOnce", "Standard user"), err))
	} else {
		for _, k := range runKeys {
			r.StartupItems = append(r.StartupItems, model.StartupItem{Name: str(k, "Name"), Location: str(k, "Key") + " => " + truncate(str(k, "Value"), 900), Kind: "REGISTRY_RUN", Enabled: boolPtr(true)})
		}
	}
	folders, err := psList(ctx, `Get-ChildItem -Path "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp","$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup" -File -ErrorAction SilentlyContinue | Select-Object Name,FullName`)
	if err == nil {
		for _, f := range folders {
			r.StartupItems = append(r.StartupItems, model.StartupItem{Name: str(f, "Name"), Location: str(f, "FullName"), Kind: "STARTUP_FOLDER", Enabled: boolPtr(true)})
		}
	}
	tasks, err := psList(ctx, `Get-ScheduledTask | Where-Object { $_.TaskPath -notlike '\Microsoft\*' } | Select-Object TaskName,TaskPath,State,Author`)
	if err != nil {
		r.Checks = append(r.Checks, classify(ck("STARTUP_SCHEDULED_TASKS", "SYSTEM", "Non-Microsoft scheduled tasks enumerated", "Get-ScheduledTask", "Standard user"), err))
	} else {
		for _, t := range tasks {
			en := !strings.EqualFold(str(t, "State"), "Disabled")
			item := model.StartupItem{Name: str(t, "TaskName"), Location: str(t, "TaskPath") + str(t, "TaskName"), Kind: "SCHEDULED_TASK", Enabled: &en}
			if a := str(t, "Author"); a != "" {
				item.Publisher = model.Str(a)
			}
			r.StartupItems = append(r.StartupItems, item)
		}
	}
	services, err := psList(ctx, `Get-CimInstance Win32_Service | Where-Object { $_.StartMode -eq 'Auto' -and $_.PathName -notlike '*\Windows\system32\svchost.exe*' } | Select-Object Name,DisplayName,PathName,State,StartMode`)
	if err != nil {
		r.Checks = append(r.Checks, classify(ck("STARTUP_SERVICES", "SYSTEM", "Auto-start services enumerated", "Win32_Service", "Standard user"), err))
	} else {
		for _, s := range services {
			r.StartupItems = append(r.StartupItems, model.StartupItem{Name: str(s, "DisplayName") + " (" + str(s, "Name") + ")", Location: truncate(str(s, "PathName"), 900), Kind: "SERVICE", Enabled: boolPtr(true)})
		}
	}
	r.Checks = append(r.Checks, ck("STARTUP_INVENTORY_COLLECTED", "SYSTEM", "Startup persistence inventory collected", "registry Run keys, Startup folders, Get-ScheduledTask, Win32_Service", "Standard user").pass(fmt.Sprintf("%d startup items enumerated", len(r.StartupItems))))
	return nil
}

func winNetwork(ctx context.Context, r *model.CollectorResult) error {
	// SMBv1
	smb := ck("SMBV1", "NETWORK", "SMBv1 protocol disabled", "Get-SmbServerConfiguration / Windows optional features", "Standard user")
	var cfg map[string]interface{}
	if err := ps(ctx, &cfg, "Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol,EnableSMB2Protocol"); err != nil {
		r.Checks = append(r.Checks, classify(smb, err))
	} else if v, ok := boolean(cfg, "EnableSMB1Protocol"); ok {
		if v {
			r.Checks = append(r.Checks, smb.fail("EnableSMB1Protocol=True"))
		} else {
			r.Checks = append(r.Checks, smb.pass("EnableSMB1Protocol=False"))
		}
	} else {
		r.Checks = append(r.Checks, smb.unknown("EnableSMB1Protocol not reported"))
	}
	// Active network profile category (public/private/domain) — descriptive only.
	np := ck("NETWORK_PROFILE", "NETWORK", "Active network connection profile", "Get-NetConnectionProfile", "Standard user")
	profiles, err := psList(ctx, "Get-NetConnectionProfile | Select-Object Name,NetworkCategory,IPv4Connectivity")
	if err != nil {
		r.Checks = append(r.Checks, classify(np, err))
	} else {
		var parts []string
		for _, p := range profiles {
			parts = append(parts, fmt.Sprintf("%s=%s", str(p, "Name"), str(p, "NetworkCategory")))
		}
		if len(parts) == 0 {
			r.Checks = append(r.Checks, np.unknown("No active connection profiles"))
		} else {
			r.Checks = append(r.Checks, np.pass("Profiles: "+strings.Join(parts, "; ")+" (informational; no traffic is inspected)"))
		}
	}
	// Firewall logging/inbound default action summary per profile.
	fwd := ck("FIREWALL_INBOUND_DEFAULT", "FIREWALL", "Firewall blocks inbound connections by default", "Get-NetFirewallProfile", "Standard user")
	fps, err := psList(ctx, "Get-NetFirewallProfile | Select-Object Name,DefaultInboundAction")
	if err != nil {
		r.Checks = append(r.Checks, classify(fwd, err))
	} else {
		var allow []string
		for _, p := range fps {
			if a := str(p, "DefaultInboundAction"); a == "Allow" || a == "2" {
				allow = append(allow, str(p, "Name"))
			}
		}
		if len(fps) == 0 {
			r.Checks = append(r.Checks, fwd.unknown("No firewall profiles returned"))
		} else if len(allow) > 0 {
			r.Checks = append(r.Checks, fwd.fail("DefaultInboundAction=Allow for: "+strings.Join(allow, ", ")))
		} else {
			r.Checks = append(r.Checks, fwd.pass("Inbound default is Block (or NotConfigured → Block) on all profiles"))
		}
	}
	_ = runtime.GOOS
	return nil
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
