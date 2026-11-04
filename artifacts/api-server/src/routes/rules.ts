import { Router, type IRouter } from "express";
import { requireOrg } from "../middlewares/auth";
import { RULES } from "../services/rules";

const router: IRouter = Router();

const VULN_RULES = [
  { ruleId: "VULN_KEV", title: "Known exploited vulnerability present", description: "Installed software matches a CVE listed in the CISA Known Exploited Vulnerabilities catalog.", severity: "CRITICAL", triggerLogic: "Vulnerability match with knownExploited=true and confidence CONFIRMED or PROBABLE.", evidenceRequirement: "Software inventory entry with version inside the NVD affected range; CVE present in KEV.", remediation: "Update or remove the affected software immediately; follow the CISA required action.", platforms: ["WINDOWS", "MACOS"], collectorId: "SOFTWARE_INVENTORY" },
  { ruleId: "VULN_CRITICAL", title: "Critical CVE present", description: "Installed software matches a CVSS critical CVE with confirmed vendor, product and version range.", severity: "HIGH", triggerLogic: "Vulnerability match with severity CRITICAL and confidence CONFIRMED.", evidenceRequirement: "Vendor, product and version all match the NVD CPE configuration.", remediation: "Update the affected software to a fixed version.", platforms: ["WINDOWS", "MACOS"], collectorId: "SOFTWARE_INVENTORY" },
  { ruleId: "AGENT_OFFLINE", title: "Agent has not reported for an extended period", description: "No heartbeat has been received for more than 3 days; the device's current state is unknown.", severity: "MEDIUM", triggerLogic: "lastSeenAt older than 72 hours for an ACTIVE device.", evidenceRequirement: "Server-side heartbeat timestamps.", remediation: "Confirm the device is powered on and the agent service is running; re-enroll if the token expired.", platforms: ["WINDOWS", "MACOS"], collectorId: "SYSTEM_INFO" },
] as const;

router.get("/rules", requireOrg, (_req, res) => {
  res.json([
    ...RULES.map(({ evaluate: _e, ...r }) => r),
    ...VULN_RULES,
  ]);
});

export default router;
