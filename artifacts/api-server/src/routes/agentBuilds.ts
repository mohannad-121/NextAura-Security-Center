import { Router, type IRouter } from "express";
import path from "node:path";
import { asyncHandler } from "../lib/asyncHandler";
import { requireOrg } from "../middlewares/auth";
import { notFound } from "../lib/errors";
import { AGENT_DIST_DIR, listAgentBuilds, platformFile } from "../services/agentBuilds";

const router: IRouter = Router();
router.use(requireOrg);

router.get("/agent-builds", asyncHandler(async (_req, res) => {
  res.json(await listAgentBuilds());
}));

router.get("/agent-builds/:platform/download", asyncHandler(async (req, res) => {
  const p = platformFile(String(req.params["platform"]));
  if (!p) throw notFound("Unknown platform");
  const builds = await listAgentBuilds();
  if (!builds.find((b) => b.platform === p.platform)?.available) throw notFound("No build available for this platform");
  res.setHeader("X-Checksum-SHA256", builds.find((b) => b.platform === p.platform)!.sha256 ?? "");
  res.download(path.join(AGENT_DIST_DIR, p.fileName), p.fileName);
}));

export default router;
