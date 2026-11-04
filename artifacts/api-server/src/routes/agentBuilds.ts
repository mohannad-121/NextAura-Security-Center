import { Router, type IRouter } from "express";
import path from "node:path";
import { asyncHandler } from "../lib/asyncHandler";
import { requireOrg } from "../middlewares/auth";
import { notFound } from "../lib/errors";
import {
  AGENT_DIST_DIR,
  listAgentBuilds,
  platformFile,
} from "../services/agentBuilds";

const router: IRouter = Router();
router.use(requireOrg);

router.get(
  "/agent-builds",
  asyncHandler(async (_req, res) => {
    res.json(await listAgentBuilds());
  }),
);

router.get(
  "/agent-builds/:platform/download",
  asyncHandler(async (req, res) => {
    const p = platformFile(String(req.params["platform"]));
    if (!p) throw notFound("Unknown platform");
    const builds = await listAgentBuilds();
    const build = builds.find((b) => b.platform === p.platform);
    if (!build?.available || !build.verified || !build.downloadPath) {
      throw notFound(
        "No verified install package is available for this platform",
      );
    }
    res.setHeader("X-Checksum-SHA256", build.sha256 ?? "");
    res.setHeader("Content-Security-Policy", "default-src 'none'; sandbox");
    res.download(path.join(AGENT_DIST_DIR, p.fileName), p.fileName);
  }),
);

export default router;
