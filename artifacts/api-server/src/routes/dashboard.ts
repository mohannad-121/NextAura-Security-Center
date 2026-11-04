import { Router, type IRouter } from "express";
import { GetDashboardActivityQueryParams } from "@workspace/api-zod";
import { asyncHandler } from "../lib/asyncHandler";
import { requireOrg, ctx } from "../middlewares/auth";
import { dashboardSummary, dashboardActivity } from "../services/dashboard";

const router: IRouter = Router();

router.get("/dashboard/summary", requireOrg, asyncHandler(async (req, res) => {
  res.json(await dashboardSummary(ctx(req).organization));
}));

router.get("/dashboard/activity", requireOrg, asyncHandler(async (req, res) => {
  const q = GetDashboardActivityQueryParams.parse(req.query);
  res.json(await dashboardActivity(ctx(req).organization, q.limit));
}));

export default router;
