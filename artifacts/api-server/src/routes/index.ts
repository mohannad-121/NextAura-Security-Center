import { Router, type IRouter } from "express";
import healthRouter from "./health";
import meRouter from "./me";
import dashboardRouter from "./dashboard";
import devicesRouter from "./devices";
import findingsRouter from "./findings";
import vulnerabilitiesRouter from "./vulnerabilities";
import enrollmentsRouter from "./enrollments";
import agentBuildsRouter from "./agentBuilds";
import reportsRouter from "./reports";
import settingsRouter from "./settings";
import emailSecurityRouter from "./emailSecurity";
import rulesRouter from "./rules";

const router: IRouter = Router();

router.use(healthRouter);
router.use(meRouter);
router.use(dashboardRouter);
router.use(devicesRouter);
router.use(findingsRouter);
router.use(vulnerabilitiesRouter);
router.use(enrollmentsRouter);
router.use(agentBuildsRouter);
router.use(reportsRouter);
router.use(settingsRouter);
router.use(emailSecurityRouter);
router.use(rulesRouter);

export default router;
