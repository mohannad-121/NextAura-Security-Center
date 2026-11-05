import express, { type Express, type RequestHandler } from "express";
import cors from "cors";
import pinoHttp from "pino-http";
import { clerkMiddleware } from "@clerk/express";
import { publishableKeyFromHost } from "@clerk/shared/keys";
import {
  CLERK_PROXY_PATH,
  clerkProxyMiddleware,
  getClerkProxyHost,
} from "./middlewares/clerkProxyMiddleware";
import healthRouter from "./routes/health";
import { logger } from "./lib/logger";
import { errorHandler } from "./middlewares/errorHandler";
import {
  missingDatabaseConfiguration,
  missingOperatorConfiguration,
  requireRuntimeConfiguration,
} from "./lib/runtimeConfiguration";

function lazyRouter(
  load: () => Promise<{ default: RequestHandler }>,
): RequestHandler {
  let pending: Promise<RequestHandler> | undefined;
  return async (req, res, next) => {
    try {
      pending ??= load().then((module) => module.default);
      const router = await pending;
      router(req, res, next);
    } catch (error) {
      next(error);
    }
  };
}

const agentRouter = lazyRouter(() => import("./routes/agent"));
const operatorRouter = lazyRouter(() => import("./routes"));

let operatorAuth: RequestHandler | undefined;
const operatorAuthMiddleware: RequestHandler = (req, res, next) => {
  operatorAuth ??= clerkMiddleware((request) => ({
    publishableKey: publishableKeyFromHost(
      getClerkProxyHost(request) ?? "",
      process.env.CLERK_PUBLISHABLE_KEY,
    ),
  }));
  operatorAuth(req, res, next);
};

const app: Express = express();
app.set("trust proxy", true);
app.disable("x-powered-by");

app.use(
  pinoHttp({
    logger,
    serializers: {
      req(req) {
        return {
          id: req.id,
          method: req.method,
          url: req.url?.split("?")[0],
        };
      },
      res(res) {
        return {
          statusCode: res.statusCode,
        };
      },
    },
  }),
);

// Security headers (no inline policy for the API; the SPA is served separately).
app.use((_req, res, next) => {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader("Cache-Control", "no-store");
  next();
});

app.use(CLERK_PROXY_PATH, clerkProxyMiddleware());

// Liveness stays available without staging credentials. Every dependent route
// below fails closed with a 503 until its required variable names are present.
app.use("/api", healthRouter);

// Agent API: device-token auth, no Clerk, strict body limit, no CORS needed.
app.use(
  "/api/agent/v1",
  requireRuntimeConfiguration(missingDatabaseConfiguration),
  express.json({ limit: "2mb" }),
  agentRouter,
);

const allowedOrigins = new Set(
  (process.env.APP_ORIGINS ?? "")
    .split(",")
    .map((origin) => origin.trim())
    .filter(Boolean),
);
if (allowedOrigins.size > 0) {
  app.use(
    cors({
      credentials: true,
      origin(origin, callback) {
        callback(null, !origin || allowedOrigins.has(origin));
      },
    }),
  );
}
app.use(express.json({ limit: "256kb" }));
app.use(express.urlencoded({ extended: true }));

// Resolve Clerk only after configuration validation. This keeps the function
// importable for liveness checks and produces a deterministic 503 rather than
// a cold-start crash when isolated staging credentials have not been set.
app.use(
  "/api",
  requireRuntimeConfiguration(missingOperatorConfiguration),
  operatorAuthMiddleware,
  operatorRouter,
);

app.use(errorHandler);

export default app;
