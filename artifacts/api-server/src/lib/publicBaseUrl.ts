function normalize(raw: string, allowLoopbackHttp: boolean): string {
  const url = new URL(raw.trim());
  const loopback = ["localhost", "127.0.0.1", "::1"].includes(url.hostname);
  if (
    url.protocol !== "https:" &&
    !(allowLoopbackHttp && url.protocol === "http:" && loopback)
  ) {
    throw new Error(
      "AGENT_PUBLIC_BASE_URL must use https:// (http is allowed only for loopback development)",
    );
  }
  if (
    url.username ||
    url.password ||
    url.search ||
    url.hash ||
    (url.pathname !== "/" && url.pathname !== "")
  ) {
    throw new Error(
      "AGENT_PUBLIC_BASE_URL must be an origin without credentials, path, query, or fragment",
    );
  }
  return url.origin;
}

interface OriginRequest {
  protocol: string;
  get(name: string): string | string[] | undefined;
}

function firstHeader(value: string | string[] | undefined): string | undefined {
  const raw = Array.isArray(value) ? value[0] : value;
  return raw?.split(",")[0]?.trim() || undefined;
}

/** Returns the one canonical origin agents are allowed to enroll against. */
export function agentPublicBaseUrl(req: OriginRequest): string {
  const configured = process.env.AGENT_PUBLIC_BASE_URL;
  const production = process.env.NODE_ENV === "production";
  if (configured) return normalize(configured, !production);
  if (production)
    throw new Error("AGENT_PUBLIC_BASE_URL is required in production");

  const forwardedHost = firstHeader(req.get("x-forwarded-host"));
  const host = forwardedHost || firstHeader(req.get("host")) || "localhost";
  const forwardedProto = firstHeader(req.get("x-forwarded-proto"));
  return normalize(`${forwardedProto || req.protocol}://${host}`, true);
}
