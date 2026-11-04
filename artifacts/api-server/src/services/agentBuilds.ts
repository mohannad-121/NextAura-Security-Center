import { promises as fs } from "node:fs";
import path from "node:path";
import { createHash } from "node:crypto";

import { existsSync } from "node:fs";

/**
 * Locate agent/dist. In development the server's cwd is artifacts/api-server;
 * in production it is the repository root. Check both plus the env override.
 */
function resolveDistDir(): string {
  const candidates = [
    process.env.AGENT_DIST_DIR,
    path.resolve(process.cwd(), "agent/dist"),
    path.resolve(process.cwd(), "../../agent/dist"),
  ].filter((c): c is string => !!c);
  return (
    candidates.find((c) => existsSync(c)) ?? candidates[candidates.length - 1]!
  );
}

export const AGENT_DIST_DIR = resolveDistDir();

const PLATFORMS = [
  {
    platform: "windows-amd64",
    osType: "WINDOWS",
    architecture: "amd64",
    fileName: "nextaura-agent-windows-amd64.zip",
  },
  {
    platform: "darwin-amd64",
    osType: "MACOS",
    architecture: "amd64",
    fileName: "nextaura-agent-darwin-amd64.tar.gz",
  },
  {
    platform: "darwin-arm64",
    osType: "MACOS",
    architecture: "arm64",
    fileName: "nextaura-agent-darwin-arm64.tar.gz",
  },
] as const;

export type PlatformId = (typeof PLATFORMS)[number]["platform"];

export function platformFile(platform: string) {
  return PLATFORMS.find((p) => p.platform === platform) ?? null;
}

interface Manifest {
  version?: string;
  builtAt?: string;
  verified?: Partial<Record<PlatformId, boolean>>;
  signed?: Partial<Record<PlatformId, boolean>>;
}

async function readManifest(): Promise<Manifest> {
  try {
    return JSON.parse(
      await fs.readFile(path.join(AGENT_DIST_DIR, "manifest.json"), "utf8"),
    ) as Manifest;
  } catch {
    return {};
  }
}

export async function listAgentBuilds() {
  const manifest = await readManifest();
  return Promise.all(
    PLATFORMS.map(async (p) => {
      const file = path.join(AGENT_DIST_DIR, p.fileName);
      let stat: Awaited<ReturnType<typeof fs.stat>> | null = null;
      try {
        stat = await fs.stat(file);
      } catch {
        stat = null;
      }
      const available = !!stat && stat.isFile() && stat.size > 0;
      let sha256: string | null = null;
      if (available) {
        const buf = await fs.readFile(file);
        sha256 = createHash("sha256").update(buf).digest("hex");
      }
      const verified = available && manifest.verified?.[p.platform] === true;
      return {
        platform: p.platform,
        osType: p.osType,
        architecture: p.architecture,
        available,
        fileName: p.fileName,
        sizeBytes: available ? stat!.size : null,
        sha256,
        version: available ? (manifest.version ?? null) : null,
        builtAt: available ? (manifest.builtAt ?? null) : null,
        verified,
        verificationNote: !available
          ? "No complete install package is present on this server. Build it on the target OS and place the package in agent/dist/."
          : verified
            ? "Package passed a native test enrollment and is approved for controlled testing."
            : "Package exists but download is disabled until a native test enrollment is recorded in agent/dist/manifest.json.",
        downloadPath: verified
          ? `/api/agent-builds/${p.platform}/download`
          : null,
        signed: available && manifest.signed?.[p.platform] === true,
      };
    }),
  );
}
