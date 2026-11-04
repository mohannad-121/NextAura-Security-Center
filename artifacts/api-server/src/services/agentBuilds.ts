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

interface NativeVerification {
  sha256?: string;
  buildId?: string;
  testedAt?: string;
  evidence?: string;
}

interface ManifestArtifact {
  fileName?: string;
  sha256?: string;
  buildId?: string;
  nativeVerification?: NativeVerification | null;
}

interface Manifest {
  schemaVersion?: number;
  version?: string;
  builtAt?: string;
  artifacts?: Partial<Record<PlatformId, ManifestArtifact>>;
}

async function readManifest(distDir: string): Promise<Manifest> {
  try {
    return JSON.parse(
      await fs.readFile(path.join(distDir, "manifest.json"), "utf8"),
    ) as Manifest;
  } catch {
    return {};
  }
}

export function artifactBuildId(
  version: string,
  platform: PlatformId,
  sha256: string,
): string {
  return createHash("sha256")
    .update(`${version}\n${platform}\n${sha256}`)
    .digest("hex");
}

export async function listAgentBuilds(distDir = AGENT_DIST_DIR) {
  const manifest = await readManifest(distDir);
  return Promise.all(
    PLATFORMS.map(async (p) => {
      const file = path.join(distDir, p.fileName);
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
      const artifact = manifest.artifacts?.[p.platform];
      const version = manifest.version ?? "";
      const expectedBuildId =
        sha256 && version ? artifactBuildId(version, p.platform, sha256) : null;
      const manifestMatches =
        available &&
        manifest.schemaVersion === 2 &&
        artifact?.fileName === p.fileName &&
        artifact.sha256 === sha256 &&
        artifact.buildId === expectedBuildId;
      const approval = artifact?.nativeVerification;
      const verified =
        manifestMatches &&
        !!approval &&
        approval.sha256 === sha256 &&
        approval.buildId === expectedBuildId &&
        !!approval.testedAt &&
        !!approval.evidence;
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
          : !manifestMatches
            ? "Package exists but its SHA-256/build identity does not match manifest.json. Rebuild it before testing."
            : verified
              ? "Package passed a native test enrollment and is approved for controlled testing."
              : "Package integrity matches the manifest, but download is disabled until a hash-bound native test record is added.",
        downloadPath: verified
          ? `/api/agent-builds/${p.platform}/download`
          : null,
        // Signing is deliberately never inferred from editable metadata. A
        // future release system must cryptographically verify the package.
        signed: false,
      };
    }),
  );
}
