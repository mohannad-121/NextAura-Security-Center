import { createHash } from "node:crypto";
import { promises as fs } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const PACKAGES = [
  ["darwin-amd64", "nextaura-agent-darwin-amd64.tar.gz"],
  ["darwin-arm64", "nextaura-agent-darwin-arm64.tar.gz"],
  ["windows-amd64", "nextaura-agent-windows-amd64.zip"],
];

function digest(value) {
  return createHash("sha256").update(value).digest("hex");
}

export function artifactBuildId(version, platform, sha256) {
  return digest(`${version}\n${platform}\n${sha256}`);
}

export async function buildManifest(distDir, version, builtAt) {
  const artifacts = {};
  const checksumLines = [];
  for (const [platform, fileName] of PACKAGES) {
    try {
      const bytes = await fs.readFile(path.join(distDir, fileName));
      const sha256 = digest(bytes);
      checksumLines.push(`${sha256}  ${fileName}`);
      artifacts[platform] = {
        fileName,
        sha256,
        buildId: artifactBuildId(version, platform, sha256),
        nativeVerification: null,
      };
    } catch (error) {
      if (error?.code !== "ENOENT") throw error;
    }
  }
  if (Object.keys(artifacts).length === 0) {
    throw new Error(`No complete install packages found in ${distDir}`);
  }
  const buildSetId = digest(
    Object.entries(artifacts)
      .map(([platform, artifact]) => `${platform}:${artifact.buildId}`)
      .join("\n"),
  );
  return {
    manifest: {
      schemaVersion: 2,
      version,
      builtAt,
      buildSetId,
      artifacts,
    },
    checksumText: `${checksumLines.join("\n")}\n`,
  };
}

export async function writeManifest(distDir, version, builtAt) {
  const { manifest, checksumText } = await buildManifest(
    distDir,
    version,
    builtAt,
  );
  await fs.writeFile(
    path.join(distDir, "manifest.json"),
    `${JSON.stringify(manifest, null, 2)}\n`,
    "utf8",
  );
  await fs.writeFile(path.join(distDir, "SHA256SUMS"), checksumText, "utf8");
  return manifest;
}

const invokedPath = process.argv[1] ? path.resolve(process.argv[1]) : "";
if (invokedPath === fileURLToPath(import.meta.url)) {
  const version = process.argv[2];
  const builtAt = process.argv[3] ?? new Date().toISOString();
  if (!version)
    throw new Error("usage: node write-manifest.mjs <version> [built-at]");
  const distDir = path.resolve(
    path.dirname(fileURLToPath(import.meta.url)),
    "../dist",
  );
  const manifest = await writeManifest(distDir, version, builtAt);
  process.stdout.write(`${JSON.stringify(manifest, null, 2)}\n`);
}
