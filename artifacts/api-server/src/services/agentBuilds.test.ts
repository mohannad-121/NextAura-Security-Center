import assert from "node:assert/strict";
import { test } from "node:test";
import { createHash } from "node:crypto";
import { promises as fs } from "node:fs";
import os from "node:os";
import path from "node:path";
import { artifactBuildId, listAgentBuilds, platformFile } from "./agentBuilds";

test("all supported targets map to complete install packages", () => {
  assert.equal(
    platformFile("windows-amd64")?.fileName,
    "nextaura-agent-windows-amd64.zip",
  );
  assert.equal(
    platformFile("darwin-amd64")?.fileName,
    "nextaura-agent-darwin-amd64.tar.gz",
  );
  assert.equal(
    platformFile("darwin-arm64")?.fileName,
    "nextaura-agent-darwin-arm64.tar.gz",
  );
  assert.equal(platformFile("linux-amd64"), null);
});

test("unverified packages are never exposed as downloads", async () => {
  const builds = await listAgentBuilds();
  assert.equal(builds.length, 3);
  for (const build of builds) {
    if (build.available && !build.verified) {
      assert.equal(build.downloadPath, null);
      assert.match(build.verificationNote, /integrity matches the manifest/);
      assert.equal(build.signed, false);
    }
  }
});

async function temporaryBuild() {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "nextaura-builds-"));
  const fileName = "nextaura-agent-windows-amd64.zip";
  const packagePath = path.join(dir, fileName);
  await fs.writeFile(packagePath, "package-v1");
  const sha256 = createHash("sha256").update("package-v1").digest("hex");
  const buildId = artifactBuildId("0.1.0", "windows-amd64", sha256);
  return { dir, fileName, packagePath, sha256, buildId };
}

test("native approval is bound to exact package hash and build identity", async (t) => {
  const build = await temporaryBuild();
  t.after(() => fs.rm(build.dir, { recursive: true, force: true }));
  await fs.writeFile(
    path.join(build.dir, "manifest.json"),
    JSON.stringify({
      schemaVersion: 2,
      version: "0.1.0",
      builtAt: "2026-11-04T00:00:00Z",
      artifacts: {
        "windows-amd64": {
          fileName: build.fileName,
          sha256: build.sha256,
          buildId: build.buildId,
          nativeVerification: {
            sha256: build.sha256,
            buildId: build.buildId,
            testedAt: "2026-11-04T00:01:00Z",
            evidence: "staging enrollment test record TEST-123",
          },
        },
      },
    }),
  );
  let windows = (await listAgentBuilds(build.dir))[0]!;
  assert.equal(windows.verified, true);
  assert.equal(
    windows.downloadPath,
    "/api/agent-builds/windows-amd64/download",
  );

  await fs.writeFile(build.packagePath, "package-v2");
  windows = (await listAgentBuilds(build.dir))[0]!;
  assert.equal(windows.verified, false);
  assert.equal(windows.downloadPath, null);
});

test("legacy booleans cannot approve or claim signing for a package", async (t) => {
  const build = await temporaryBuild();
  t.after(() => fs.rm(build.dir, { recursive: true, force: true }));
  await fs.writeFile(
    path.join(build.dir, "manifest.json"),
    JSON.stringify({
      version: "0.1.0",
      verified: { "windows-amd64": true },
      signed: { "windows-amd64": true },
    }),
  );
  const windows = (await listAgentBuilds(build.dir))[0]!;
  assert.equal(windows.verified, false);
  assert.equal(windows.signed, false);
  assert.equal(windows.downloadPath, null);
});
