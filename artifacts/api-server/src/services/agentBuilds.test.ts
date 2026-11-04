import assert from "node:assert/strict";
import { test } from "node:test";
import { listAgentBuilds, platformFile } from "./agentBuilds";

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
    if (build.available && !build.verified)
      assert.equal(build.downloadPath, null);
  }
});
