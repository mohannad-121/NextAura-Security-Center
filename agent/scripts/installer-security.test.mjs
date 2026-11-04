import assert from "node:assert/strict";
import { promises as fs } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";

const scriptsDir = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(scriptsDir, "../..");

test("installers keep enrollment codes out of commands and process arguments", async () => {
  const windows = await fs.readFile(
    path.join(scriptsDir, "install-service-windows.ps1"),
    "utf8",
  );
  const macos = await fs.readFile(
    path.join(scriptsDir, "install-service-macos.sh"),
    "utf8",
  );
  const ui = await fs.readFile(
    path.join(repoRoot, "artifacts/security-center/src/pages/enroll.tsx"),
    "utf8",
  );

  assert.match(windows, /Read-Host.+-AsSecureString/);
  assert.match(windows, /--code-stdin/);
  assert.doesNotMatch(windows, /EnrollmentCode/);
  assert.match(macos, /read -r -s ENROLLMENT_CODE < \/dev\/tty/);
  assert.match(macos, /--code-stdin/);
  assert.doesNotMatch(macos, /--code(?:\s|=)/);
  assert.doesNotMatch(ui, /EnrollmentCode/);
  assert.doesNotMatch(ui, /--code(?:\s|=)/);
});

test("macOS installer creates standard destinations before copying", async () => {
  const macos = await fs.readFile(
    path.join(scriptsDir, "install-service-macos.sh"),
    "utf8",
  );
  assert.match(macos, /install -d -m 0755 \/usr\/local\/bin/);
  assert.match(macos, /install -d -m 0700 "\$STATE_DIRECTORY"/);
});
