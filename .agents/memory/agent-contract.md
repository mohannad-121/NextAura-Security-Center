---
name: Agent contract sync
description: How the Go agent and API server stay in sync and the honesty invariants the user requires.
---
Rule: the agent↔server protocol lives in two hand-maintained places (server Zod contract under routes/agent, Go structs under agent/internal/model). Any field or enum change must be made in both, and the six collector IDs are fixed everywhere (agent registry, Zod enum, DB enum).

**Why:** the user's spec forbids dynamic/remote execution and fabricated results; collector IDs being a closed set on both sides is the enforcement point. Any check that was not observed must be UNKNOWN/UNSUPPORTED/PERMISSION_DENIED and must never be treated as PASS (coverage drops, visibility-gap finding opens).

**How to apply:** when adding a check or collector field, update contract.ts, model.go, the platform collectors, and rules.ts together; keep no demo/seed data in real orgs (test data was created and deleted via throwaway scripts).
