import { eq } from "drizzle-orm";
import { db, scanJobDevicesTable, scanJobsTable } from "@workspace/db";

type ScanStatus = typeof scanJobDevicesTable.$inferSelect.status;

const terminal = new Set<ScanStatus>([
  "COMPLETED",
  "PARTIAL",
  "FAILED",
  "CANCELLED",
  "EXPIRED",
]);

export async function recomputeScanJob(scanJobId: string): Promise<void> {
  const targets = await db
    .select({ status: scanJobDevicesTable.status })
    .from(scanJobDevicesTable)
    .where(eq(scanJobDevicesTable.scanJobId, scanJobId));
  if (!targets.length) return;
  const statuses = targets.map((target) => target.status);
  let status: ScanStatus;
  if (statuses.some((value) => value === "RUNNING")) status = "RUNNING";
  else if (statuses.some((value) => !terminal.has(value)))
    status = "WAITING_FOR_AGENT";
  else if (statuses.every((value) => value === "COMPLETED"))
    status = "COMPLETED";
  else if (statuses.every((value) => value === "CANCELLED"))
    status = "CANCELLED";
  else if (statuses.every((value) => value === "EXPIRED")) status = "EXPIRED";
  else if (
    statuses.some((value) => value === "COMPLETED" || value === "PARTIAL")
  )
    status = "PARTIAL";
  else status = "FAILED";
  await db
    .update(scanJobsTable)
    .set({ status, completedAt: terminal.has(status) ? new Date() : null })
    .where(eq(scanJobsTable.id, scanJobId));
}

export async function markTargetByRequest(
  requestId: string,
  values: Partial<typeof scanJobDevicesTable.$inferInsert>,
): Promise<void> {
  const [target] = Object.keys(values).length
    ? await db
        .update(scanJobDevicesTable)
        .set(values)
        .where(eq(scanJobDevicesTable.agentRequestId, requestId))
        .returning({ scanJobId: scanJobDevicesTable.scanJobId })
    : await db
        .select({ scanJobId: scanJobDevicesTable.scanJobId })
        .from(scanJobDevicesTable)
        .where(eq(scanJobDevicesTable.agentRequestId, requestId));
  if (target) await recomputeScanJob(target.scanJobId);
}
