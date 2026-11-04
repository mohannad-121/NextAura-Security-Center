import { db, auditLogsTable } from "@workspace/db";

export async function audit(entry: {
  organizationId: string;
  actorType: "USER" | "DEVICE" | "SYSTEM";
  actorId?: string | null;
  actorLabel: string;
  action: string;
  targetType?: string;
  targetId?: string;
  details?: Record<string, unknown>;
  ipAddress?: string | null;
}) {
  await db.insert(auditLogsTable).values({
    organizationId: entry.organizationId,
    actorType: entry.actorType,
    actorId: entry.actorId ?? null,
    actorLabel: entry.actorLabel,
    action: entry.action,
    targetType: entry.targetType ?? null,
    targetId: entry.targetId ?? null,
    details: entry.details ?? {},
    ipAddress: entry.ipAddress ?? null,
  });
}
