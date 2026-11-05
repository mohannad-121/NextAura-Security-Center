import { and, desc, eq } from "drizzle-orm";
import { db, devicesTable, securityFindingsTable } from "@workspace/db";
import { serializeFinding } from "./serializers";

/** Tenant-scoped finding retrieval shared by routes and database integration tests. */
export async function listFindingsForOrganization(organizationId: string) {
  const rows = await db
    .select({ finding: securityFindingsTable, deviceName: devicesTable.name })
    .from(securityFindingsTable)
    .innerJoin(
      devicesTable,
      eq(devicesTable.id, securityFindingsTable.deviceId),
    )
    .where(
      and(
        eq(securityFindingsTable.organizationId, organizationId),
        eq(devicesTable.organizationId, organizationId),
      ),
    )
    .orderBy(desc(securityFindingsTable.lastSeenAt));
  return rows.map(({ finding, deviceName }) =>
    serializeFinding(finding, deviceName),
  );
}
