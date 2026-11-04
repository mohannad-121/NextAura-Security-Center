export type EnrollmentState = "VALID" | "EXPIRED" | "USED" | "CANCELLED";

export function enrollmentState(
  enrollment: {
    status: "PENDING" | "CONSUMED" | "EXPIRED" | "CANCELLED";
    expiresAt: Date;
  },
  now = Date.now(),
): EnrollmentState {
  if (enrollment.status === "CONSUMED") return "USED";
  if (enrollment.status === "CANCELLED") return "CANCELLED";
  if (enrollment.status === "EXPIRED" || enrollment.expiresAt.getTime() < now)
    return "EXPIRED";
  return "VALID";
}
