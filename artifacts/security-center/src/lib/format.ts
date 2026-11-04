import { format, formatDistanceToNowStrict } from "date-fns";

export function fmtDate(s?: string | null) {
  if (!s) return "—";
  const d = new Date(s);
  return isNaN(d.getTime()) ? "—" : format(d, "d MMM yyyy, HH:mm");
}
export function fmtDay(s?: string | null) {
  if (!s) return "—";
  const d = new Date(s);
  return isNaN(d.getTime()) ? "—" : format(d, "d MMM yyyy");
}
export function fmtRel(s?: string | null, never = "Never") {
  if (!s) return never;
  const d = new Date(s);
  return isNaN(d.getTime()) ? never : formatDistanceToNowStrict(d, { addSuffix: true });
}
export function humanize(s: string) {
  return s.replace(/_/g, " ").toLowerCase().replace(/^\w/, (c) => c.toUpperCase());
}
export function fmtBytes(n?: number | null) {
  if (n == null) return "—";
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  if (n < 1024 ** 3) return `${(n / 1024 / 1024).toFixed(1)} MB`;
  return `${(n / 1024 ** 3).toFixed(2)} GB`;
}
export function errMsg(e: unknown) {
  if (e && typeof e === "object") {
    const d = (e as { data?: unknown }).data;
    if (d && typeof d === "object" && "error" in d) return String((d as { error: unknown }).error);
    if ("message" in e) return String((e as { message: unknown }).message);
  }
  return "Unexpected error";
}
