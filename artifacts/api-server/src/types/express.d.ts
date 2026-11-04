import type { AuthContext } from "../middlewares/auth";
import type { Device, Organization } from "@workspace/db";

declare global {
  namespace Express {
    interface Request {
      auth?: AuthContext;
      identity?: { userId: string; email: string; name: string | null };
      deviceAuth?: { device: Device; org: Organization; credentialId: string };
    }
  }
}
export {};
