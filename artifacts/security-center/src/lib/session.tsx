import { createContext, useContext, useEffect } from "react";
import type { Me, Role } from "@workspace/api-client-react";

export const MeContext = createContext<Me | null>(null);

export function useMe(): Me {
  const me = useContext(MeContext);
  if (!me) throw new Error("useMe used outside the authenticated shell");
  return me;
}

export function useRole(): Role {
  return useMe().currentOrganization?.role ?? "VIEWER";
}

export const canAnalyze = (r: Role) => r !== "VIEWER";
export const canAdmin = (r: Role) => r === "OWNER" || r === "ADMIN";
export const isOwner = (r: Role) => r === "OWNER";

export function usePageMeta(title: string, description: string) {
  useEffect(() => {
    document.title = `${title} · NextAura Security Center`;
    let m = document.querySelector('meta[name="description"]');
    if (!m) {
      m = document.createElement("meta");
      m.setAttribute("name", "description");
      document.head.appendChild(m);
    }
    m.setAttribute("content", description);
  }, [title, description]);
}
