import { useCallback, useSyncExternalStore } from "react";
import { en, type TKey } from "./en";
import { ar } from "./ar";

export type Lang = "en" | "ar";
const dictionaries: Record<Lang, Partial<Record<TKey, string>>> = { en, ar };

let current: Lang = "en";
const listeners = new Set<() => void>();

export function setLanguage(lang: Lang) {
  current = lang;
  document.documentElement.lang = lang;
  document.documentElement.dir = lang === "ar" ? "rtl" : "ltr";
  listeners.forEach((l) => l());
}

function subscribe(cb: () => void) {
  listeners.add(cb);
  return () => listeners.delete(cb);
}

export function useT() {
  const lang = useSyncExternalStore(subscribe, () => current);
  return useCallback(
    (key: TKey, vars?: Record<string, string | number>) => {
      let s: string = dictionaries[lang][key] ?? en[key];
      if (vars) for (const [k, v] of Object.entries(vars)) s = s.split(`{${k}}`).join(String(v));
      return s;
    },
    [lang],
  );
}

export type { TKey };
