import {
  createContext,
  useCallback,
  useContext,
  useMemo,
  useState,
  type ReactNode,
} from "react";
import { en } from "./en";
import { zh } from "./zh";
import type { Dict } from "./en";

type Lang = "en" | "zh";

type Ctx = {
  lang: Lang;
  t: (key: keyof Dict) => string;
  toggle: () => void;
  set: (l: Lang) => void;
};

const I18nCtx = createContext<Ctx | null>(null);

const DICTS: Record<Lang, Dict> = { en, zh };

/** Detect initial language from storage → browser → default en. */
function detectLang(): Lang {
  if (typeof window === "undefined") return "en";
  const stored = window.localStorage.getItem("neoshell.lang");
  if (stored === "zh" || stored === "en") return stored;
  if (/^zh\b/i.test(navigator.language || "")) return "zh";
  return "en";
}

export function I18nProvider({ children }: { children: ReactNode }) {
  const [lang, setLangState] = useState<Lang>(detectLang);

  const set = useCallback((l: Lang) => {
    setLangState(l);
    try { window.localStorage.setItem("neoshell.lang", l); } catch {}
    document.documentElement.setAttribute("lang", l === "zh" ? "zh-CN" : "en");
  }, []);

  const toggle = useCallback(() => set(lang === "en" ? "zh" : "en"), [lang, set]);

  const value = useMemo<Ctx>(() => ({
    lang,
    t: (k: keyof Dict) => DICTS[lang][k] ?? String(k),
    toggle,
    set,
  }), [lang, toggle, set]);

  return <I18nCtx.Provider value={value}>{children}</I18nCtx.Provider>;
}

export function useI18n(): Ctx {
  const v = useContext(I18nCtx);
  if (!v) throw new Error("useI18n must be used inside I18nProvider");
  return v;
}
