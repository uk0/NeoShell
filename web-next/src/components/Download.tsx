import { motion, useInView } from "framer-motion";
import { useRef } from "react";
import { useI18n } from "../i18n/context";
import "./Download.css";

const VERSION = "0.6.26";
const BASE = "/downloads";

type Asset = { href: string; label: string; accent?: boolean };

const platforms: {
  id: string;
  key: "macos" | "windows" | "win7" | "linux";
  assets: (t: ReturnType<typeof useI18n>["t"]) => Asset[];
  glyph: React.ReactNode;
}[] = [
  {
    id: "macos",
    key: "macos",
    glyph: (
      <svg viewBox="0 0 32 32" width="34" height="34" fill="currentColor" aria-hidden>
        <path d="M22.8 16.6c-.1-2.9 2.3-4.2 2.4-4.3-1.3-1.9-3.3-2.2-4-2.2-1.7-.2-3.4 1-4.2 1-.9 0-2.3-1-3.8-1-2 0-3.8 1.2-4.8 3-2.1 3.6-.5 8.9 1.5 11.8 1 1.4 2.2 3 3.7 3 1.5-.1 2.1-1 3.9-1s2.3 1 3.9 1c1.6 0 2.6-1.5 3.6-2.9 1.1-1.6 1.6-3.2 1.6-3.3-.1 0-3.1-1.2-3.1-4.7zM20.3 8.3c.8-1 1.4-2.4 1.3-3.8-1.2.1-2.7.8-3.5 1.8-.7.9-1.4 2.3-1.2 3.7 1.3.1 2.6-.7 3.4-1.7z" />
      </svg>
    ),
    assets: (t) => [
      {
        href: `${BASE}/NeoShell-${VERSION}-macos-aarch64.dmg`,
        label: t("dl.macos_arm"),
        accent: true,
      },
      {
        href: `${BASE}/NeoShell-${VERSION}-macos-x86_64.dmg`,
        label: t("dl.macos_intel"),
      },
    ],
  },
  {
    id: "windows",
    key: "windows",
    glyph: (
      <svg viewBox="0 0 32 32" width="34" height="34" fill="currentColor" aria-hidden>
        <path d="M3 6.6l11-1.6v10.6H3zM3 18.3h11v10.7l-11-1.6zm13-13.8l13-1.9v12.9H16zm0 13.8h13v12.9l-13-1.9z" />
      </svg>
    ),
    assets: (t) => [
      {
        href: `${BASE}/NeoShell-${VERSION}-windows-x64.zip`,
        label: t("dl.windows"),
        accent: true,
      },
    ],
  },
  {
    id: "win7",
    key: "win7",
    glyph: (
      <svg viewBox="0 0 32 32" width="34" height="34" fill="none" stroke="currentColor" strokeWidth="1.3" aria-hidden>
        <rect x="4" y="6" width="24" height="18" rx="2" />
        <path d="M4 20h24" />
        <path d="M13 27l3-3 3 3" strokeLinecap="round" strokeLinejoin="round" />
      </svg>
    ),
    assets: (t) => [
      {
        href: `${BASE}/NeoShell-${VERSION}-windows-win7-x64.zip`,
        label: t("dl.win7"),
        accent: true,
      },
    ],
  },
  {
    id: "linux",
    key: "linux",
    glyph: (
      <svg viewBox="0 0 32 32" width="34" height="34" fill="currentColor" aria-hidden>
        <path d="M16 2c-4 0-6 3-6 7 0 3 1 5 1 7 0 2-3 4-3 7s2 5 4 5l2-1v1h4v-1l2 1c2 0 4-2 4-5s-3-5-3-7c0-2 1-4 1-7 0-4-2-7-6-7zm-2 7c0-1 1-1 2-1s2 0 2 1-1 1-2 1-2 0-2-1zm2 4c2 0 3 2 3 4l-3 3-3-3c0-2 1-4 3-4z" />
      </svg>
    ),
    assets: (_t) => [
      {
        href: `${BASE}/NeoShell-${VERSION}-linux-x86_64.AppImage`,
        label: ".AppImage",
        accent: true,
      },
    ],
  },
];

export function Download() {
  const { t } = useI18n();
  const ref = useRef<HTMLDivElement | null>(null);
  const inView = useInView(ref, { once: true, margin: "-10% 0px" });

  return (
    <section id="download" className="section download-section">
      <div className="wrap">
        <div className="download-head">
          <div className="eyebrow">{t("dl.eyebrow")}</div>
          <h2 className="section-title">{t("dl.title")}</h2>
          <p className="section-lede">{t("dl.lede")}</p>
        </div>

        <div ref={ref} className="download-grid">
          {platforms.map((p, i) => (
            <motion.article
              key={p.id}
              className="dl-card"
              initial={{ y: 32, opacity: 0 }}
              animate={inView ? { y: 0, opacity: 1 } : {}}
              transition={{ duration: 0.8, delay: i * 0.08, ease: [0.2, 0.8, 0.2, 1] }}
              data-hover
            >
              <div className="dl-card-head">
                <span className="dl-card-glyph">{p.glyph}</span>
                <div className="dl-card-platform display">{t(`dl.${p.key}` as any)}</div>
                <div className="dl-card-version mono">v{VERSION}</div>
              </div>
              <div className="dl-card-actions">
                {p.assets(t).map((a) => (
                  <a
                    key={a.href}
                    href={a.href}
                    className={`dl-btn ${a.accent ? "dl-btn-primary" : "dl-btn-alt"}`}
                    data-hover
                  >
                    <span>{a.label}</span>
                    <span className="dl-btn-arrow" aria-hidden>↓</span>
                  </a>
                ))}
              </div>
            </motion.article>
          ))}
        </div>

        <div className="download-footnote mono">
          <span>{t("dl.update_note")}</span>
          <span className="download-dot">·</span>
          <a
            href="https://neoshell.wwwneo.com/updates/update.json"
            target="_blank"
            rel="noopener"
            className="u-link"
          >
            updates/update.json
          </a>
          <span className="download-dot">·</span>
          <span>{t("dl.note")}</span>
        </div>
      </div>
    </section>
  );
}
