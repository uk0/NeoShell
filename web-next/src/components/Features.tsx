import { motion, useInView } from "framer-motion";
import { useRef, type MouseEvent as ReactMouseEvent } from "react";
import { useI18n } from "../i18n/context";
import "./Features.css";

/**
 * Magnetic 3D tilt — reads the pointer position relative to the card's
 * center and writes CSS variables consumed by the card's transform.
 * Keeps everything on the compositor (transform + will-change) so it
 * runs at display refresh on high-Hz monitors.
 */
function handleTilt(e: ReactMouseEvent<HTMLElement>) {
  const el = e.currentTarget;
  const r = el.getBoundingClientRect();
  const px = (e.clientX - r.left) / r.width;
  const py = (e.clientY - r.top) / r.height;
  const rx = (0.5 - py) * 6;
  const ry = (px - 0.5) * 10;
  el.style.setProperty("--tilt-rx", `${rx}deg`);
  el.style.setProperty("--tilt-ry", `${ry}deg`);
  el.style.setProperty("--tilt-px", `${px * 100}%`);
  el.style.setProperty("--tilt-py", `${py * 100}%`);
}
function resetTilt(e: ReactMouseEvent<HTMLElement>) {
  const el = e.currentTarget;
  el.style.setProperty("--tilt-rx", `0deg`);
  el.style.setProperty("--tilt-ry", `0deg`);
}

/**
 * Features grid — 3 × 2 cards, each fades up on entry with a staggered
 * delay. Hover lifts the card + sweeps a subtle gradient edge.
 */
export function Features() {
  const { t } = useI18n();
  const ref = useRef<HTMLDivElement | null>(null);
  const inView = useInView(ref, { once: true, margin: "-15% 0px" });

  const cards: {
    id: string;
    num: string;
    icon: React.ReactNode;
    title: string;
    body: string;
  }[] = [
    {
      id: "terminal", num: "01",
      icon: <GlyphTerminal />,
      title: t("features.terminal.title"),
      body: t("features.terminal.body"),
    },
    {
      id: "vault", num: "02",
      icon: <GlyphLock />,
      title: t("features.vault.title"),
      body: t("features.vault.body"),
    },
    {
      id: "ssh", num: "03",
      icon: <GlyphInfinity />,
      title: t("features.ssh.title"),
      body: t("features.ssh.body"),
    },
    {
      id: "monitor", num: "04",
      icon: <GlyphPulse />,
      title: t("features.monitor.title"),
      body: t("features.monitor.body"),
    },
    {
      id: "sftp", num: "05",
      icon: <GlyphFolder />,
      title: t("features.sftp.title"),
      body: t("features.sftp.body"),
    },
    {
      id: "cross", num: "06",
      icon: <GlyphGlobe />,
      title: t("features.cross.title"),
      body: t("features.cross.body"),
    },
  ];

  return (
    <section id="features" className="section features">
      <div className="wrap">
        <div className="features-head">
          <div className="eyebrow">{t("features.eyebrow")}</div>
          <h2 className="section-title">{t("features.title")}</h2>
          <p className="section-lede">{t("features.lede")}</p>
        </div>

        <div ref={ref} className="features-grid">
          {cards.map((c, i) => (
            <motion.article
              key={c.id}
              className="feature-card"
              initial={{ y: 40, opacity: 0 }}
              animate={inView ? { y: 0, opacity: 1 } : {}}
              transition={{ duration: 0.8, delay: i * 0.08, ease: [0.2, 0.8, 0.2, 1] }}
              onMouseMove={handleTilt}
              onMouseLeave={resetTilt}
              data-hover
            >
              <div className="feature-card-num mono">{c.num}</div>
              <div className="feature-card-icon">{c.icon}</div>
              <h3 className="feature-card-title display">{c.title}</h3>
              <p className="feature-card-body">{c.body}</p>
              <div className="feature-card-glow" />
            </motion.article>
          ))}
        </div>
      </div>
    </section>
  );
}

/* ---------- inline glyphs (mono-weight strokes, amber accent) ---------- */

const stroke = {
  fill: "none",
  stroke: "currentColor",
  strokeWidth: 1.4,
  strokeLinecap: "round" as const,
  strokeLinejoin: "round" as const,
};

function GlyphTerminal() {
  return (
    <svg viewBox="0 0 40 40" width="40" height="40" {...stroke}>
      <rect x="5" y="8" width="30" height="24" rx="3" />
      <path d="M11 17l5 3-5 3" />
      <path d="M19 23h9" />
    </svg>
  );
}
function GlyphLock() {
  return (
    <svg viewBox="0 0 40 40" width="40" height="40" {...stroke}>
      <rect x="9" y="18" width="22" height="15" rx="3" />
      <path d="M14 18v-5a6 6 0 1112 0v5" />
      <circle cx="20" cy="25" r="1.5" />
    </svg>
  );
}
function GlyphInfinity() {
  return (
    <svg viewBox="0 0 40 40" width="40" height="40" {...stroke}>
      <path d="M10 20c0-4 3-7 7-7 3 0 5 2 6 5l4 6c1 3 3 5 6 5 4 0 7-3 7-7s-3-7-7-7c-3 0-5 2-6 5l-4 6c-1 3-3 5-6 5-4 0-7-3-7-7z" />
    </svg>
  );
}
function GlyphPulse() {
  return (
    <svg viewBox="0 0 40 40" width="40" height="40" {...stroke}>
      <path d="M5 24h6l3-11 5 16 4-10 3 5h9" />
    </svg>
  );
}
function GlyphFolder() {
  return (
    <svg viewBox="0 0 40 40" width="40" height="40" {...stroke}>
      <path d="M6 13a2 2 0 012-2h7l3 4h14a2 2 0 012 2v12a2 2 0 01-2 2H8a2 2 0 01-2-2z" />
      <path d="M20 19l3 3-3 3" />
      <path d="M15 22h8" />
    </svg>
  );
}
function GlyphGlobe() {
  return (
    <svg viewBox="0 0 40 40" width="40" height="40" {...stroke}>
      <circle cx="20" cy="20" r="13" />
      <path d="M7 20h26" />
      <path d="M20 7c5 4 5 22 0 26" />
      <path d="M20 7c-5 4-5 22 0 26" />
    </svg>
  );
}
