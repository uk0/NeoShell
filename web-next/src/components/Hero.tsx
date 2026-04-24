import { motion } from "framer-motion";
import { useI18n } from "../i18n/context";
import { HeroCanvas } from "./HeroCanvas";
import "./Hero.css";

const stagger = {
  hidden: {},
  visible: { transition: { staggerChildren: 0.08, delayChildren: 0.15 } },
};
const lineUp = {
  hidden: { y: "110%", opacity: 0 },
  visible: {
    y: "0%",
    opacity: 1,
    transition: { duration: 0.95, ease: [0.2, 0.8, 0.2, 1] },
  },
};
const fade = {
  hidden: { y: 20, opacity: 0 },
  visible: { y: 0, opacity: 1, transition: { duration: 0.9, ease: [0.2, 0.8, 0.2, 1] } },
};

export function Hero() {
  const { t } = useI18n();
  const stats: [string, string][] = [
    ["6 MB",        t("hero.stat.binary")],
    ["< 1 s",       t("hero.stat.start")],
    ["~80 MB",      t("hero.stat.mem")],
    ["mac · win · linux", t("hero.stat.platforms")],
  ];

  return (
    <section id="top" className="hero">
      <HeroCanvas />

      <div className="wrap hero-inner">
        <motion.div variants={stagger} initial="hidden" animate="visible">
          <motion.div variants={fade} className="hero-badge mono">
            <span className="hero-badge-dot" /> {t("hero.badge")}
          </motion.div>

          <h1 className="hero-title display">
            {[t("hero.title_a"), t("hero.title_b"), t("hero.title_c")].map((line, i) => (
              <span key={i} className="hero-line-clip">
                <motion.span
                  className={`hero-line ${i === 1 ? "hero-line-accent" : ""}`}
                  variants={lineUp}
                >
                  {line}
                </motion.span>
              </span>
            ))}
          </h1>

          <motion.p variants={fade} className="hero-lede">
            {t("hero.lede")}
          </motion.p>

          <motion.div variants={fade} className="hero-cta-row">
            <a href="#download" className="cta cta-primary" data-hover>
              <span>{t("hero.cta.primary")}</span>
              <svg viewBox="0 0 24 24" width="16" height="16" fill="none" aria-hidden>
                <path
                  d="M12 4v12m0 0l-5-5m5 5l5-5M4 20h16"
                  stroke="currentColor"
                  strokeWidth="1.8"
                  strokeLinecap="round"
                  strokeLinejoin="round"
                />
              </svg>
            </a>
            <a href="#features" className="cta cta-ghost" data-hover>
              {t("hero.cta.secondary")}
            </a>
            <a
              href="https://github.com/uk0/NeoShell"
              target="_blank"
              rel="noopener"
              className="cta cta-text u-link"
              data-hover
            >
              {t("hero.cta.source")}
            </a>
          </motion.div>

          <motion.div variants={fade} className="hero-stats">
            {stats.map(([val, label]) => (
              <div key={label} className="hero-stat">
                <div className="hero-stat-val display">{val}</div>
                <div className="hero-stat-label mono">{label}</div>
              </div>
            ))}
          </motion.div>
        </motion.div>
      </div>

      <div className="hero-scroll-hint" aria-hidden>
        <span className="mono">scroll</span>
        <span className="hero-scroll-line" />
      </div>
    </section>
  );
}
