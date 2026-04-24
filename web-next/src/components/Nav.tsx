import { useEffect, useState } from "react";
import { motion } from "framer-motion";
import { useI18n } from "../i18n/context";
import "./Nav.css";

export function Nav() {
  const { t, lang, toggle } = useI18n();
  const [scrolled, setScrolled] = useState(false);

  useEffect(() => {
    const on = () => setScrolled(window.scrollY > 40);
    on();
    window.addEventListener("scroll", on, { passive: true });
    return () => window.removeEventListener("scroll", on);
  }, []);

  return (
    <motion.header
      initial={{ y: -60, opacity: 0 }}
      animate={{ y: 0, opacity: 1 }}
      transition={{ delay: 0.25, duration: 0.7, ease: [0.2, 0.8, 0.2, 1] }}
      className={`nav ${scrolled ? "is-scrolled" : ""}`}
    >
      <div className="wrap nav-wrap">
        <a href="#top" className="brand" aria-label="NeoShell home">
          <span className="brand-mark" aria-hidden>
            <span className="brand-mark-chevron">&gt;_</span>
          </span>
          <span className="brand-name display">NeoShell</span>
        </a>

        <nav className="nav-links" aria-label="Primary">
          <a href="#features" className="u-link">{t("nav.features")}</a>
          <a href="#stack" className="u-link">{t("nav.stack")}</a>
          <a href="#security" className="u-link">{t("nav.security")}</a>
          <a href="#changelog" className="u-link">{t("nav.changelog")}</a>
        </nav>

        <div className="nav-meta">
          <span className="build-badge mono" title="Site build ID">
            build {__BUILD_ID__}
          </span>
          <button
            onClick={toggle}
            className="lang-toggle"
            aria-label="Switch language"
            data-hover
          >
            <span className={lang === "en" ? "is-active" : ""}>EN</span>
            <span className="divider">·</span>
            <span className={lang === "zh" ? "is-active" : ""}>中</span>
          </button>

          <a
            href="#download"
            className="nav-cta"
            data-hover
          >
            <span>{t("nav.download")}</span>
            <span className="nav-cta-arrow" aria-hidden>→</span>
          </a>
        </div>
      </div>
    </motion.header>
  );
}
