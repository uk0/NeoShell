import { motion, useInView } from "framer-motion";
import { useRef } from "react";
import { useI18n } from "../i18n/context";
import "./Contact.css";

/** Contact block — left column = message + CTAs; right column = the QQ
 *  group QR card (so Chinese-speaking users can scan in-page). */
export function Contact() {
  const { t } = useI18n();
  const ref = useRef<HTMLDivElement | null>(null);
  const inView = useInView(ref, { once: true, margin: "-10% 0px" });

  return (
    <section id="contact" className="section contact-section">
      <div className="wrap">
        <motion.div
          ref={ref}
          className="contact-card"
          initial={{ scale: 0.94, opacity: 0 }}
          animate={inView ? { scale: 1, opacity: 1 } : {}}
          transition={{ duration: 0.9, ease: [0.2, 0.8, 0.2, 1] }}
        >
          <div className="contact-ornament" aria-hidden>
            <svg viewBox="0 0 320 320" width="320" height="320">
              <circle cx="160" cy="160" r="120" fill="none" stroke="url(#g1)" strokeWidth="1" opacity="0.4" />
              <circle cx="160" cy="160" r="80"  fill="none" stroke="url(#g1)" strokeWidth="1" opacity="0.6" />
              <circle cx="160" cy="160" r="40"  fill="none" stroke="url(#g1)" strokeWidth="1" opacity="0.9" />
              <defs>
                <linearGradient id="g1" x1="0" y1="0" x2="1" y2="1">
                  <stop offset="0%"   stopColor="#f4b86b" />
                  <stop offset="100%" stopColor="#5de4c7" />
                </linearGradient>
              </defs>
            </svg>
          </div>

          <div className="contact-grid">
            <div className="contact-copy">
              <div className="eyebrow">{t("contact.eyebrow")}</div>
              <h2 className="section-title contact-title">{t("contact.title")}</h2>
              <p className="section-lede contact-lede">{t("contact.lede")}</p>

              <div className="contact-channels">
                <a
                  href="https://github.com/uk0/NeoShell/issues"
                  target="_blank"
                  rel="noopener"
                  className="channel-link"
                  data-hover
                >
                  <span className="channel-icon" aria-hidden>
                    <svg viewBox="0 0 24 24" width="18" height="18" fill="currentColor">
                      <path d="M12 .5C5.4.5 0 5.9 0 12.5c0 5.3 3.4 9.8 8.2 11.3.6.1.8-.3.8-.6v-2.1c-3.3.7-4-1.4-4-1.4-.6-1.4-1.3-1.8-1.3-1.8-1.1-.7.1-.7.1-.7 1.2.1 1.8 1.2 1.8 1.2 1.1 1.8 2.8 1.3 3.5 1 .1-.8.4-1.3.8-1.6-2.7-.3-5.5-1.3-5.5-6 0-1.3.5-2.4 1.2-3.2-.1-.3-.5-1.5.1-3.1 0 0 1-.3 3.3 1.2 1-.3 2-.4 3-.4s2 .1 3 .4c2.3-1.5 3.3-1.2 3.3-1.2.7 1.7.2 2.9.1 3.1.8.8 1.2 1.9 1.2 3.2 0 4.7-2.8 5.7-5.5 6 .4.4.8 1.1.8 2.2v3.3c0 .3.2.7.8.6C20.6 22.3 24 17.8 24 12.5 24 5.9 18.6.5 12 .5z" />
                    </svg>
                  </span>
                  <span className="channel-body">
                    <span className="channel-label">{t("contact.github")}</span>
                    <span className="channel-meta mono">github.com/uk0/NeoShell</span>
                  </span>
                  <span className="channel-arrow" aria-hidden>→</span>
                </a>

                <a
                  href="mailto:hello@firsh.me"
                  className="channel-link"
                  data-hover
                >
                  <span className="channel-icon" aria-hidden>
                    <svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" strokeWidth="1.6">
                      <rect x="3" y="5" width="18" height="14" rx="2" />
                      <path d="M3 7l9 7 9-7" />
                    </svg>
                  </span>
                  <span className="channel-body">
                    <span className="channel-label">hello@firsh.me</span>
                    <span className="channel-meta mono">{t("contact.lede")}</span>
                  </span>
                  <span className="channel-arrow" aria-hidden>→</span>
                </a>
              </div>
            </div>

            <div className="contact-qr" data-hover>
              <div className="contact-qr-frame">
                <img
                  src="/qqGroupCode.png"
                  alt="QQ group QR"
                  width="200"
                  height="200"
                  loading="lazy"
                  className="contact-qr-img"
                />
                <div className="contact-qr-scan" aria-hidden />
                <div className="contact-qr-corner tl" aria-hidden />
                <div className="contact-qr-corner tr" aria-hidden />
                <div className="contact-qr-corner bl" aria-hidden />
                <div className="contact-qr-corner br" aria-hidden />
              </div>
              <div className="contact-qr-meta">
                <div className="contact-qr-label mono">{t("contact.qq")}</div>
                <div className="contact-qr-hint">{t("contact.qr_hint")}</div>
              </div>
            </div>
          </div>
        </motion.div>
      </div>
    </section>
  );
}
