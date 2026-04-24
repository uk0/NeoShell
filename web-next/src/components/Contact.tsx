import { motion, useInView } from "framer-motion";
import { useRef, useState } from "react";
import { useI18n } from "../i18n/context";
import "./Contact.css";

type QrKey = "wechat" | "qq";

/** Contact block — left column = message + CTAs; right column = a two-
 *  tabbed QR card (official WeChat account default, QQ group second). */
export function Contact() {
  const { t } = useI18n();
  const ref = useRef<HTMLDivElement | null>(null);
  const inView = useInView(ref, { once: true, margin: "-10% 0px" });
  const [qr, setQr] = useState<QrKey>("wechat");

  const qrMeta: Record<QrKey, { src: string; label: string; hint: string }> = {
    wechat: {
      src: "/weixin.jpg",
      label: t("contact.wechat"),
      hint: t("contact.wechat_hint"),
    },
    qq: {
      src: "/qqGroupCode.png",
      label: t("contact.qq"),
      hint: t("contact.qr_hint"),
    },
  };
  const current = qrMeta[qr];

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
                  href="https://discord.gg/GZH24Fmh4u"
                  target="_blank"
                  rel="noopener"
                  className="channel-link channel-discord"
                  data-hover
                >
                  <span className="channel-icon" aria-hidden>
                    <svg viewBox="0 0 24 24" width="18" height="18" fill="currentColor">
                      <path d="M20.317 4.37a19.79 19.79 0 00-4.885-1.515.074.074 0 00-.079.037c-.21.375-.444.864-.608 1.25a18.27 18.27 0 00-5.487 0 12.64 12.64 0 00-.617-1.25.077.077 0 00-.079-.037A19.736 19.736 0 003.677 4.37a.07.07 0 00-.032.027C.533 9.046-.32 13.58.099 18.057a.082.082 0 00.031.057 19.9 19.9 0 005.993 3.03.078.078 0 00.084-.028c.462-.63.874-1.295 1.226-1.994.021-.041.001-.09-.041-.106a13.107 13.107 0 01-1.872-.892.077.077 0 01-.008-.128 10.2 10.2 0 00.372-.292.074.074 0 01.077-.01c3.928 1.793 8.18 1.793 12.062 0a.074.074 0 01.078.009c.12.098.246.198.373.292a.077.077 0 01-.006.127 12.3 12.3 0 01-1.873.892.077.077 0 00-.041.107c.36.698.772 1.362 1.225 1.993a.076.076 0 00.084.028 19.839 19.839 0 006.002-3.03.077.077 0 00.032-.054c.5-5.177-.838-9.674-3.549-13.66a.061.061 0 00-.031-.03zM8.02 15.33c-1.183 0-2.157-1.085-2.157-2.419 0-1.333.956-2.419 2.157-2.419 1.21 0 2.176 1.096 2.157 2.42 0 1.333-.956 2.418-2.157 2.418zm7.975 0c-1.183 0-2.157-1.085-2.157-2.419 0-1.333.955-2.419 2.157-2.419 1.21 0 2.176 1.096 2.157 2.42 0 1.333-.946 2.418-2.157 2.418z" />
                    </svg>
                  </span>
                  <span className="channel-body">
                    <span className="channel-label">{t("contact.discord")}</span>
                    <span className="channel-meta mono">discord.gg/GZH24Fmh4u</span>
                  </span>
                  <span className="channel-arrow" aria-hidden>→</span>
                </a>

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
                    <span className="channel-meta mono">email</span>
                  </span>
                  <span className="channel-arrow" aria-hidden>→</span>
                </a>
              </div>
            </div>

            <div className="contact-qr" data-hover>
              <div className="qr-tabs" role="tablist">
                {(Object.keys(qrMeta) as QrKey[]).map((k) => (
                  <button
                    key={k}
                    role="tab"
                    aria-selected={qr === k}
                    className={`qr-tab ${qr === k ? "is-active" : ""}`}
                    onClick={() => setQr(k)}
                  >
                    {qrMeta[k].label}
                  </button>
                ))}
              </div>

              <div className="contact-qr-frame">
                <img
                  src={current.src}
                  alt={current.label}
                  width="220"
                  height="220"
                  loading="lazy"
                  className="contact-qr-img"
                  key={current.src} /* re-trigger fade on swap */
                />
                <div className="contact-qr-scan" aria-hidden />
                <div className="contact-qr-corner tl" aria-hidden />
                <div className="contact-qr-corner tr" aria-hidden />
                <div className="contact-qr-corner bl" aria-hidden />
                <div className="contact-qr-corner br" aria-hidden />
              </div>
              <div className="contact-qr-meta">
                <div className="contact-qr-hint">{current.hint}</div>
              </div>
            </div>
          </div>
        </motion.div>
      </div>
    </section>
  );
}
