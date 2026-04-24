import { motion, useInView } from "framer-motion";
import { useRef } from "react";
import { useI18n } from "../i18n/context";
import "./Security.css";

/** Security section. Left column is the message, right column is a
 *  guarantees list with a thin rule between each item. */
export function Security() {
  const { t } = useI18n();
  const ref = useRef<HTMLDivElement | null>(null);
  const inView = useInView(ref, { once: true, margin: "-10% 0px" });

  const items = [
    t("security.item.1"),
    t("security.item.2"),
    t("security.item.3"),
    t("security.item.4"),
    t("security.item.5"),
    t("security.item.6"),
  ];

  return (
    <section id="security" className="section security-section">
      <div className="wrap security-wrap">
        <div className="security-lead">
          <div className="eyebrow">{t("security.eyebrow")}</div>
          <h2 className="section-title">{t("security.title")}</h2>
          <p className="section-lede">{t("security.lede")}</p>
          <div className="security-seal mono">
            <span className="security-seal-kv"><b>AES</b>-256-GCM</span>
            <span className="security-seal-kv"><b>Argon2</b>id</span>
            <span className="security-seal-kv"><b>zero</b>-trust client</span>
          </div>
        </div>

        <div ref={ref} className="security-list">
          {items.map((line, i) => (
            <motion.div
              key={i}
              className="security-item"
              initial={{ x: 24, opacity: 0 }}
              animate={inView ? { x: 0, opacity: 1 } : {}}
              transition={{ duration: 0.7, delay: i * 0.07, ease: [0.2, 0.8, 0.2, 1] }}
            >
              <span className="security-item-bullet" aria-hidden>
                <svg viewBox="0 0 16 16" width="14" height="14" fill="none">
                  <path d="M3 8l3.5 3.5L13 5" stroke="currentColor" strokeWidth="1.6"
                        strokeLinecap="round" strokeLinejoin="round" />
                </svg>
              </span>
              <span>{line}</span>
            </motion.div>
          ))}
        </div>
      </div>
    </section>
  );
}
