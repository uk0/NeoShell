import { motion, useInView } from "framer-motion";
import { useRef } from "react";
import { useI18n } from "../i18n/context";
import "./Stack.css";

/** Stack list — Rust crates powering NeoShell.
 *  Each row reveals on scroll with a staggered slide-in; the leading
 *  mono label is accent-colored, the meta is dim. */
export function Stack() {
  const { t } = useI18n();
  const ref = useRef<HTMLDivElement | null>(null);
  const inView = useInView(ref, { once: true, margin: "-10% 0px" });

  const rows: [string, string][] = [
    [t("stack.item.iced"),   t("stack.item.iced_d")],
    [t("stack.item.ssh2"),   t("stack.item.ssh2_d")],
    [t("stack.item.vte"),    t("stack.item.vte_d")],
    [t("stack.item.crypto"), t("stack.item.crypto_d")],
    [t("stack.item.tokio"),  t("stack.item.tokio_d")],
  ];

  return (
    <section id="stack" className="section stack-section">
      <div className="wrap stack-wrap">
        <div className="stack-head">
          <div className="eyebrow">{t("stack.eyebrow")}</div>
          <h2 className="section-title">
            <span>100% Rust.</span>
            <br />
            <span className="stack-title-accent">Zero JavaScript.</span>
          </h2>
          <p className="section-lede">{t("stack.lede")}</p>
        </div>

        <div ref={ref} className="stack-list">
          {rows.map(([label, meta], i) => (
            <motion.div
              key={label}
              className="stack-row"
              initial={{ x: -24, opacity: 0 }}
              animate={inView ? { x: 0, opacity: 1 } : {}}
              transition={{ duration: 0.7, delay: i * 0.09, ease: [0.2, 0.8, 0.2, 1] }}
            >
              <span className="stack-row-num mono">0{i + 1}</span>
              <span className="stack-row-label mono">{label}</span>
              <span className="stack-row-meta">{meta}</span>
              <span className="stack-row-line" aria-hidden />
            </motion.div>
          ))}
        </div>
      </div>
    </section>
  );
}
