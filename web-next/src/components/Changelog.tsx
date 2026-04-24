import { motion, useInView } from "framer-motion";
import { useRef } from "react";
import { useI18n } from "../i18n/context";
import "./Changelog.css";

type Dict = ReturnType<typeof useI18n>["t"];

const entries = (t: Dict) => [
  { cat: "added", items: ["cl.added.1","cl.added.2","cl.added.3","cl.added.4","cl.added.5","cl.added.6"] },
  { cat: "changed", items: ["cl.changed.1","cl.changed.2","cl.changed.3"] },
  { cat: "fixed", items: ["cl.fixed.1"] },
].map(b => ({ ...b, title: t(`cl.category.${b.cat}` as any), lines: b.items.map(k => t(k as any)) }));

/**
 * Changelog — single rollup entry for v0.6.26, rendered as a timeline
 * with Added / Changed / Fixed columns. Each line reveals on scroll.
 */
export function Changelog() {
  const { t } = useI18n();
  const ref = useRef<HTMLDivElement | null>(null);
  const inView = useInView(ref, { once: true, margin: "-10% 0px" });
  const blocks = entries(t);

  return (
    <section id="changelog" className="section changelog-section">
      <div className="wrap">
        <div className="changelog-head">
          <div className="eyebrow">{t("cl.eyebrow")}</div>
          <h2 className="section-title">{t("cl.title")}</h2>
          <div className="changelog-meta">
            <span className="mono changelog-ver">v0.6.26</span>
            <span className="changelog-dot">·</span>
            <span className="mono changelog-date">{t("cl.date")}</span>
            <span className="changelog-latest">{t("cl.latest")}</span>
          </div>
        </div>

        <div ref={ref} className="changelog-grid">
          {blocks.map((block, bi) => (
            <motion.div
              key={block.cat}
              className={`cl-block cl-block-${block.cat}`}
              initial={{ y: 30, opacity: 0 }}
              animate={inView ? { y: 0, opacity: 1 } : {}}
              transition={{ duration: 0.75, delay: bi * 0.12, ease: [0.2, 0.8, 0.2, 1] }}
            >
              <div className="cl-block-head">
                <span className="cl-block-dot" />
                <span className="cl-block-title mono">{block.title}</span>
                <span className="cl-block-count mono">{block.lines.length.toString().padStart(2, "0")}</span>
              </div>
              <ul className="cl-block-list">
                {block.lines.map((line, i) => (
                  <motion.li
                    key={i}
                    initial={{ y: 10, opacity: 0 }}
                    animate={inView ? { y: 0, opacity: 1 } : {}}
                    transition={{ duration: 0.6, delay: bi * 0.12 + i * 0.05 + 0.1, ease: [0.2, 0.8, 0.2, 1] }}
                  >
                    {line}
                  </motion.li>
                ))}
              </ul>
            </motion.div>
          ))}
        </div>
      </div>
    </section>
  );
}
