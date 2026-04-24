import { useEffect, useRef, useState } from "react";
import "./Cursor.css";

type Ripple = { id: number; x: number; y: number; tint: string };

/**
 * Custom pointer: a dot + halo ring that follow with exponential
 * smoothing (frame-rate independent), a trail of ghost dots, a click
 * ripple that blooms outward, and a section-aware tint that shifts
 * from amber → teal → violet as you scroll.
 */
export function Cursor() {
  const dotRef = useRef<HTMLDivElement | null>(null);
  const ringRef = useRef<HTMLDivElement | null>(null);
  const trailRefs = useRef<HTMLDivElement[]>([]);
  const [enabled, setEnabled] = useState(false);
  const [ripples, setRipples] = useState<Ripple[]>([]);

  useEffect(() => {
    const mm = window.matchMedia("(pointer: fine)");
    const rm = window.matchMedia("(prefers-reduced-motion: reduce)");
    const update = () => setEnabled(mm.matches && !rm.matches);
    update();
    mm.addEventListener("change", update);
    rm.addEventListener("change", update);
    return () => {
      mm.removeEventListener("change", update);
      rm.removeEventListener("change", update);
    };
  }, []);

  useEffect(() => {
    if (!enabled) return;

    const TRAIL = 10;
    const DOT_TAU = 0.05;
    const RING_TAU = 0.12;
    const TRAIL_TAUS = Array.from(
      { length: TRAIL },
      (_, i) => 0.07 + i * 0.04,
    );

    let tx = -200,
      ty = -200;
    let cx = tx,
      cy = ty;
    let rx = tx,
      ry = ty;
    const trailX = new Array(TRAIL).fill(tx);
    const trailY = new Array(TRAIL).fill(ty);
    let hovering = false;
    let tint = "amber";

    let rafId = 0;
    let last = performance.now();

    const onMove = (e: PointerEvent) => {
      tx = e.clientX;
      ty = e.clientY;
      const el = e.target as HTMLElement | null;
      hovering = !!el?.closest("a, button, [data-hover]");
    };

    const onClick = (e: PointerEvent) => {
      if (e.pointerType !== "mouse") return;
      const id = Math.random();
      setRipples((r) => [...r, { id, x: e.clientX, y: e.clientY, tint }]);
      window.setTimeout(() => {
        setRipples((r) => r.filter((x) => x.id !== id));
      }, 750);
    };

    // Scroll-driven tint — cursor recolors as sections change.
    const sectionTints = [
      { el: () => document.getElementById("top"),       tint: "amber" },
      { el: () => document.getElementById("features"),  tint: "teal" },
      { el: () => document.getElementById("stack"),     tint: "amber" },
      { el: () => document.getElementById("security"),  tint: "teal" },
      { el: () => document.getElementById("download"),  tint: "amber" },
      { el: () => document.getElementById("changelog"), tint: "violet" },
      { el: () => document.getElementById("contact"),   tint: "teal" },
    ];
    const refreshTint = () => {
      const y = window.scrollY + window.innerHeight * 0.45;
      let best = "amber";
      for (const s of sectionTints) {
        const n = s.el();
        if (!n) continue;
        const top = n.offsetTop;
        if (y >= top) best = s.tint;
      }
      tint = best;
      document.body.setAttribute("data-cursor-tint", best);
    };
    refreshTint();

    const loop = (now: number) => {
      const dt = Math.min((now - last) / 1000, 0.05);
      last = now;
      const aDot = 1 - Math.exp(-dt / DOT_TAU);
      const aRing = 1 - Math.exp(-dt / RING_TAU);

      cx += (tx - cx) * aDot;
      cy += (ty - cy) * aDot;
      rx += (tx - rx) * aRing;
      ry += (ty - ry) * aRing;

      if (dotRef.current) {
        dotRef.current.style.transform = `translate3d(${cx - 4}px, ${cy - 4}px, 0)`;
      }
      if (ringRef.current) {
        const scale = hovering ? 2.3 : 1;
        ringRef.current.style.transform = `translate3d(${rx - 18}px, ${ry - 18}px, 0) scale(${scale})`;
      }

      // Ghost trail.
      for (let i = 0; i < TRAIL; i++) {
        const aT = 1 - Math.exp(-dt / TRAIL_TAUS[i]);
        trailX[i] += (tx - trailX[i]) * aT;
        trailY[i] += (ty - trailY[i]) * aT;
        const node = trailRefs.current[i];
        if (node) {
          node.style.transform = `translate3d(${trailX[i] - 3}px, ${trailY[i] - 3}px, 0)`;
        }
      }

      rafId = requestAnimationFrame(loop);
    };

    window.addEventListener("pointermove", onMove);
    window.addEventListener("pointerdown", onClick);
    window.addEventListener("scroll", refreshTint, { passive: true });
    rafId = requestAnimationFrame(loop);

    return () => {
      cancelAnimationFrame(rafId);
      window.removeEventListener("pointermove", onMove);
      window.removeEventListener("pointerdown", onClick);
      window.removeEventListener("scroll", refreshTint);
    };
  }, [enabled]);

  if (!enabled) return null;
  return (
    <>
      {Array.from({ length: 10 }, (_, i) => (
        <div
          key={i}
          ref={(el) => {
            if (el) trailRefs.current[i] = el;
          }}
          className="cursor-trail"
          style={{
            opacity: 0.08 + (10 - i) * 0.03,
            width: Math.max(2, 6 - i * 0.35),
            height: Math.max(2, 6 - i * 0.35),
          }}
          aria-hidden
        />
      ))}
      <div ref={ringRef} className="cursor-ring" aria-hidden />
      <div ref={dotRef}  className="cursor-dot"  aria-hidden />
      {ripples.map((r) => (
        <div
          key={r.id}
          className={`cursor-ripple cursor-ripple-${r.tint}`}
          style={{ left: r.x, top: r.y }}
          aria-hidden
        />
      ))}
    </>
  );
}
