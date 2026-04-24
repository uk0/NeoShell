import { useEffect, useRef, useState } from "react";
import "./Cursor.css";

/**
 * Magnetic halo cursor. Hidden on touch / reduced-motion; on desktop it
 * follows the pointer with a tiny lag and swells when over interactive
 * elements. The OS cursor stays visible (accessibility first).
 */
export function Cursor() {
  const ref = useRef<HTMLDivElement | null>(null);
  const ringRef = useRef<HTMLDivElement | null>(null);
  const [enabled, setEnabled] = useState(false);

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

    let tx = -100,
      ty = -100;
    let cx = tx,
      cy = ty;
    let rx = tx,
      ry = ty;
    let raf = 0;
    let hovering = false;

    const onMove = (e: PointerEvent) => {
      tx = e.clientX;
      ty = e.clientY;
      const el = e.target as HTMLElement | null;
      hovering = !!el?.closest("a, button, [data-hover]");
    };

    // Exponential smoothing decoupled from frame rate — lerp rate is
    // framerate-dependent (k=0.25 at 60Hz feels snappy, at 240Hz it
    // would overshoot). We derive per-frame alpha from delta-time
    // and a target time constant, so 60/120/144/240/360Hz monitors
    // all produce identical perceived motion.
    const DOT_TAU = 0.06;  // seconds — small = tight follow
    const RING_TAU = 0.12; // seconds — larger = smoother lag
    let last = performance.now();

    const loop = (now: number) => {
      const dt = Math.min((now - last) / 1000, 0.05);
      last = now;
      const aDot  = 1 - Math.exp(-dt / DOT_TAU);
      const aRing = 1 - Math.exp(-dt / RING_TAU);
      cx += (tx - cx) * aDot;
      cy += (ty - cy) * aDot;
      rx += (tx - rx) * aRing;
      ry += (ty - ry) * aRing;
      if (ref.current) {
        ref.current.style.transform = `translate3d(${cx - 4}px, ${cy - 4}px, 0)`;
      }
      if (ringRef.current) {
        const scale = hovering ? 2.2 : 1;
        ringRef.current.style.transform = `translate3d(${rx - 18}px, ${ry - 18}px, 0) scale(${scale})`;
      }
      raf = requestAnimationFrame(loop);
    };

    window.addEventListener("pointermove", onMove);
    raf = requestAnimationFrame(loop);
    return () => {
      window.removeEventListener("pointermove", onMove);
      cancelAnimationFrame(raf);
    };
  }, [enabled]);

  if (!enabled) return null;
  return (
    <>
      <div ref={ringRef} className="cursor-ring" aria-hidden />
      <div ref={ref} className="cursor-dot" aria-hidden />
    </>
  );
}
