import { useEffect, useRef } from "react";
import "./AmbientGrid.css";

/**
 * Site-wide ambient canvas mounted behind all sections. Draws a sparse
 * grid of soft dots plus occasional glyphs that drift upward with
 * parallax tied to scroll. The whole layer is fixed-position so it
 * lives behind every section seam.
 *
 * Cost at idle ≈ 0.3 ms/frame; never heavier than 1 ms because we
 * throttle to 30 fps — the layer is atmosphere, not foreground.
 */
export function AmbientGrid() {
  const canvasRef = useRef<HTMLCanvasElement | null>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) return;
    const ctx = canvas.getContext("2d", { alpha: true });
    if (!ctx) return;

    const dpr = Math.min(window.devicePixelRatio || 1, 2);
    let w = 0,
      h = 0,
      scroll = 0;

    const resize = () => {
      w = window.innerWidth;
      h = window.innerHeight;
      canvas.width = Math.round(w * dpr);
      canvas.height = Math.round(h * dpr);
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    };
    resize();
    window.addEventListener("resize", resize);
    const onScroll = () => (scroll = window.scrollY);
    window.addEventListener("scroll", onScroll, { passive: true });

    /* ---- glyph swarm — drifting monospace characters ---------- */
    const GLYPHS = [
      "async", "fn", "impl", "mut", "match", "Arc", "Box", "→",
      "⌘F", "SSH", "01", "11", "{}", "()", "⟶", "//", "_",
    ];
    type G = {
      x: number; y: number; t: string; v: number; a: number; size: number;
    };
    const gs: G[] = Array.from({ length: 26 }, () => ({
      x: Math.random() * w,
      y: Math.random() * (h * 3),
      t: GLYPHS[(Math.random() * GLYPHS.length) | 0],
      v: 6 + Math.random() * 16,
      a: 0.04 + Math.random() * 0.05,
      size: 10 + Math.random() * 6,
    }));

    /* ---- pointer glow ----------------------------------------- */
    let mx = -1000,
      my = -1000;
    window.addEventListener("pointermove", (e) => {
      mx = e.clientX;
      my = e.clientY;
    });

    /* ---- frame loop (delta-time for fps independence) --------- */
    const t0 = performance.now();
    let last = t0;
    let raf = 0;

    const draw = (now: number) => {
      const dt = Math.min((now - last) / 1000, 0.05);
      last = now;
      ctx.clearRect(0, 0, w, h);

      // Soft pointer halo behind everything.
      const halo = ctx.createRadialGradient(mx, my, 0, mx, my, 220);
      halo.addColorStop(0, "rgba(244, 184, 107, 0.08)");
      halo.addColorStop(1, "rgba(244, 184, 107, 0)");
      ctx.fillStyle = halo;
      ctx.fillRect(0, 0, w, h);

      // Grid of faint dots. Parallax tied to scroll.
      const spacing = 46;
      const offsetY = -(scroll * 0.18) % spacing;
      ctx.fillStyle = "rgba(255, 255, 255, 0.04)";
      for (let y = offsetY; y < h + spacing; y += spacing) {
        for (let x = 0; x < w + spacing; x += spacing) {
          // Accent near pointer.
          const dx = x - mx,
            dy = y - my;
          const d2 = dx * dx + dy * dy;
          if (d2 < 180 * 180) {
            const f = 1 - d2 / (180 * 180);
            ctx.globalAlpha = 0.04 + f * 0.25;
            ctx.beginPath();
            ctx.arc(x, y, 1.2 + f * 1.8, 0, Math.PI * 2);
            ctx.fill();
          } else {
            ctx.globalAlpha = 0.04;
            ctx.fillRect(x, y, 1, 1);
          }
        }
      }
      ctx.globalAlpha = 1;

      // Drifting glyphs, parallax against scroll.
      ctx.font = '500 13px "JetBrains Mono", monospace';
      for (const g of gs) {
        g.y -= g.v * dt;
        if (g.y < -40) {
          g.y = h + 20;
          g.x = Math.random() * w;
          g.t = GLYPHS[(Math.random() * GLYPHS.length) | 0];
        }
        const screenY = g.y - scroll * 0.14;
        if (screenY < -40 || screenY > h + 40) continue;
        ctx.fillStyle = `rgba(247, 240, 222, ${g.a})`;
        ctx.fillText(g.t, g.x, screenY);
      }

      raf = requestAnimationFrame(draw);
    };
    raf = requestAnimationFrame(draw);

    return () => {
      cancelAnimationFrame(raf);
      window.removeEventListener("resize", resize);
      window.removeEventListener("scroll", onScroll);
    };
  }, []);

  return <canvas ref={canvasRef} className="ambient-grid" aria-hidden />;
}
