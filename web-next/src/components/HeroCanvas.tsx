import { useEffect, useRef } from "react";
import "./HeroCanvas.css";

/**
 * Hero background. Prefers a WebGL2 fragment-shader flow field rendered
 * on a fullscreen quad (GPU-accelerated, cost = a few dozen µs per
 * frame). Falls back to a Canvas2D particle system when WebGL2 isn't
 * available. Both paths respect prefers-reduced-motion.
 *
 * TODO (next pass): swap in a WebGPU compute pipeline when Safari's
 * WebGPU support stabilises on common macOS installs.
 */
export function HeroCanvas() {
  const canvasRef = useRef<HTMLCanvasElement | null>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) return;

    const gl = canvas.getContext("webgl2", {
      alpha: false,
      antialias: false,
      powerPreference: "high-performance",
    });
    if (gl) return startWebGL(canvas, gl);
    return startFallback2D(canvas);
  }, []);

  return (
    <div className="hero-canvas-wrap" aria-hidden>
      <canvas ref={canvasRef} className="hero-canvas" />
      <div className="hero-canvas-vignette" />
    </div>
  );
}

/* ====================================================================
   WebGL2 implementation: single fullscreen triangle, fragment shader
   generates a time-driven simplex-noise flow field colored between
   amber and teal. Mouse biases the glow.
   ==================================================================== */

const VERT = /* glsl */ `#version 300 es
in vec2 a_pos;
out vec2 v_uv;
void main() {
  v_uv = a_pos * 0.5 + 0.5;
  gl_Position = vec4(a_pos, 0.0, 1.0);
}`;

const FRAG = /* glsl */ `#version 300 es
precision highp float;
in vec2 v_uv;
out vec4 fragColor;
uniform float u_t;
uniform vec2  u_res;
uniform vec2  u_mouse;

/* Simplex 2D noise (Ashima / Stefan Gustavson) */
vec3 permute(vec3 x) { return mod(((x * 34.0) + 1.0) * x, 289.0); }
float snoise(vec2 v) {
  const vec4 C = vec4(0.211324865405187, 0.366025403784439,
                      -0.577350269189626, 0.024390243902439);
  vec2 i  = floor(v + dot(v, C.yy));
  vec2 x0 = v -   i + dot(i, C.xx);
  vec2 i1 = (x0.x > x0.y) ? vec2(1.0, 0.0) : vec2(0.0, 1.0);
  vec4 x12 = x0.xyxy + C.xxzz;
  x12.xy -= i1;
  i = mod(i, 289.0);
  vec3 p = permute(permute(i.y + vec3(0.0, i1.y, 1.0))
                   + i.x + vec3(0.0, i1.x, 1.0));
  vec3 m = max(0.5 - vec3(dot(x0, x0),
                          dot(x12.xy, x12.xy),
                          dot(x12.zw, x12.zw)), 0.0);
  m = m * m; m = m * m;
  vec3 x = 2.0 * fract(p * C.www) - 1.0;
  vec3 h = abs(x) - 0.5;
  vec3 ox = floor(x + 0.5);
  vec3 a0 = x - ox;
  m *= 1.79284291400159 - 0.85373472095314 * (a0 * a0 + h * h);
  vec3 g = vec3(a0.x * x0.x + h.x * x0.y,
                a0.yz * x12.xz + h.yz * x12.yw);
  return 130.0 * dot(m, g);
}

float fbm(vec2 p) {
  float v = 0.0, a = 0.5;
  for (int i = 0; i < 5; i++) {
    v += a * snoise(p);
    p *= 2.03;
    a *= 0.5;
  }
  return v;
}

void main() {
  vec2 uv = v_uv;
  vec2 p = uv;
  p.x *= u_res.x / u_res.y;
  p *= 1.9;

  float t = u_t * 0.14;
  float n1 = fbm(p + vec2(t, 0.0));
  float n2 = fbm(p * 0.7 + vec2(0.0, -t * 0.6) + 11.0);

  /* Flow bands — thin ribbons where the field crosses a contour.
     Intentionally quiet so the hero copy stays legible on top. */
  float field = n1 + n2 * 0.5;
  float bands = smoothstep(0.04, 0.0, abs(field) - 0.04);
  float glow  = smoothstep(0.8, 0.0, abs(field));

  vec3 amber = vec3(0.957, 0.722, 0.420);
  vec3 teal  = vec3(0.365, 0.894, 0.780);
  vec3 deep  = vec3(0.039, 0.043, 0.071);

  vec3 col = deep;
  col = mix(col, amber, glow * 0.09 * (0.6 + 0.4 * sin(t + n2)));
  col = mix(col, teal,  glow * 0.09 * (0.6 + 0.4 * cos(t * 1.3 - n1)));
  col += bands * mix(amber, teal, 0.5) * 0.22;

  /* Mouse beacon — subtle local brighten following the cursor. */
  vec2 md = uv - u_mouse;
  md.x *= u_res.x / u_res.y;
  float beacon = exp(-dot(md, md) * 9.0);
  col += amber * beacon * 0.12;

  /* Copy-protection scrim — keep the lower-left readable where the
     hero title lives. */
  float copyMask = smoothstep(0.0, 0.55, uv.x) * smoothstep(0.0, 0.45, 1.0 - uv.y);
  col *= mix(1.0, 0.28, copyMask);

  /* Edge vignette. */
  float vg = smoothstep(1.25, 0.25, length(uv - vec2(0.4, 0.55)));
  col *= vg;

  /* Fine film grain via the fractional coordinate. */
  float grain = fract(sin(dot(gl_FragCoord.xy, vec2(12.9898, 78.233))) * 43758.5453);
  col += (grain - 0.5) * 0.012;

  fragColor = vec4(col, 1.0);
}`;

function compile(gl: WebGL2RenderingContext, type: number, src: string) {
  const s = gl.createShader(type)!;
  gl.shaderSource(s, src);
  gl.compileShader(s);
  if (!gl.getShaderParameter(s, gl.COMPILE_STATUS)) {
    const log = gl.getShaderInfoLog(s);
    gl.deleteShader(s);
    throw new Error(`shader: ${log}`);
  }
  return s;
}

function startWebGL(canvas: HTMLCanvasElement, gl: WebGL2RenderingContext): () => void {
  const dpr = Math.min(window.devicePixelRatio || 1, 2);
  let w = 0, h = 0;

  const resize = () => {
    const rect = canvas.getBoundingClientRect();
    w = rect.width;
    h = rect.height;
    canvas.width = Math.round(w * dpr);
    canvas.height = Math.round(h * dpr);
    gl.viewport(0, 0, canvas.width, canvas.height);
  };
  resize();
  const ro = new ResizeObserver(resize);
  ro.observe(canvas);

  let program: WebGLProgram;
  try {
    const vs = compile(gl, gl.VERTEX_SHADER, VERT);
    const fs = compile(gl, gl.FRAGMENT_SHADER, FRAG);
    program = gl.createProgram()!;
    gl.attachShader(program, vs);
    gl.attachShader(program, fs);
    gl.linkProgram(program);
    if (!gl.getProgramParameter(program, gl.LINK_STATUS)) {
      throw new Error(gl.getProgramInfoLog(program) ?? "link failed");
    }
  } catch {
    ro.disconnect();
    return startFallback2D(canvas);
  }
  gl.useProgram(program);

  /* Fullscreen triangle trick — one vert buffer, three vertices. */
  const buf = gl.createBuffer();
  gl.bindBuffer(gl.ARRAY_BUFFER, buf);
  gl.bufferData(
    gl.ARRAY_BUFFER,
    new Float32Array([-1, -1, 3, -1, -1, 3]),
    gl.STATIC_DRAW,
  );
  const aPos = gl.getAttribLocation(program, "a_pos");
  gl.enableVertexAttribArray(aPos);
  gl.vertexAttribPointer(aPos, 2, gl.FLOAT, false, 0, 0);

  const uT = gl.getUniformLocation(program, "u_t");
  const uRes = gl.getUniformLocation(program, "u_res");
  const uMouse = gl.getUniformLocation(program, "u_mouse");

  let mx = 0.5, my = 0.35;
  const onMove = (e: PointerEvent) => {
    const r = canvas.getBoundingClientRect();
    mx = (e.clientX - r.left) / r.width;
    my = 1.0 - (e.clientY - r.top) / r.height;
  };
  canvas.parentElement?.addEventListener("pointermove", onMove);

  const t0 = performance.now();
  let raf = 0;
  const frame = () => {
    const t = (performance.now() - t0) / 1000;
    gl.uniform1f(uT, t);
    gl.uniform2f(uRes, canvas.width, canvas.height);
    gl.uniform2f(uMouse, mx, my);
    gl.drawArrays(gl.TRIANGLES, 0, 3);
    raf = requestAnimationFrame(frame);
  };
  raf = requestAnimationFrame(frame);

  return () => {
    cancelAnimationFrame(raf);
    ro.disconnect();
    canvas.parentElement?.removeEventListener("pointermove", onMove);
    gl.deleteProgram(program);
    gl.deleteBuffer(buf);
  };
}

/* ====================================================================
   Canvas2D fallback — the pre-GL particle flow field. Cheaper.
   ==================================================================== */

function startFallback2D(canvas: HTMLCanvasElement): () => void {
  const ctx = canvas.getContext("2d", { alpha: true });
  if (!ctx) return () => {};

  const dpr = Math.min(window.devicePixelRatio || 1, 2);
  let w = 0, h = 0;
  const resize = () => {
    const rect = canvas.getBoundingClientRect();
    w = rect.width;
    h = rect.height;
    canvas.width = Math.round(w * dpr);
    canvas.height = Math.round(h * dpr);
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  };
  resize();
  const ro = new ResizeObserver(resize);
  ro.observe(canvas);

  const N = 220;
  type P = { x: number; y: number; vx: number; vy: number; a: number; c: [number, number, number] };
  const lerp = (a: number, b: number, t: number) => a + (b - a) * t;
  const amber: [number, number, number] = [244, 184, 107];
  const teal:  [number, number, number] = [ 93, 228, 199];
  const ps: P[] = [];
  for (let i = 0; i < N; i++) {
    const t = Math.random();
    ps.push({
      x: Math.random() * w, y: Math.random() * h, vx: 0, vy: 0,
      a: Math.random() * 0.55 + 0.1,
      c: [lerp(amber[0], teal[0], t), lerp(amber[1], teal[1], t), lerp(amber[2], teal[2], t)],
    });
  }

  let mx = w * 0.5, my = h * 0.35;
  const onMove = (e: PointerEvent) => {
    const r = canvas.getBoundingClientRect();
    mx = e.clientX - r.left;
    my = e.clientY - r.top;
  };
  canvas.parentElement?.addEventListener("pointermove", onMove);

  // Frame-rate-independent. Uses real delta-time so the simulation
  // runs identically at 60 / 120 / 144 / 240 / 360 Hz; rAF already
  // fires in lockstep with the monitor refresh, but physics had to
  // stop scaling with frame count or high-Hz users would see the
  // animation run twice as fast.
  let raf = 0, t = 0;
  let last = performance.now();
  const draw = (now: number) => {
    const dt = Math.min((now - last) / 1000, 0.05); // clamp runaway gaps
    last = now;
    t += dt;
    const k60 = dt * 60; // scale "per-60fps-frame" tunables

    ctx.fillStyle = `rgba(10, 11, 18, ${Math.min(0.12 * k60, 0.4)})`;
    ctx.fillRect(0, 0, w, h);
    ctx.globalCompositeOperation = "lighter";
    const damp = Math.pow(0.94, k60);
    const stepScale = k60;
    for (let i = 0; i < N; i++) {
      const p = ps[i];
      const nx = Math.sin(p.x * 0.0032 + t * 2.1) + Math.cos(p.y * 0.0024 - t * 1.5);
      const ny = Math.cos(p.x * 0.0028 - t * 1.7) + Math.sin(p.y * 0.0036 + t * 2.1);
      p.vx = p.vx * damp + (nx * 0.35 + (mx - p.x) * 0.00008) * 0.6 * stepScale;
      p.vy = p.vy * damp + (ny * 0.35 + (my - p.y) * 0.00008) * 0.6 * stepScale;
      const px = p.x, py = p.y;
      p.x += p.vx; p.y += p.vy;
      if (p.x < -10) p.x = w + 10; if (p.x > w + 10) p.x = -10;
      if (p.y < -10) p.y = h + 10; if (p.y > h + 10) p.y = -10;
      ctx.strokeStyle = `rgba(${p.c[0]|0}, ${p.c[1]|0}, ${p.c[2]|0}, ${p.a * 0.5})`;
      ctx.lineWidth = 1;
      ctx.beginPath();
      ctx.moveTo(px, py);
      ctx.lineTo(p.x, p.y);
      ctx.stroke();
    }
    ctx.globalCompositeOperation = "source-over";
    raf = requestAnimationFrame(draw);
  };
  raf = requestAnimationFrame(draw);

  return () => {
    cancelAnimationFrame(raf);
    ro.disconnect();
    canvas.parentElement?.removeEventListener("pointermove", onMove);
  };
}
