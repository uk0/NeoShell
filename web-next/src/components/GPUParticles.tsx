import { useEffect, useRef } from "react";
import "./GPUParticles.css";

/**
 * WebGPU compute-shader particle field rendered on top of the Hero.
 * Compute kernel advects ~4000 particles through a simplex-noise flow
 * field plus a cursor attractor; render pass draws each as an
 * instanced quad with additive blend so density builds into glow.
 *
 * Feature-detected: does nothing when navigator.gpu is missing so it
 * stacks harmlessly on top of the WebGL2 fluid layer underneath.
 * Frame-rate independent — the compute uses real delta-time.
 */
export function GPUParticles() {
  const canvasRef = useRef<HTMLCanvasElement | null>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    if (!("gpu" in navigator)) return;
    if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) return;

    let disposed = false;
    let cleanup: (() => void) | undefined;
    (async () => {
      try {
        cleanup = await initWebGPU(canvas);
        if (disposed && cleanup) cleanup();
      } catch (err) {
        // WebGPU init can fail on certain adapters; silently fall
        // back to the WebGL2 fluid layer below.
        console.debug("[GPUParticles] webgpu init failed:", err);
      }
    })();
    return () => {
      disposed = true;
      cleanup?.();
    };
  }, []);

  return <canvas ref={canvasRef} className="gpu-particles" aria-hidden />;
}

/* ==================================================================== */

const COMPUTE_WGSL = /* wgsl */ `
struct Particle {
  pos: vec2f,
  vel: vec2f,
  color: vec3f,
  age: f32,
};

struct Params {
  t: f32,
  dt: f32,
  mx: f32,
  my: f32,
  rx: f32,
  ry: f32,
  _pad0: f32,
  _pad1: f32,
};

@group(0) @binding(0) var<storage, read_write> particles: array<Particle>;
@group(0) @binding(1) var<uniform> P: Params;

fn hash(n: f32) -> f32 {
  return fract(sin(n) * 43758.5453);
}

@compute @workgroup_size(64)
fn main(@builtin(global_invocation_id) gid: vec3u) {
  let i = gid.x;
  if (i >= arrayLength(&particles)) { return; }
  var p = particles[i];

  let sp = p.pos * 0.0032;
  let t = P.t * 0.4;
  let nx = sin(sp.x + t) + cos(sp.y * 0.7 - t * 0.7);
  let ny = cos(sp.x * 0.8 - t * 0.8) + sin(sp.y + t * 1.1);

  let md = vec2f(P.mx, P.my) - p.pos;
  let r2 = dot(md, md);
  let pull = md * 0.00025 * exp(-r2 * 0.00004);

  let damp = pow(0.93, P.dt * 60.0);
  p.vel = p.vel * damp + (vec2f(nx, ny) * 18.0 + pull * 800.0) * P.dt;
  p.pos = p.pos + p.vel * P.dt * 50.0;

  // Wrap around screen edges.
  if (p.pos.x < -8.0)          { p.pos.x = P.rx + 8.0; }
  if (p.pos.x > P.rx + 8.0)    { p.pos.x = -8.0; }
  if (p.pos.y < -8.0)          { p.pos.y = P.ry + 8.0; }
  if (p.pos.y > P.ry + 8.0)    { p.pos.y = -8.0; }

  p.age = p.age + P.dt;

  // Periodic re-seed so particles don't lump in the same attractors
  // forever. Keeps motion fresh even with static mouse.
  if (p.age > 14.0 + hash(f32(i)) * 6.0) {
    p.pos = vec2f(
      P.rx * hash(f32(i) + P.t * 0.1),
      P.ry * hash(f32(i) + P.t * 0.2 + 3.17)
    );
    p.vel = vec2f(0.0, 0.0);
    p.age = 0.0;
  }

  particles[i] = p;
}`;

const RENDER_WGSL = /* wgsl */ `
struct Particle {
  pos: vec2f,
  vel: vec2f,
  color: vec3f,
  age: f32,
};

struct Params {
  t: f32,
  dt: f32,
  mx: f32,
  my: f32,
  rx: f32,
  ry: f32,
  _pad0: f32,
  _pad1: f32,
};

@group(0) @binding(0) var<storage, read> particles: array<Particle>;
@group(0) @binding(1) var<uniform> P: Params;

struct VSOut {
  @builtin(position) pos: vec4f,
  @location(0) uv:    vec2f,
  @location(1) color: vec3f,
  @location(2) alpha: f32,
};

const CORNERS = array<vec2f, 6>(
  vec2f(-1.0, -1.0), vec2f( 1.0, -1.0), vec2f( 1.0,  1.0),
  vec2f(-1.0, -1.0), vec2f( 1.0,  1.0), vec2f(-1.0,  1.0),
);

@vertex
fn vs_main(
  @builtin(vertex_index)   vi: u32,
  @builtin(instance_index) ii: u32,
) -> VSOut {
  let p = particles[ii];
  let corner = CORNERS[vi];

  // Speed-modulated size so faster particles streak slightly longer.
  let speed = length(p.vel);
  let radius = 2.0 + clamp(speed * 0.012, 0.0, 4.0);

  let px = p.pos + corner * radius;
  var ndc = (px / vec2f(P.rx, P.ry)) * 2.0 - 1.0;
  ndc.y = -ndc.y;

  // Alpha rises in the particle's first second of life, then holds.
  let lifeIn = clamp(p.age / 1.2, 0.0, 1.0);

  var o: VSOut;
  o.pos   = vec4f(ndc, 0.0, 1.0);
  o.uv    = corner;
  o.color = p.color;
  o.alpha = 0.55 * lifeIn;
  return o;
}

@fragment
fn fs_main(in: VSOut) -> @location(0) vec4f {
  // Round soft falloff.
  let d = dot(in.uv, in.uv);
  let a = smoothstep(1.0, 0.0, d) * in.alpha;
  return vec4f(in.color * a, a);
}`;

async function initWebGPU(canvas: HTMLCanvasElement): Promise<() => void> {
  const adapter = await navigator.gpu.requestAdapter({
    powerPreference: "high-performance",
  });
  if (!adapter) throw new Error("no adapter");
  const device = await adapter.requestDevice();
  const ctx = canvas.getContext("webgpu");
  if (!ctx) throw new Error("no webgpu context");

  const format = navigator.gpu.getPreferredCanvasFormat();
  ctx.configure({ device, format, alphaMode: "premultiplied" });

  const dpr = Math.min(window.devicePixelRatio || 1, 2);
  let rx = 0,
    ry = 0;
  const resize = () => {
    const r = canvas.getBoundingClientRect();
    canvas.width = Math.max(2, Math.round(r.width * dpr));
    canvas.height = Math.max(2, Math.round(r.height * dpr));
    rx = canvas.width;
    ry = canvas.height;
  };
  resize();
  const ro = new ResizeObserver(resize);
  ro.observe(canvas);

  /* ------- particle buffer ----------------------------------------- */
  const N = 4000;
  const STRIDE_F32 = 8; // pos(2) + vel(2) + color(3) + age(1)
  const BYTES_PER = STRIDE_F32 * 4;
  const init = new Float32Array(N * STRIDE_F32);
  for (let i = 0; i < N; i++) {
    const o = i * STRIDE_F32;
    const k = Math.random();
    init[o + 0] = Math.random() * rx;
    init[o + 1] = Math.random() * ry;
    init[o + 2] = (Math.random() - 0.5) * 8;
    init[o + 3] = (Math.random() - 0.5) * 8;
    // Amber -> teal gradient by id.
    init[o + 4] = 0.957 * (1 - k) + 0.365 * k;
    init[o + 5] = 0.722 * (1 - k) + 0.894 * k;
    init[o + 6] = 0.42  * (1 - k) + 0.78  * k;
    init[o + 7] = Math.random() * 8;
  }
  const particleBuffer = device.createBuffer({
    size: N * BYTES_PER,
    usage:
      GPUBufferUsage.STORAGE |
      GPUBufferUsage.COPY_DST,
  });
  device.queue.writeBuffer(particleBuffer, 0, init);

  const paramsBuffer = device.createBuffer({
    size: 32,
    usage: GPUBufferUsage.UNIFORM | GPUBufferUsage.COPY_DST,
  });

  /* ------- pipelines ----------------------------------------------- */
  const computeModule = device.createShaderModule({ code: COMPUTE_WGSL });
  const renderModule = device.createShaderModule({ code: RENDER_WGSL });

  const computePipeline = device.createComputePipeline({
    layout: "auto",
    compute: { module: computeModule, entryPoint: "main" },
  });

  const renderPipeline = device.createRenderPipeline({
    layout: "auto",
    vertex: { module: renderModule, entryPoint: "vs_main" },
    fragment: {
      module: renderModule,
      entryPoint: "fs_main",
      targets: [
        {
          format,
          blend: {
            color: { srcFactor: "src-alpha", dstFactor: "one", operation: "add" },
            alpha: { srcFactor: "one",       dstFactor: "one", operation: "add" },
          },
        },
      ],
    },
    primitive: { topology: "triangle-list" },
  });

  const computeBG = device.createBindGroup({
    layout: computePipeline.getBindGroupLayout(0),
    entries: [
      { binding: 0, resource: { buffer: particleBuffer } },
      { binding: 1, resource: { buffer: paramsBuffer } },
    ],
  });
  const renderBG = device.createBindGroup({
    layout: renderPipeline.getBindGroupLayout(0),
    entries: [
      { binding: 0, resource: { buffer: particleBuffer } },
      { binding: 1, resource: { buffer: paramsBuffer } },
    ],
  });

  /* ------- pointer uniform ----------------------------------------- */
  let mx = rx * 0.5,
    my = ry * 0.35;
  const onMove = (e: PointerEvent) => {
    const r = canvas.getBoundingClientRect();
    mx = (e.clientX - r.left) * dpr;
    my = (e.clientY - r.top) * dpr;
  };
  canvas.parentElement?.addEventListener("pointermove", onMove);

  /* ------- frame loop ---------------------------------------------- */
  const t0 = performance.now();
  let last = t0;
  let raf = 0;
  let running = true;

  const frame = () => {
    if (!running) return;
    const now = performance.now();
    const dt = Math.min((now - last) / 1000, 0.05);
    last = now;
    const t = (now - t0) / 1000;

    device.queue.writeBuffer(
      paramsBuffer,
      0,
      new Float32Array([t, dt, mx, my, rx, ry, 0, 0]),
    );

    const encoder = device.createCommandEncoder();

    const cpass = encoder.beginComputePass();
    cpass.setPipeline(computePipeline);
    cpass.setBindGroup(0, computeBG);
    cpass.dispatchWorkgroups(Math.ceil(N / 64));
    cpass.end();

    const rpass = encoder.beginRenderPass({
      colorAttachments: [
        {
          view: ctx.getCurrentTexture().createView(),
          clearValue: { r: 0, g: 0, b: 0, a: 0 },
          loadOp: "clear",
          storeOp: "store",
        },
      ],
    });
    rpass.setPipeline(renderPipeline);
    rpass.setBindGroup(0, renderBG);
    rpass.draw(6, N, 0, 0);
    rpass.end();

    device.queue.submit([encoder.finish()]);
    raf = requestAnimationFrame(frame);
  };
  raf = requestAnimationFrame(frame);

  return () => {
    running = false;
    cancelAnimationFrame(raf);
    ro.disconnect();
    canvas.parentElement?.removeEventListener("pointermove", onMove);
    particleBuffer.destroy();
    paramsBuffer.destroy();
    device.destroy();
  };
}
