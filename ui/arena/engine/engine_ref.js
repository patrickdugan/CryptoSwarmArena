/* JavaScript reference of ui/arena/engine/src/lib.rs (`units_init` / `step` and the
   ambient layer, `amb_init` / `amb_step`).
   The viewer falls back to it when WebAssembly is unavailable, and
   ui/arena/engine/parity.test.mjs checks that the compiled module matches it.
   Keep the two in lockstep: same input layout, same state, same order of operations. */
(function (root) {
  "use strict";
  const IN = 24, ST = 16;
  const GX = 0, GY = 1, GZ = 2, GYAW = 3, SNAP = 4, WALKABLE = 5, SCALE = 6, HEAD_R = 7, TORSO_R = 8, ARM_OFF = 9,
    GY_OFF = 10, SLUMP = 11, PHASE = 12, STRESS = 13, OFF = 14, HAS_DESK = 15, AT_DESK = 16, NO_TYPE = 17, TURNED = 18,
    LEGACY_TURN = 19, POSE_KIND = 20, POSE_START = 21, SHAKE_START = 22, BASE_ROT = 23;
  const X = 0, Y = 1, Z = 2, YAW = 3, HEADING = 4, WALK = 5, STRIDE = 6, RX0 = 7, RZ0 = 8, RX1 = 9, RZ1 = 10,
    POSE_T = 11, POSE = 12, SHAKE = 13, INIT = 14;

  function compose(p, r, s) {   // T(p) * R(Euler XYZ, as three.js) * S(s), column-major
    const a = Math.cos(r[0]), b = Math.sin(r[0]), c = Math.cos(r[1]), d = Math.sin(r[1]), e = Math.cos(r[2]), f = Math.sin(r[2]);
    const ae = a * e, af = a * f, be = b * e, bf = b * f;
    return [
      c * e * s[0], (af + be * d) * s[0], (bf - ae * d) * s[0], 0,
      -c * f * s[1], (ae - bf * d) * s[1], (be + af * d) * s[1], 0,
      d * s[2], -b * c * s[2], a * c * s[2], 0,
      p[0], p[1], p[2], 1,
    ];
  }
  function mul(a, b) {
    const r = new Array(16);
    for (let col = 0; col < 4; col++) for (let row = 0; row < 4; row++) {
      let v = 0; for (let k = 0; k < 4; k++) v += a[k * 4 + row] * b[col * 4 + k];
      r[col * 4 + row] = v;
    }
    return r;
  }
  function put(out, i, m) { for (let k = 0; k < 16; k++) out[i * 16 + k] = m[k]; }
  const ONE = [1, 1, 1], ZERO = [0, 0, 0];

  // ---- ambient layer (amb_* in lib.rs): pedestrians on looping circuits, air traffic ----
  const MAX_PEDS = 192, MAX_CARS = 48, MAX_SLABS = 16, PIN = 12, PST = 8, CIN = 8, LIGHTS = 5, SLAB_N = 5;
  const LX0 = 0, LX1 = 1, LZ0 = 2, LZ1 = 3, DIR = 4, SPEED = 5, START = 6, PSCALE = 7, UMB = 8, PPHASE = 9, GROUND = 10;
  const PS = 0, LAT = 1, PY = 2, PYAW = 3, GAIT = 4, PINIT = 5, PACE = 6;
  const AXIS = 0, LANE = 1, HEIGHT = 2, CSPEED = 3, CSTART = 4, SPAN = 5, CPHASE = 6, FADE = 7;
  const LOCAL = [[1.0, 0.05, 3.45], [-1.0, 0.05, 3.45], [1.1, 0.15, -3.5], [-1.1, 0.15, -3.5], [0.0, -1.0, 0.0]];
  const clamp = (x, a, b) => Math.min(b, Math.max(a, x)), clamp01 = (x) => clamp(x, 0, 1);
  function loopAt(x0, x1, z0, z1, rc, s) {   // point and unit tangent on the rounded rectangle
    const lw = x1 - x0 - 2 * rc, lh = z1 - z0 - 2 * rc, la = rc * Math.PI * 0.5;
    const arc = (cx, cz, a) => [cx + rc * Math.cos(a), cz + rc * Math.sin(a), -Math.sin(a), Math.cos(a)];
    if (s < lw) return [x0 + rc + s, z0, 1, 0]; s -= lw;
    if (s < la) return arc(x1 - rc, z0 + rc, -Math.PI * 0.5 + s / rc); s -= la;
    if (s < lh) return [x1, z0 + rc + s, 0, 1]; s -= lh;
    if (s < la) return arc(x1 - rc, z1 - rc, s / rc); s -= la;
    if (s < lw) return [x1 - rc - s, z1, -1, 0]; s -= lw;
    if (s < la) return arc(x0 + rc, z1 - rc, Math.PI * 0.5 + s / rc); s -= la;
    if (s < lh) return [x0, z1 - rc - s, 0, -1]; s -= lh;
    return arc(x0 + rc, z0 + rc, Math.PI + Math.min(s, la) / rc);
  }
  function groundAt(slab, ns, ground, x, z) {   // street level, ramped onto a slab over its outer 0.4 units
    let lift = 0, top = ground;
    for (let k = 0; k < ns; k++) {
      const b = k * SLAB_N, w = clamp01((x - slab[b]) / 0.4) * clamp01((slab[b + 1] - x) / 0.4) * clamp01((z - slab[b + 2]) / 0.4) * clamp01((slab[b + 3] - z) / 0.4);
      if (w > lift) { lift = w; top = slab[b + 4]; }
    }
    return ground + (top - ground) * lift;
  }
  function steer(dx, dz, tx, tz, nx, nz, reach, tie, acc) {   // continuous push away from a neighbour, pace limit when close ahead
    const along = dx * tx + dz * tz, side = dx * nx + dz * nz;
    const wa = clamp01((along + 0.6) / 0.6) * clamp01((3.4 - along) / 1.0);
    const room = Math.max(0, reach - Math.abs(side));
    const away = clamp((-side + tie * 0.15) / 0.3, -1, 1);
    acc.push += away * room * wa * 2.2;   // strong enough to step clear (|side| > 0.9) and overtake
    const close = clamp01((1.6 - along) / 1.6) * clamp01(along / 0.3) * clamp01((0.9 - Math.abs(side)) / 0.3);
    acc.pace = Math.min(acc.pace, 1 - 0.65 * close);
  }
  function makeAmbient(units) {   // units() -> { n, pos } of the unit engine, read for avoidance
    let na = 0, nc = 0, ns = 0, pin = null, pst, cin, slab, abody, aleg, aumb, ppos, acar, alight, afade;
    const stv = new Float32Array(PST), acc = { push: 0, pace: 1 };
    return {
      ambInit(peds, cars, slabs) {
        na = Math.min(peds, MAX_PEDS); nc = Math.min(cars, MAX_CARS); ns = Math.min(slabs, MAX_SLABS);
        if (!pin) {
          pin = new Float32Array(MAX_PEDS * PIN); pst = new Float32Array(MAX_PEDS * PST); cin = new Float32Array(MAX_CARS * CIN); slab = new Float32Array(MAX_SLABS * SLAB_N);
          abody = new Float32Array(MAX_PEDS * 16); aleg = new Float32Array(MAX_PEDS * 32); aumb = new Float32Array(MAX_PEDS * 16); ppos = new Float32Array(MAX_PEDS * 4);
          acar = new Float32Array(MAX_CARS * 16); alight = new Float32Array(MAX_CARS * LIGHTS * 3); afade = new Float32Array(MAX_CARS * LIGHTS);
        }
        for (const b of [pin, pst, cin, slab, abody, aleg, aumb, ppos, acar, alight, afade]) b.fill(0);
        return { ped: pin.subarray(0, na * PIN), car: cin.subarray(0, nc * CIN), slab: slab.subarray(0, ns * SLAB_N), body: abody.subarray(0, na * 16),
          leg: aleg.subarray(0, na * 32), umb: aumb.subarray(0, na * 16), ppos: ppos.subarray(0, na * 4), carM: acar.subarray(0, nc * 16),
          light: alight.subarray(0, nc * LIGHTS * 3), fade: afade.subarray(0, nc * LIGHTS) };
      },
      ambStep(dtIn, now) {
        const dt = Math.min(0.05, Math.max(0, dtIn)), U = units();
        for (let i = 0; i < na; i++) {
          const I = i * PIN, S0 = i * PST;
          for (let k = 0; k < PST; k++) stv[k] = pst[S0 + k];
          const x0 = pin[I + LX0], x1 = pin[I + LX1], z0 = pin[I + LZ0], z1 = pin[I + LZ1];
          const rc = Math.max(0.05, Math.min(3, (x1 - x0) * 0.45, (z1 - z0) * 0.45));
          const per = 2 * (x1 - x0 + z1 - z0) - 8 * rc + 2 * Math.PI * rc;
          const dir = pin[I + DIR] < 0 ? -1 : 1;
          if (stv[PINIT] === 0) {
            stv[PS] = clamp(pin[I + START], 0, 1) * per;
            const b0 = loopAt(x0, x1, z0, z1, rc, stv[PS]);
            stv[PYAW] = Math.atan2(b0[2] * dir, b0[3] * dir);
            stv[PY] = groundAt(slab, ns, pin[I + GROUND], b0[0], b0[1]);
            stv[PACE] = 1; stv[PINIT] = 1;
          }
          let b = loopAt(x0, x1, z0, z1, rc, stv[PS]);
          let tx = b[2] * dir, tz = b[3] * dir, nx = tz, nz = -tx;
          const px = b[0] + nx * stv[LAT], pz = b[1] + nz * stv[LAT];
          const tie = i % 2 === 0 ? 1 : -1;
          acc.push = 0; acc.pace = 1;
          for (let u = 0; u < U.n; u++) steer(U.pos[u * 4] - px, U.pos[u * 4 + 2] - pz, tx, tz, nx, nz, 1.6, tie, acc);
          for (let j = 0; j < na; j++) if (j !== i) steer(ppos[j * 4] - px, ppos[j * 4 + 2] - pz, tx, tz, nx, nz, 1.4, tie, acc);
          const wander = Math.sin(now * 0.00031 + pin[I + PPHASE]) * 0.45;
          const target = clamp(wander + acc.push, -2.6, 2.6);
          stv[LAT] += (target - stv[LAT]) * Math.min(1, dt * 2.6);
          stv[PACE] += (acc.pace - stv[PACE]) * Math.min(1, dt * 4);
          const v = pin[I + SPEED] * stv[PACE];
          let s = (stv[PS] + dir * v * dt) % per; if (s < 0) s += per; stv[PS] = s;
          stv[GAIT] += dt * v * 1.15;
          b = loopAt(x0, x1, z0, z1, rc, stv[PS]);
          tx = b[2] * dir; tz = b[3] * dir; nx = tz; nz = -tx;
          const x = b[0] + nx * stv[LAT], z = b[1] + nz * stv[LAT];
          const gy = groundAt(slab, ns, pin[I + GROUND], x, z);
          stv[PY] += (gy - stv[PY]) * Math.min(1, dt * 14);
          const dy = Math.atan2(tx, tz) - stv[PYAW];
          let w = Math.atan2(Math.sin(dy), Math.cos(dy)); if (w < -Math.PI + 1e-3) w += 2 * Math.PI;
          stv[PYAW] += w * Math.min(1, dt * 6);
          const sc = pin[I + PSCALE], g = stv[GAIT], bob = Math.abs(Math.sin(g)) * 0.1;
          const body = compose([x, stv[PY] + bob, z], [0.05, stv[PYAW], 0], [sc, sc, sc]);
          put(abody, i, body);
          const swing = Math.sin(g) * 0.48;
          put(aleg, 2 * i, mul(body, compose([0.3, 1.85, 0], [swing, 0, 0], ONE)));
          put(aleg, 2 * i + 1, mul(body, compose([-0.3, 1.85, 0], [-swing, 0, 0], ONE)));
          if (pin[I + UMB] !== 0) { const sway = Math.sin(g * 0.5) * 0.025; put(aumb, i, mul(body, compose([0.42, 3.6, 0.2], [-0.12 + sway, 0, -0.06], ONE))); }
          else aumb.fill(0, i * 16, i * 16 + 16);
          ppos[i * 4] = x; ppos[i * 4 + 1] = stv[PY]; ppos[i * 4 + 2] = z; ppos[i * 4 + 3] = stv[PYAW];
          for (let k = 0; k < PST; k++) pst[S0 + k] = stv[k];
        }
        for (let c = 0; c < nc; c++) {   // vehicles: a function of the clock, in float64 like the module
          const Q = c * CIN, span = cin[Q + SPAN];
          const raw = cin[Q + CSTART] + cin[Q + CSPEED] * now * 0.001;
          let m2 = (raw + span) % (2 * span); if (m2 < 0) m2 += 2 * span;
          const p = Math.fround(m2 - span);
          const bob = Math.sin(now * 0.0011 + cin[Q + CPHASE]) * 0.35, fwd = cin[Q + CSPEED] >= 0;
          let x, z, yaw;
          if (cin[Q + AXIS] === 0) { x = p; z = cin[Q + LANE]; yaw = fwd ? Math.PI * 0.5 : -Math.PI * 0.5; }
          else { x = cin[Q + LANE]; z = p; yaw = fwd ? 0 : Math.PI; }
          const roll = Math.sin(now * 0.0007 + cin[Q + CPHASE] * 1.7) * 0.04;
          const m = compose([x, cin[Q + HEIGHT] + bob, z], [0, yaw, roll], ONE);
          put(acar, c, m);
          const f = clamp01((cin[Q + SPAN] - Math.abs(p)) / Math.max(1, cin[Q + SPAN] - cin[Q + FADE]));
          for (let k = 0; k < LIGHTS; k++) {
            const l = LOCAL[k], o = (c * LIGHTS + k) * 3;
            alight[o] = m[0] * l[0] + m[4] * l[1] + m[8] * l[2] + m[12];
            alight[o + 1] = m[1] * l[0] + m[5] * l[1] + m[9] * l[2] + m[13];
            alight[o + 2] = m[2] * l[0] + m[6] * l[1] + m[10] * l[2] + m[14];
            afade[c * LIGHTS + k] = f;
          }
        }
      },
    };
  }

  function createRefEngine() {
    let n = 0, inp, st, torso, head, leg, arm, phone, pos;
    const eng = {
      kind: "js",
      init(count) {
        n = count;
        inp = new Float32Array(n * IN); st = new Float32Array(n * ST);
        torso = new Float32Array(n * 16); head = new Float32Array(n * 16); leg = new Float32Array(n * 32); arm = new Float32Array(n * 32);
        phone = new Float32Array(n * 16); pos = new Float32Array(n * 4);
        return { inp, torso, head, leg, arm, phone, pos };
      },
      step(dtIn, now, hiveX, hiveZ, hiveVis) {
        const dt = Math.min(0.05, Math.max(0, dtIn));
        for (let i = 0; i < n; i++) {
          const I = i * IN, S = i * ST;
          if (st[S + INIT] === 0 || inp[I + SNAP] !== 0) {
            st[S + X] = inp[I + GX]; st[S + Y] = inp[I + GY]; st[S + Z] = inp[I + GZ];
            if (st[S + INIT] === 0) { st[S + YAW] = inp[I + BASE_ROT]; st[S + HEADING] = inp[I + BASE_ROT]; }
            st[S + WALK] = 0; st[S + INIT] = 1; inp[I + SNAP] = 0;
          }
          let moving = false;
          if (inp[I + WALKABLE] !== 0) {
            const dx = inp[I + GX] - st[S + X], dz = inp[I + GZ] - st[S + Z], dist = Math.sqrt(dx * dx + dz * dz);
            if (dist > 0.2) {
              const stp = Math.min(dist, dt * Math.max(10, dist / 1.6));
              st[S + X] += dx / dist * stp; st[S + Z] += dz / dist * stp; st[S + HEADING] = Math.atan2(dx, dz); moving = true;
            }
            st[S + Y] += (inp[I + GY] - st[S + Y]) * Math.min(1, dt * 6);
          } else { st[S + X] = inp[I + GX]; st[S + Y] = inp[I + GY]; st[S + Z] = inp[I + GZ]; }
          st[S + WALK] += ((moving ? 1 : 0) - st[S + WALK]) * Math.min(1, dt * 8);
          st[S + STRIDE] += dt * 10 * st[S + WALK];
          const walk = st[S + WALK], stride = st[S + STRIDE], ph = inp[I + PHASE], stress = inp[I + STRESS];
          const bob = Math.sin(now * 0.0016 + ph) * 0.18 * (1 - walk) + Math.abs(Math.sin(stride)) * 0.22 * walk;
          const sway = stress !== 0 ? Math.sin(now * 0.016 + ph) * 0.12 * stress * (1 - walk) : 0;
          let ry = inp[I + WALKABLE] !== 0 ? inp[I + GYAW] : inp[I + BASE_ROT];
          if (walk > 0.3) ry = st[S + HEADING];
          else if (inp[I + LEGACY_TURN] !== 0) ry += Math.PI;
          else if (stress > 0.12 && hiveVis !== 0) ry = Math.atan2(hiveX - st[S + X], hiveZ - st[S + Z]);
          const dy = ry - st[S + YAW];
          let w = Math.atan2(Math.sin(dy), Math.cos(dy)); if (w < -Math.PI + 1e-3) w += 2 * Math.PI;   // a half turn always goes the positive way
          st[S + YAW] += w * Math.min(1, dt * 5);
          if (inp[I + SHAKE_START] !== 0) { st[S + SHAKE] = 0.7; inp[I + SHAKE_START] = 0; }
          if (st[S + SHAKE] > 0) { st[S + SHAKE] -= dt; st[S + YAW] += Math.sin(now * 0.045) * 0.09; }
          const idle = Math.sin(now * 0.0018 + ph) * (0.07 + 0.3 * stress);
          let rx = [idle, -idle], rz = [-0.35, 0.35];
          if (inp[I + OFF] === 0 && inp[I + HAS_DESK] !== 0 && inp[I + NO_TYPE] === 0 && inp[I + AT_DESK] !== 0 && walk < 0.3) {
            const j = Math.sin(now * 0.02 + ph) * 0.05; rx = [-0.8 + j, -0.8 - j]; rz = [-0.15, 0.15];
          }
          if (walk > 0.05) { const a = Math.sin(stride) * 0.5 * walk; rx = [-a, a]; rz = [-0.25, 0.25]; }
          let lean = 0;
          if (inp[I + POSE_START] !== 0) { st[S + POSE] = inp[I + POSE_KIND]; st[S + POSE_T] = 1.8; inp[I + POSE_START] = 0; }
          if (st[S + POSE_T] > 0) {
            st[S + POSE_T] -= dt;
            if (st[S + POSE_T] <= 0) st[S + POSE] = 0;
            else switch (Math.trunc(st[S + POSE])) {
              case 1: rx[0] = -1.5; rz[0] = -0.1; break;
              case 2: rx[0] = -2.3; rz[0] = -0.55; break;
              case 3: rx[0] = -1.05; rz[0] = -0.1; lean = 0.12; break;
              case 4: rx = [-0.9, -0.9]; rz = [-0.2, 0.2]; break;
              case 5: rx[0] = -0.6; rz[0] = -1.1; break;
              default: break;
            }
          }
          const k = Math.min(1, dt * 7);
          st[S + RX0] += (rx[0] - st[S + RX0]) * k; st[S + RZ0] += (rz[0] - st[S + RZ0]) * k;
          st[S + RX1] += (rx[1] - st[S + RX1]) * k; st[S + RZ1] += (rz[1] - st[S + RZ1]) * k;
          const s = inp[I + SCALE], pitch = inp[I + SLUMP] + (inp[I + TURNED] !== 0 ? 0.14 : 0) + lean;
          const fig = compose([st[S + X], st[S + Y] + inp[I + GY_OFF] + bob, st[S + Z]], [pitch, st[S + YAW], sway], [s, s, s]);
          const tr = inp[I + TORSO_R], hr = inp[I + HEAD_R];
          put(torso, i, mul(fig, compose(ZERO, ZERO, [tr, 1, tr])));
          put(head, i, mul(fig, compose([0, 2.25, 0], ZERO, [hr, hr, hr])));
          const legsw = Math.sin(stride) * 0.55 * walk;
          put(leg, 2 * i, mul(fig, compose([0.42, -0.6, 0], [legsw, 0, 0], ONE)));
          put(leg, 2 * i + 1, mul(fig, compose([-0.42, -0.6, 0], [-legsw, 0, 0], ONE)));
          const aw = inp[I + ARM_OFF];
          const armR = mul(fig, compose([aw, 1.5, 0], [st[S + RX0], 0, st[S + RZ0]], ONE));
          const armL = mul(fig, compose([-aw, 1.5, 0], [st[S + RX1], 0, st[S + RZ1]], ONE));
          put(arm, 2 * i, armR); put(arm, 2 * i + 1, armL);
          put(phone, i, mul(armR, compose([0.1, -2.25, 0.32], [-0.4, 0, 0], ONE)));
          pos[i * 4] = st[S + X]; pos[i * 4 + 1] = st[S + Y]; pos[i * 4 + 2] = st[S + Z]; pos[i * 4 + 3] = st[S + YAW];
        }
      },
    };
    return Object.assign(eng, makeAmbient(() => ({ n, pos })));
  }
  const AMB = { MAX_PEDS, MAX_CARS, MAX_SLABS, PIN, CIN, LIGHTS, SLAB_N,
    PED: { LX0, LX1, LZ0, LZ1, DIR, SPEED, START, PSCALE, UMB, PPHASE, GROUND }, CAR: { AXIS, LANE, HEIGHT, CSPEED, CSTART, SPAN, CPHASE, FADE } };
  const api = { createRefEngine, AMB, IN, INPUT: { GX, GY, GZ, GYAW, SNAP, WALKABLE, SCALE, HEAD_R, TORSO_R, ARM_OFF, GY_OFF, SLUMP, PHASE, STRESS, OFF, HAS_DESK, AT_DESK, NO_TYPE, TURNED, LEGACY_TURN, POSE_KIND, POSE_START, SHAKE_START, BASE_ROT } };
  root.DioramaEngineRef = api;
  if (typeof module !== "undefined" && module.exports) module.exports = api;
})(typeof window !== "undefined" ? window : globalThis);
