//! Per-frame animation core for the Hive Swarm diorama viewer, compiled to WebAssembly.
//!
//! Presentation only. The viewer derives each unit's goal (desk, kiosk, transit stop,
//! night gathering spot) from the exported replay; this core walks the units there, runs
//! the gait, the idle / typing / event poses and the facing rules, and writes column-major
//! 4x4 instance matrices that three.js draws with instancing. It reads nothing from, and
//! writes nothing to, the sims.
//!
//! ABI: plain C exports over linear memory, no bindings generator. Per scenario the viewer
//! calls `units_init(n)`, writes `IN` floats per unit into `units_in()`, then calls `step()`
//! every animation frame and reads the outputs (`units_torso()`, `units_head()`,
//! `units_leg()`, `units_arm()`, `units_phone()`, `units_pos()`) as Float32Array views.
//! All buffers are allocated in `units_init`; nothing allocates afterwards, so the views
//! stay valid until the next `units_init` (the viewer rebuilds them then).
//!
//! The ambient layer (`amb_*`, below) animates decorative city life: pedestrians on
//! looping sidewalk circuits and air traffic. Its buffers are fixed-capacity statics, so
//! `amb_init` never allocates and never invalidates the units' views.
//!
//! `ui/arena/engine/engine_ref.js` is a line-for-line JavaScript reference of `step` and
//! `amb_step`; the viewer falls back to it if WebAssembly is unavailable, and a Node test
//! checks parity.

use core::f32::consts::PI;

/// Floats per unit in the input block.
pub const IN: usize = 24;
/// Floats per unit in the private state block.
const ST: usize = 16;

// ---- input layout (written by the viewer) ----
const GX: usize = 0; // goal: rig centre (feet at -3)
const GY: usize = 1;
const GZ: usize = 2;
const GYAW: usize = 3; // yaw to face once arrived
const SNAP: usize = 4; // 1 = teleport to the goal this step (scrubbing); cleared by the core
const WALKABLE: usize = 5; // 1 = walks to goals (city layout); 0 = pinned (legacy layout)
const SCALE: usize = 6; // overall figure scale
const HEAD_R: usize = 7; // head size relative to the shared head geometry
const TORSO_R: usize = 8; // shoulder width relative to the shared torso geometry
const ARM_OFF: usize = 9; // shoulder x offset
const GY_OFF: usize = 10; // figure's local y inside the rig (feet on the ground)
const SLUMP: usize = 11; // archetype posture pitch
const PHASE: usize = 12; // per-unit phase for idle motion
const STRESS: usize = 13; // graded pressure, 0..1
const OFF: usize = 14; // off shift
const HAS_DESK: usize = 15; // has a laptop / server to type at
const AT_DESK: usize = 16; // the routine says "desk" this frame
const NO_TYPE: usize = 17; // compromised or recruited: no typing
const TURNED: usize = 18; // compromised (not a decoy): slumps forward
const LEGACY_TURN: usize = 19; // legacy layout: off shift turns away from the desk
const POSE_KIND: usize = 20; // 1 declined, 2 phone to face, 3 plug in, 4 both arms, 5 envelope, 6+ no arm change
const POSE_START: usize = 21; // 1 = start POSE_KIND now; cleared by the core
const SHAKE_START: usize = 22; // 1 = head shake now; cleared by the core
const BASE_ROT: usize = 23; // yaw at the station

// ---- private state ----
const X: usize = 0;
const Y: usize = 1;
const Z: usize = 2;
const YAW: usize = 3;
const HEADING: usize = 4;
const WALK: usize = 5;
const STRIDE: usize = 6;
const RX0: usize = 7;
const RZ0: usize = 8;
const RX1: usize = 9;
const RZ1: usize = 10;
const POSE_T: usize = 11;
const POSE: usize = 12;
const SHAKE: usize = 13;
const INIT: usize = 14;

type M4 = [f32; 16];

/// T(p) * R(Euler XYZ, as three.js) * S(s), column-major.
fn compose(p: [f32; 3], r: [f32; 3], s: [f32; 3]) -> M4 {
    let (a, b) = (r[0].cos(), r[0].sin());
    let (c, d) = (r[1].cos(), r[1].sin());
    let (e, f) = (r[2].cos(), r[2].sin());
    let (ae, af, be, bf) = (a * e, a * f, b * e, b * f);
    [
        c * e * s[0], (af + be * d) * s[0], (bf - ae * d) * s[0], 0.0,
        -c * f * s[1], (ae - bf * d) * s[1], (be + af * d) * s[1], 0.0,
        d * s[2], -b * c * s[2], a * c * s[2], 0.0,
        p[0], p[1], p[2], 1.0,
    ]
}

fn mul(a: &M4, b: &M4) -> M4 {
    let mut r = [0.0f32; 16];
    for col in 0..4 {
        for row in 0..4 {
            let mut v = 0.0;
            for k in 0..4 {
                v += a[k * 4 + row] * b[col * 4 + k];
            }
            r[col * 4 + row] = v;
        }
    }
    r
}

fn put(out: &mut [f32], i: usize, m: &M4) {
    out[i * 16..i * 16 + 16].copy_from_slice(m);
}

fn s64(x: f64) -> f32 {
    x.sin() as f32
}

struct Engine {
    n: usize,
    inp: Vec<f32>,
    st: Vec<f32>,
    torso: Vec<f32>,
    head: Vec<f32>,
    leg: Vec<f32>,
    arm: Vec<f32>,
    phone: Vec<f32>,
    pos: Vec<f32>,
}

static mut ENGINE: Engine = Engine {
    n: 0,
    inp: Vec::new(),
    st: Vec::new(),
    torso: Vec::new(),
    head: Vec::new(),
    leg: Vec::new(),
    arm: Vec::new(),
    phone: Vec::new(),
    pos: Vec::new(),
};

fn eng() -> &'static mut Engine {
    // wasm32-unknown-unknown is single-threaded; the viewer is the only caller.
    unsafe { &mut *core::ptr::addr_of_mut!(ENGINE) }
}

#[no_mangle]
pub extern "C" fn engine_version() -> u32 {
    2
}

#[no_mangle]
pub extern "C" fn in_stride() -> u32 {
    IN as u32
}

/// Allocate every buffer for `n` units (zeroed). Views taken before this call are invalid.
#[no_mangle]
pub extern "C" fn units_init(n: u32) -> u32 {
    let e = eng();
    let n = n as usize;
    e.n = n;
    e.inp = vec![0.0; n * IN];
    e.st = vec![0.0; n * ST];
    e.torso = vec![0.0; n * 16];
    e.head = vec![0.0; n * 16];
    e.leg = vec![0.0; n * 2 * 16];
    e.arm = vec![0.0; n * 2 * 16];
    e.phone = vec![0.0; n * 16];
    e.pos = vec![0.0; n * 4];
    n as u32
}

#[no_mangle]
pub extern "C" fn units_in() -> *mut f32 {
    eng().inp.as_mut_ptr()
}
#[no_mangle]
pub extern "C" fn units_torso() -> *const f32 {
    eng().torso.as_ptr()
}
#[no_mangle]
pub extern "C" fn units_head() -> *const f32 {
    eng().head.as_ptr()
}
#[no_mangle]
pub extern "C" fn units_leg() -> *const f32 {
    eng().leg.as_ptr()
}
#[no_mangle]
pub extern "C" fn units_arm() -> *const f32 {
    eng().arm.as_ptr()
}
#[no_mangle]
pub extern "C" fn units_phone() -> *const f32 {
    eng().phone.as_ptr()
}
#[no_mangle]
pub extern "C" fn units_pos() -> *const f32 {
    eng().pos.as_ptr()
}

/// Advance every unit by `dt` seconds at wall-clock `now` (ms) and write all outputs.
/// `hive_*` is the adversary marker: pressed units turn to watch it when it is visible.
#[no_mangle]
pub extern "C" fn step(dt: f32, now: f64, hive_x: f32, hive_z: f32, hive_vis: f32) {
    let e = eng();
    let dt = dt.clamp(0.0, 0.05);
    for i in 0..e.n {
        let inp = &mut e.inp[i * IN..(i + 1) * IN];
        let st = &mut e.st[i * ST..(i + 1) * ST];

        if st[INIT] == 0.0 || inp[SNAP] != 0.0 {
            st[X] = inp[GX];
            st[Y] = inp[GY];
            st[Z] = inp[GZ];
            if st[INIT] == 0.0 {
                st[YAW] = inp[BASE_ROT];
                st[HEADING] = inp[BASE_ROT];
            }
            st[WALK] = 0.0;
            st[INIT] = 1.0;
            inp[SNAP] = 0.0;
        }

        // walking: head for the goal, arriving within ~1.6 s at no less than 10 units/s
        let mut moving = false;
        if inp[WALKABLE] != 0.0 {
            let (dx, dz) = (inp[GX] - st[X], inp[GZ] - st[Z]);
            let dist = (dx * dx + dz * dz).sqrt();
            if dist > 0.2 {
                let stp = dist.min(dt * 10.0f32.max(dist / 1.6));
                st[X] += dx / dist * stp;
                st[Z] += dz / dist * stp;
                st[HEADING] = dx.atan2(dz);
                moving = true;
            }
            st[Y] += (inp[GY] - st[Y]) * (dt * 6.0).min(1.0);
        } else {
            st[X] = inp[GX];
            st[Y] = inp[GY];
            st[Z] = inp[GZ];
        }
        st[WALK] += (if moving { 1.0 } else { 0.0 } - st[WALK]) * (dt * 8.0).min(1.0);
        st[STRIDE] += dt * 10.0 * st[WALK];
        let (walk, stride) = (st[WALK], st[STRIDE]);
        let ph = inp[PHASE] as f64;
        let stress = inp[STRESS];
        let bob = s64(now * 0.0016 + ph) * 0.18 * (1.0 - walk) + stride.sin().abs() * 0.22 * walk;
        let sway = if stress != 0.0 { s64(now * 0.016 + ph) * 0.12 * stress * (1.0 - walk) } else { 0.0 };

        // facing: where you're going, else the station / adversary rules
        let mut ry = if inp[WALKABLE] != 0.0 { inp[GYAW] } else { inp[BASE_ROT] };
        if walk > 0.3 {
            ry = st[HEADING];
        } else if inp[LEGACY_TURN] != 0.0 {
            ry += PI;
        } else if stress > 0.12 && hive_vis != 0.0 {
            ry = (hive_x - st[X]).atan2(hive_z - st[Z]);
        }
        let dy = ry - st[YAW];
        let mut w = dy.sin().atan2(dy.cos());
        if w < -PI + 1e-3 {
            w += 2.0 * PI; // a half turn always goes the positive way (deterministic across f32 / f64)
        }
        st[YAW] += w * (dt * 5.0).min(1.0);
        if inp[SHAKE_START] != 0.0 {
            st[SHAKE] = 0.7;
            inp[SHAKE_START] = 0.0;
        }
        if st[SHAKE] > 0.0 {
            st[SHAKE] -= dt;
            st[YAW] += s64(now * 0.045) * 0.09;
        }

        // arms: idle swing -> typing at the desk -> walking swing -> the event pose
        let idle = s64(now * 0.0018 + ph) * (0.07 + 0.3 * stress);
        let (mut rx, mut rz) = ([idle, -idle], [-0.35f32, 0.35]);
        if inp[OFF] == 0.0 && inp[HAS_DESK] != 0.0 && inp[NO_TYPE] == 0.0 && inp[AT_DESK] != 0.0 && walk < 0.3 {
            let j = s64(now * 0.02 + ph) * 0.05;
            rx = [-0.8 + j, -0.8 - j];
            rz = [-0.15, 0.15];
        }
        if walk > 0.05 {
            let a = stride.sin() * 0.5 * walk;
            rx = [-a, a];
            rz = [-0.25, 0.25];
        }
        let mut lean = 0.0;
        if inp[POSE_START] != 0.0 {
            st[POSE] = inp[POSE_KIND];
            st[POSE_T] = 1.8;
            inp[POSE_START] = 0.0;
        }
        if st[POSE_T] > 0.0 {
            st[POSE_T] -= dt;
            if st[POSE_T] <= 0.0 {
                st[POSE] = 0.0;
            } else {
                match st[POSE] as i32 {
                    1 => { rx[0] = -1.5; rz[0] = -0.1; }
                    2 => { rx[0] = -2.3; rz[0] = -0.55; }
                    3 => { rx[0] = -1.05; rz[0] = -0.1; lean = 0.12; }
                    4 => { rx = [-0.9, -0.9]; rz = [-0.2, 0.2]; }
                    5 => { rx[0] = -0.6; rz[0] = -1.1; }
                    _ => {}
                }
            }
        }
        let k = (dt * 7.0).min(1.0);
        st[RX0] += (rx[0] - st[RX0]) * k;
        st[RZ0] += (rz[0] - st[RZ0]) * k;
        st[RX1] += (rx[1] - st[RX1]) * k;
        st[RZ1] += (rz[1] - st[RZ1]) * k;

        // instance matrices
        let s = inp[SCALE];
        let pitch = inp[SLUMP] + if inp[TURNED] != 0.0 { 0.14 } else { 0.0 } + lean;
        let fig = compose([st[X], st[Y] + inp[GY_OFF] + bob, st[Z]], [pitch, st[YAW], sway], [s, s, s]);
        let tr = inp[TORSO_R];
        put(&mut e.torso, i, &mul(&fig, &compose([0.0; 3], [0.0; 3], [tr, 1.0, tr])));
        let hr = inp[HEAD_R];
        put(&mut e.head, i, &mul(&fig, &compose([0.0, 2.25, 0.0], [0.0; 3], [hr, hr, hr])));
        let legsw = stride.sin() * 0.55 * walk;
        put(&mut e.leg, 2 * i, &mul(&fig, &compose([0.42, -0.6, 0.0], [legsw, 0.0, 0.0], [1.0; 3])));
        put(&mut e.leg, 2 * i + 1, &mul(&fig, &compose([-0.42, -0.6, 0.0], [-legsw, 0.0, 0.0], [1.0; 3])));
        let aw = inp[ARM_OFF];
        let arm_r = mul(&fig, &compose([aw, 1.5, 0.0], [st[RX0], 0.0, st[RZ0]], [1.0; 3]));
        let arm_l = mul(&fig, &compose([-aw, 1.5, 0.0], [st[RX1], 0.0, st[RZ1]], [1.0; 3]));
        put(&mut e.arm, 2 * i, &arm_r);
        put(&mut e.arm, 2 * i + 1, &arm_l);
        put(&mut e.phone, i, &mul(&arm_r, &compose([0.1, -2.25, 0.32], [-0.4, 0.0, 0.0], [1.0; 3])));
        e.pos[i * 4] = st[X];
        e.pos[i * 4 + 1] = st[Y];
        e.pos[i * 4 + 2] = st[Z];
        e.pos[i * 4 + 3] = st[YAW];
    }
}

// =====================================================================================
// Ambient city life: pedestrians walking looping sidewalk circuits and air traffic in
// lanes over the streets. Decorative extras the viewer seeds per scenario; they are not
// sim units and the sims never see them. Every ambient buffer is a fixed-capacity
// static, so `amb_init` never grows linear memory and the units' zero-copy views stay
// valid. Pedestrians steer around units (read from `units_pos`) and each other with
// smooth weights (no hard thresholds), which keeps float32 and float64 runs together.
// Vehicles are a pure function of the clock, computed in float64.
// =====================================================================================

/// Capacity: pedestrians, vehicles, walkable slabs.
pub const MAX_PEDS: usize = 192;
pub const MAX_CARS: usize = 48;
pub const MAX_SLABS: usize = 16;
/// Floats per pedestrian in the input block.
pub const PIN: usize = 12;
const PST: usize = 8;
/// Floats per vehicle in the input block.
pub const CIN: usize = 8;
/// Lights per vehicle: two head, two tail, one underglow.
pub const LIGHTS: usize = 5;
/// Floats per slab: x0, x1, z0, z1, top.
pub const SLAB_N: usize = 5;

// ---- pedestrian input ----
const LX0: usize = 0; // the loop: a rounded rectangle
const LX1: usize = 1;
const LZ0: usize = 2;
const LZ1: usize = 3;
const DIR: usize = 4; // +1 runs (x0, z0) -> (x1, z0) -> (x1, z1) -> (x0, z1); -1 the reverse
const SPEED: usize = 5; // units / s
const START: usize = 6; // starting point as a fraction of the loop
const PSCALE: usize = 7;
const UMB: usize = 8; // 1 = carries an umbrella
const PPHASE: usize = 9;
const GROUND: usize = 10; // street level

// ---- pedestrian state ----
const PS: usize = 0; // arc length along the loop
const LAT: usize = 1; // lateral offset from the loop line
const PY: usize = 2; // feet height
const PYAW: usize = 3;
const GAIT: usize = 4;
const PINIT: usize = 5;
const PACE: usize = 6; // 1 = full speed; drops when someone is close ahead

// ---- vehicle input ----
const AXIS: usize = 0; // 0 = the lane runs along x, 1 = along z
const LANE: usize = 1; // the lane's other coordinate
const HEIGHT: usize = 2;
const CSPEED: usize = 3; // signed units / s
const CSTART: usize = 4;
const SPAN: usize = 5; // the lane runs from -SPAN to +SPAN, then wraps
const CPHASE: usize = 6;
const FADE: usize = 7; // lights fade out between |p| = FADE and SPAN

struct Ambient {
    peds: usize,
    cars: usize,
    slabs: usize,
    ped_in: [f32; MAX_PEDS * PIN],
    ped_st: [f32; MAX_PEDS * PST],
    car_in: [f32; MAX_CARS * CIN],
    slab: [f32; MAX_SLABS * SLAB_N],
    body: [f32; MAX_PEDS * 16],
    leg: [f32; MAX_PEDS * 32],
    umb: [f32; MAX_PEDS * 16],
    ppos: [f32; MAX_PEDS * 4],
    car: [f32; MAX_CARS * 16],
    light: [f32; MAX_CARS * LIGHTS * 3],
    fade: [f32; MAX_CARS * LIGHTS],
}

static mut AMB: Ambient = Ambient {
    peds: 0,
    cars: 0,
    slabs: 0,
    ped_in: [0.0; MAX_PEDS * PIN],
    ped_st: [0.0; MAX_PEDS * PST],
    car_in: [0.0; MAX_CARS * CIN],
    slab: [0.0; MAX_SLABS * SLAB_N],
    body: [0.0; MAX_PEDS * 16],
    leg: [0.0; MAX_PEDS * 32],
    umb: [0.0; MAX_PEDS * 16],
    ppos: [0.0; MAX_PEDS * 4],
    car: [0.0; MAX_CARS * 16],
    light: [0.0; MAX_CARS * LIGHTS * 3],
    fade: [0.0; MAX_CARS * LIGHTS],
};

fn amb() -> &'static mut Ambient {
    unsafe { &mut *core::ptr::addr_of_mut!(AMB) }
}

#[no_mangle]
pub extern "C" fn amb_max_peds() -> u32 {
    MAX_PEDS as u32
}
#[no_mangle]
pub extern "C" fn amb_max_cars() -> u32 {
    MAX_CARS as u32
}
#[no_mangle]
pub extern "C" fn amb_max_slabs() -> u32 {
    MAX_SLABS as u32
}
#[no_mangle]
pub extern "C" fn amb_ped_stride() -> u32 {
    PIN as u32
}
#[no_mangle]
pub extern "C" fn amb_car_stride() -> u32 {
    CIN as u32
}

/// Set the counts (clamped to capacity) and clear every ambient buffer. Returns the
/// pedestrian count accepted.
#[no_mangle]
pub extern "C" fn amb_init(peds: u32, cars: u32, slabs: u32) -> u32 {
    let a = amb();
    a.peds = (peds as usize).min(MAX_PEDS);
    a.cars = (cars as usize).min(MAX_CARS);
    a.slabs = (slabs as usize).min(MAX_SLABS);
    a.ped_in.fill(0.0);
    a.ped_st.fill(0.0);
    a.car_in.fill(0.0);
    a.slab.fill(0.0);
    a.body.fill(0.0);
    a.leg.fill(0.0);
    a.umb.fill(0.0);
    a.ppos.fill(0.0);
    a.car.fill(0.0);
    a.light.fill(0.0);
    a.fade.fill(0.0);
    a.peds as u32
}

#[no_mangle]
pub extern "C" fn amb_ped_in() -> *mut f32 {
    amb().ped_in.as_mut_ptr()
}
#[no_mangle]
pub extern "C" fn amb_car_in() -> *mut f32 {
    amb().car_in.as_mut_ptr()
}
#[no_mangle]
pub extern "C" fn amb_slab_in() -> *mut f32 {
    amb().slab.as_mut_ptr()
}
#[no_mangle]
pub extern "C" fn amb_body() -> *const f32 {
    amb().body.as_ptr()
}
#[no_mangle]
pub extern "C" fn amb_leg() -> *const f32 {
    amb().leg.as_ptr()
}
#[no_mangle]
pub extern "C" fn amb_umb() -> *const f32 {
    amb().umb.as_ptr()
}
#[no_mangle]
pub extern "C" fn amb_ppos() -> *const f32 {
    amb().ppos.as_ptr()
}
#[no_mangle]
pub extern "C" fn amb_car() -> *const f32 {
    amb().car.as_ptr()
}
#[no_mangle]
pub extern "C" fn amb_light() -> *const f32 {
    amb().light.as_ptr()
}
#[no_mangle]
pub extern "C" fn amb_fade() -> *const f32 {
    amb().fade.as_ptr()
}

fn clamp01(x: f32) -> f32 {
    x.clamp(0.0, 1.0)
}

/// Point and unit tangent at arc length `s` on a rectangle [x0, x1] x [z0, z1] with corner
/// radius `rc`, starting at (x0 + rc, z0) heading +x.
fn loop_at(x0: f32, x1: f32, z0: f32, z1: f32, rc: f32, s: f32) -> (f32, f32, f32, f32) {
    let lw = x1 - x0 - 2.0 * rc;
    let lh = z1 - z0 - 2.0 * rc;
    let la = rc * PI * 0.5;
    let arc = |cx: f32, cz: f32, a: f32| (cx + rc * a.cos(), cz + rc * a.sin(), -a.sin(), a.cos());
    let mut s = s;
    if s < lw {
        return (x0 + rc + s, z0, 1.0, 0.0);
    }
    s -= lw;
    if s < la {
        return arc(x1 - rc, z0 + rc, -PI * 0.5 + s / rc);
    }
    s -= la;
    if s < lh {
        return (x1, z0 + rc + s, 0.0, 1.0);
    }
    s -= lh;
    if s < la {
        return arc(x1 - rc, z1 - rc, s / rc);
    }
    s -= la;
    if s < lw {
        return (x1 - rc - s, z1, -1.0, 0.0);
    }
    s -= lw;
    if s < la {
        return arc(x0 + rc, z1 - rc, PI * 0.5 + s / rc);
    }
    s -= la;
    if s < lh {
        return (x0, z1 - rc - s, 0.0, -1.0);
    }
    s -= lh;
    arc(x0 + rc, z0 + rc, PI + s.min(la) / rc)
}

/// Feet height at (x, z): street level, ramped up onto any slab over its outer 0.4 units.
fn ground_at(slab: &[f32], n: usize, ground: f32, x: f32, z: f32) -> f32 {
    let mut lift = 0.0f32;
    let mut top = ground;
    for k in 0..n {
        let b = &slab[k * SLAB_N..k * SLAB_N + SLAB_N];
        let w = clamp01((x - b[0]) / 0.4) * clamp01((b[1] - x) / 0.4) * clamp01((z - b[2]) / 0.4) * clamp01((b[3] - z) / 0.4);
        if w > lift {
            lift = w;
            top = b[4];
        }
    }
    ground + (top - ground) * lift
}

/// One neighbour's influence: a lateral push away from it and a pace limit when it is close
/// ahead. Every factor is a ramp, so the response is continuous in the positions.
fn steer(dx: f32, dz: f32, tx: f32, tz: f32, nx: f32, nz: f32, reach: f32, tie: f32, push: &mut f32, pace: &mut f32) {
    let along = dx * tx + dz * tz;
    let side = dx * nx + dz * nz;
    let wa = clamp01((along + 0.6) / 0.6) * clamp01((3.4 - along) / 1.0);
    let room = (reach - side.abs()).max(0.0);
    let away = ((-side + tie * 0.15) / 0.3).clamp(-1.0, 1.0);
    *push += away * room * wa * 2.2; // strong enough to step clear (|side| > 0.9) and overtake
    let close = clamp01((1.6 - along) / 1.6) * clamp01(along / 0.3) * clamp01((0.9 - side.abs()) / 0.3);
    *pace = pace.min(1.0 - 0.65 * close);
}

/// Advance the ambient layer by `dt` seconds at wall-clock `now` (ms) and write its outputs.
#[no_mangle]
pub extern "C" fn amb_step(dt: f32, now: f64) {
    let a = amb();
    let e = eng();
    let dt = dt.clamp(0.0, 0.05);
    for i in 0..a.peds {
        let mut p = [0.0f32; PIN];
        p.copy_from_slice(&a.ped_in[i * PIN..(i + 1) * PIN]);
        let mut st = [0.0f32; PST];
        st.copy_from_slice(&a.ped_st[i * PST..(i + 1) * PST]);
        let (x0, x1, z0, z1) = (p[LX0], p[LX1], p[LZ0], p[LZ1]);
        let rc = 3.0f32.min((x1 - x0) * 0.45).min((z1 - z0) * 0.45).max(0.05);
        let per = 2.0 * (x1 - x0 + z1 - z0) - 8.0 * rc + 2.0 * PI * rc;
        let dir = if p[DIR] < 0.0 { -1.0f32 } else { 1.0 };
        if st[PINIT] == 0.0 {
            st[PS] = p[START].clamp(0.0, 1.0) * per;
            let (bx, bz, tx, tz) = loop_at(x0, x1, z0, z1, rc, st[PS]);
            st[PYAW] = (tx * dir).atan2(tz * dir);
            st[PY] = ground_at(&a.slab, a.slabs, p[GROUND], bx, bz);
            st[PACE] = 1.0;
            st[PINIT] = 1.0;
        }

        // where we are now, and who is around
        let (bx, bz, tx0, tz0) = loop_at(x0, x1, z0, z1, rc, st[PS]);
        let (tx, tz) = (tx0 * dir, tz0 * dir);
        let (nx, nz) = (tz, -tx);
        let (px, pz) = (bx + nx * st[LAT], bz + nz * st[LAT]);
        let tie = if i % 2 == 0 { 1.0 } else { -1.0 };
        let mut push = 0.0f32;
        let mut pace = 1.0f32;
        for u in 0..e.n {
            steer(e.pos[u * 4] - px, e.pos[u * 4 + 2] - pz, tx, tz, nx, nz, 1.6, tie, &mut push, &mut pace);
        }
        for j in 0..a.peds {
            if j != i {
                steer(a.ppos[j * 4] - px, a.ppos[j * 4 + 2] - pz, tx, tz, nx, nz, 1.4, tie, &mut push, &mut pace);
            }
        }
        let wander = s64(now * 0.00031 + p[PPHASE] as f64) * 0.45;
        let target = (wander + push).clamp(-2.6, 2.6);
        st[LAT] += (target - st[LAT]) * (dt * 2.6).min(1.0);
        st[PACE] += (pace - st[PACE]) * (dt * 4.0).min(1.0);
        let v = p[SPEED] * st[PACE];
        st[PS] = (st[PS] + dir * v * dt).rem_euclid(per);
        st[GAIT] += dt * v * 1.15;

        // the new pose
        let (bx, bz, tx0, tz0) = loop_at(x0, x1, z0, z1, rc, st[PS]);
        let (tx, tz) = (tx0 * dir, tz0 * dir);
        let (nx, nz) = (tz, -tx);
        let (x, z) = (bx + nx * st[LAT], bz + nz * st[LAT]);
        let gy = ground_at(&a.slab, a.slabs, p[GROUND], x, z);
        st[PY] += (gy - st[PY]) * (dt * 14.0).min(1.0);
        let dy = tx.atan2(tz) - st[PYAW];
        let mut w = dy.sin().atan2(dy.cos());
        if w < -PI + 1e-3 {
            w += 2.0 * PI;
        }
        st[PYAW] += w * (dt * 6.0).min(1.0);

        let s = p[PSCALE];
        let g = st[GAIT];
        let bob = g.sin().abs() * 0.1;
        let body = compose([x, st[PY] + bob, z], [0.05, st[PYAW], 0.0], [s, s, s]);
        put(&mut a.body, i, &body);
        let swing = g.sin() * 0.48;
        put(&mut a.leg, 2 * i, &mul(&body, &compose([0.3, 1.85, 0.0], [swing, 0.0, 0.0], [1.0; 3])));
        put(&mut a.leg, 2 * i + 1, &mul(&body, &compose([-0.3, 1.85, 0.0], [-swing, 0.0, 0.0], [1.0; 3])));
        if p[UMB] != 0.0 {
            let sway = (g * 0.5).sin() * 0.025;
            put(&mut a.umb, i, &mul(&body, &compose([0.42, 3.6, 0.2], [-0.12 + sway, 0.0, -0.06], [1.0; 3])));
        } else {
            put(&mut a.umb, i, &[0.0; 16]);
        }
        a.ppos[i * 4] = x;
        a.ppos[i * 4 + 1] = st[PY];
        a.ppos[i * 4 + 2] = z;
        a.ppos[i * 4 + 3] = st[PYAW];
        a.ped_st[i * PST..(i + 1) * PST].copy_from_slice(&st);
    }

    // vehicles: position is a function of the clock (float64), so every engine agrees
    const LOCAL: [[f32; 3]; LIGHTS] = [[1.0, 0.05, 3.45], [-1.0, 0.05, 3.45], [1.1, 0.15, -3.5], [-1.1, 0.15, -3.5], [0.0, -1.0, 0.0]];
    for c in 0..a.cars {
        let q = &a.car_in[c * CIN..(c + 1) * CIN];
        let span = q[SPAN] as f64;
        let raw = q[CSTART] as f64 + q[CSPEED] as f64 * now * 0.001;
        let pos = ((raw + span).rem_euclid(2.0 * span) - span) as f32;
        let bob = s64(now * 0.0011 + q[CPHASE] as f64) * 0.35;
        let fwd = q[CSPEED] >= 0.0;
        let (x, z, yaw) = if q[AXIS] == 0.0 {
            (pos, q[LANE], if fwd { PI * 0.5 } else { -PI * 0.5 })
        } else {
            (q[LANE], pos, if fwd { 0.0 } else { PI })
        };
        let roll = s64(now * 0.0007 + q[CPHASE] as f64 * 1.7) * 0.04;
        let m = compose([x, q[HEIGHT] + bob, z], [0.0, yaw, roll], [1.0; 3]);
        put(&mut a.car, c, &m);
        let f = clamp01((q[SPAN] - pos.abs()) / (q[SPAN] - q[FADE]).max(1.0));
        for (k, l) in LOCAL.iter().enumerate() {
            let o = (c * LIGHTS + k) * 3;
            a.light[o] = m[0] * l[0] + m[4] * l[1] + m[8] * l[2] + m[12];
            a.light[o + 1] = m[1] * l[0] + m[5] * l[1] + m[9] * l[2] + m[13];
            a.light[o + 2] = m[2] * l[0] + m[6] * l[1] + m[10] * l[2] + m[14];
            a.fade[c * LIGHTS + k] = f;
        }
    }
}
