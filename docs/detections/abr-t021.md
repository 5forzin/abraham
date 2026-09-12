# ABR-T021 — Resident km payload, covert channel, kernel-side self-protection

Offensive: `payloads/abraham-km/payload.rs` (freestanding Rust, zero PE
imports, timer-DPC heartbeat + command loop) + the mapper's channel
provisioning (`implant/src/mapper.rs`, `driver chan ...`). Mapped
resident through the iqvw64e chain, invisible to driver enumeration
when stacked with `modhide`.

## Why classic anchors are gone

The payload has: no service, no file, no registry key, no device
object, no IRP traffic, no image entry in the loader list. Its only
kernel footprint is pool memory (image + two small allocations) and a
timer/DPC pair whose routine address points into unbacked pool.

## Signals

1. **The loader chain remains the primary anchor** — every EID 7045/6,
   hash and blocklist signal from ABR-T018/T019 applies before the
   payload ever exists. Blocklist ON kills the whole stack.
2. **Unbacked executable pool**: pool scanners that cross-reference
   `PoolTag`/page ownership against loaded modules find code pages
   attributed to no image. Timer/DPC/worker callbacks registered from
   addresses outside any module are the strongest residual —
   enumerate `KiStartTimerDispatch`-owned timers or monitor
   `KeSetTimerEx`-armed objects whose DPC routine lies in pool.
3. **Heartbeat periodicity**: the channel ticks every 2000ms exactly.
   An implant polling the same kernel pool address through a
   vulnerable-driver device at a fixed cadence is a cross-view
   behavioral signature (device IOCTL burst pattern every tick).
4. **Self-healing protection anomalies** (see ABR-T020): a Protection
   byte that reverts to a protected value within seconds of being
   cleared indicates an in-kernel re-apply loop — clear-then-watch is
   the active check.

## Hardening

- Vulnerable Driver Blocklist ON (the chain never starts).
- WDAC enforce mode; driver-block hash sets kept current.
- Periodic consistency sweeps: module list vs executable pool vs
  callback registration lists — any code in pool with no module is a
  tripwire.
