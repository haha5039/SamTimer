# SamTimer

One-tap Android root for Samsung Galaxy devices, built around the
**CVE-2026-98260** timer exploit (posix-cpu-timers UAF) and a
**KernelSU** late-load module with Samsung KDP/RKP/DEFEX compatibility.

> Based on the **CVE-2026-98260-aurora** repo — its timer LPE port
> (real-cred zero-write / fake-cred ksud late-load chains) is what
> `app/src/main/cpp/timer.c` evolved from.

> [!WARNING]
> For devices you own or are explicitly authorized to test. The exploit is a
> probabilistic kernel UAF — a failed run can leave the system unstable until
> the next reboot. Rebooting always restores the phone to a clean, unrooted
> state.

## Overview

| | |
| --- | --- |
| Exploit | CVE-2026-98260 (timer.c payload, built by Gradle) |
| Root module | KernelSU 3.2.5 (`ksud-A566EXXSCCZG6-kdp`, android15-6.6 no-patch-text) |
| Execution context | Shizuku shell (uid 2000) |
| su authorization | KernelSU manager (`me.weishu.kernelsu`), domain `u:r:ksu:s0` |
| Root lifetime | Per-boot (ephemeral — cleared on reboot) |

Tested on **SM-A566S** (a56x, Exynos 1580), firmware
`A566SKSUADZJ1`, kernel `6.6.127-android15-8`, One UI 9.

## SM-A566S port

This fork ports SamTimer's UMH/pipe endgame to the SM-A566S kernel layout.
The target offsets were derived from the matching stock boot image's kallsyms,
BTF, and ARM64 disassembly, then validated with the read-only `umhread` path
before the KernelSU late-load run.

The SM-A566S port and live validation were completed with **GPT-5.6 Sol**.

## Features

- Material 3 Compose UI (English / Korean, follows the system locale)
- Live root badge — detects the loaded KernelSU module every few seconds
- Confirmation dialog before every run; **re-root** button stays available
  when already rooted
- **Auto-root after reboot** — boot receiver → WorkManager chain that waits
  3 minutes for the system to settle, waits for Shizuku, then runs the chain
  headless with progress notifications; a failed run disables the option
  itself (boot-loop protection); a manual run pressed inside the
  3-minute post-boot window is held back with a countdown instead of
  being thrown at a still-busy system
- **Safe boot (block modules)** — one-run panic recovery for a bad module:
  the payload reads the toggle straight out of the app's prefs XML at stage
  time (DirtyFrag pattern — no relay file).  Enabled: every KernelSU module
  dir gets a `disable` flag and service.d / post-fs-data.d are parked; turn the switch off
  and the following run restores everything (the auto-root chain re-establishes
  root every boot regardless, so the fix reaches you even if the phone
  boot-looped)
- The exploit payload is compiled automatically by Gradle — `assembleDebug`
  always ships a fresh binary

## Requirements

1. **Shizuku** running (wireless debugging). For auto-root: enable Shizuku's
   boot auto-start and grant its permission to SamTimer once.
2. **KernelSU manager** (`me.weishu.kernelsu`) installed — su is only
   granted to apps the manager authorizes.

## Build

```sh
./gradlew assembleDebug
# APK: app/build/outputs/apk/debug/app-debug.apk
```

- `app/src/main/cpp/timer.c` is compiled into
  `app/src/main/jniLibs/arm64-v8a/libtimer.so` by the `buildPayload` task
  (NDK is auto-detected: `ANDROID_NDK_HOME` → `local.properties` → SDK →
  `~/android-ndk-r27c`)
- `libksud.so` is the prebuilt A56 KernelSU 3.2.5 KDP late-load daemon
- `./gradlew clean` removes all outputs **including** the generated payload
  (the prebuilt `libksud.so` is kept)

## Usage

1. Start Shizuku, open SamTimer
2. Tap **Root now** → confirm → wait 1–7 minutes
3. Grant `su` to your apps in the KernelSU manager
4. Optionally enable **Auto-root after reboot**

## Chain

1. `timer.c` turns the timer UAF into a controlled write, then repoints a pipe
   buffer to build a bounded kernel read/write primitive.
2. The payload reads the real `system_unbound_wq`/`pool_workqueue` layout,
   waits for a stable empty worklist, and queues a genuine kernel
   usermodehelper.
3. The helper stages `.ksud-stage`, binds `ksud` over `/system/bin/logcat`
   inside a private mount namespace, and runs
   `late-load --allow-shell --package-name me.weishu.kernelsu`.
4. KernelSU 3.2.5 loads its android15-6.6 no-patch-text module and restores
   SELinux enforcing.
5. Success is verified through the KSU driver's `reboot()` backdoor ioctl.
6. Failed-plant zombies are made reap-safe first — their posix-cpu-timer
   queue leftmost pointers are zeroed through the write primitive, so
   `posix_cpu_timers_exit` finds empty queues and the reap cannot touch the
   stale node — then reaped on the spot. Nothing is left parked and there is
   never a zombie for init to reap later; a park is only a last-resort
   fallback when a repair plant cannot land

## Credits / upstream

- **CVE-2026-98260-aurora** — this app is built on the `aurora` repo's timer
  LPE port: the `timer.c` payload (real-cred zero-write and fake-cred /
  ksud late-load chains) started there and lives in this project as
  `app/src/main/cpp/timer.c`
- [BuSung-dev/Root-My-Galaxy](https://github.com/BuSung-dev/Root-My-Galaxy) —
  the verified Samsung KSU late-load flow this app mirrors (`su_daemon.c`
  shape, `.ksud-stage` staging, manager pairing)
- [BuSung-dev/Root-My-Galaxy-Payloads](https://github.com/BuSung-dev/Root-My-Galaxy-Payloads) —
  per-target `ksud`/`kernelsu.ko` pairs and the Samsung KDP/RKP/DEFEX port
  methodology (exact-release vermagic, no-patch-text for Exynos)
- [rushiranpise/Root-My-Galaxy-Payloads](https://github.com/rushiranpise/Root-My-Galaxy-Payloads) —
  Samsung delta patches and the A56 KernelSU 3.2.5 KDP/no-patch-text daemon
  used by this port
- [tiann/KernelSU](https://github.com/tiann/KernelSU) — the root module
  lineage
- [DirtyFrag](https://github.com/mitschud/DirtyFrag) (CVE-2026-43284, DFRoot
  lineage) — the autorun / failed-run-interlock pattern
- [Shizuku](https://github.com/RikkaApps/Shizuku) — shell-uid execution
  without a PC

## Disclaimer

Use at your own risk. The authors take no responsibility for data loss,
bricked devices, or anything else that happens to hardware you point this at.
