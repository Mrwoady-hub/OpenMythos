# OpenMythos OS Architecture Design

**Status:** Approved design; implementation has not begun

**Date:** 2026-08-31

**Target release:** OpenMythos OS v0.1 installable alpha

**First implementation cycle:** Gate 01 — Stone Boot Proof

## 1. Executive summary

OpenMythos will become a real, installable Linux distribution for developers and creators. It will own the configuration, build, packaging, signing, testing, and update pipeline for its Linux kernel while keeping the patch delta from upstream deliberately small.

The distribution is named and structured around two product concepts:

- **Stone** is the signed, recoverable operating-system image: Fedora userspace, the `linux-openmythos` kernel, firmware, drivers, desktop, and deterministic system services.
- **Worlds** are portable units of work: source repositories, toolchains, services, permissions, knowledge, agent sessions, verification evidence, and provider handoffs.

The differentiator is not “Linux with an AI chat window.” A World is the first-class object. Codex and Claude remain official, native tools. The user always chooses which provider runs and when to switch. OpenMythos supplies the reproducible environment, explicit capabilities, human-readable handoff, durable continuity, and auditable system boundary around them.

The v0.1 baseline is:

- x86_64 UEFI only;
- Fedora 44 bootc userspace, pinned by OCI digest;
- `linux-openmythos` based initially on upstream Linux 6.18.48 LTS;
- stable bootc/OSTree deployments with Fedora shim and GRUB;
- Hyprland plus Quickshell, with an independent TTY recovery path;
- a Rust control plane and rootless Podman Worlds;
- native Codex and Claude lanes with mandatory manual selection;
- the existing Python Personal Hermes as an unprivileged continuity service;
- QCOW2 and installer ISO artifacts built from the same signed payload;
- acceptance in QEMU and on one deeply supported reference computer.

This is a master architecture specification, not a single big-bang implementation plan. Each release gate receives its own detailed plan and must produce evidence before the next gate starts.

## 2. Approved decisions

| Area | Decision |
|---|---|
| Product | Installable developer/creator Linux distribution, not a customization script |
| Foundation | “Stone + Worlds”: Fedora bootc system image plus portable project Worlds |
| Base release | Fedora 44 stable; Fedora 45 remains canary-only until its actual GA and a separate migration decision |
| Kernel ownership | Build, configure, sign, package, test, and update an upstream LTS kernel; maintain a minimal patch queue |
| Kernel line | Linux 6.18.y; initial pinned source is 6.18.48 |
| Boot path | UEFI Secure Boot, Fedora shim, GRUB, locally enrolled OpenMythos MOK certificate |
| Update model | Signed bootc deployments with manual previous-deployment rollback |
| Desktop | Hyprland plus Quickshell, with `greetd`/`tuigreet` and independent virtual-console recovery |
| Primary UX | World Deck overlay; normal Linux applications remain primary |
| World runtime | Rootless Podman, user namespaces, SELinux, seccomp, explicit mounts and capabilities |
| Control plane | Rust user daemon and minimal privileged Rust system service over versioned D-Bus APIs |
| Existing Python | Personal Hermes remains unprivileged and outside the security boundary |
| Providers | Official Codex and Claude CLIs installed from verified vendor sources after user approval |
| Routing | Never automatic; the user explicitly selects Codex or Claude on every start and switch |
| Switching | Exclusive writer lane plus transparent, editable Markdown and JSON handoff capsule |
| Reference target | Current CyberPowerPC desktop; QEMU validation always precedes physical writes |
| Delivery sequence | Six risk-first release gates, beginning with Stone Boot Proof |

## 3. Context and problem statement

The current repository is a Python/PyTorch alpha containing a recurrent-depth transformer implementation and Personal Hermes. Hermes already has useful product DNA: a durable identity, local memory, a journal, continuity, background tasks, permission-scoped file learning, and a localhost interface.

The repository does not yet contain an operating-system substrate. It has no kernel build, RPM packaging, initramfs policy, bootloader integration, root filesystem image, installer, signed update pipeline, hardware enablement suite, desktop session, or recovery environment. Existing Python permission checks are application-level checks; they are not a host security boundary.

Omarchy demonstrates a compelling keyboard-first Linux workflow, cohesive desktop configuration, guarded updates, migrations, and acceptance testing. OpenMythos will learn from those workflow patterns without pretending that a customization layer is an owned operating system. Package-backed state, explicit migrations, semantic themes, VM installer tests, and a clear separation between package-owned files and user overrides are worth carrying forward. Mutable package drift, ambiguous substrate ownership, unsafe theme/plugin execution, and rollback claims that ignore boot and user state are not.

## 4. Product objective and v0.1 success criteria

OpenMythos OS v0.1 succeeds only when all of the following are true:

1. A reproducible build produces a QCOW2 image and an installer ISO from the same versioned bootc payload.
2. The installed system boots an OpenMythos-built 6.18.y kernel, not Fedora’s stock kernel.
3. Secure Boot stays enabled through installation and normal operation.
4. The system launches a usable Hyprland and Quickshell desktop while preserving an independent TTY recovery path.
5. A Git repository can be materialized as a locked, rootless World with visible filesystem, network, device, secret, and resource capabilities.
6. The user can start Codex or Claude, explicitly switch to the other, review the handoff, and switch back without losing workspace state.
7. Hermes provides user-owned continuity without gaining host authority or receiving provider secrets or raw transcripts by default.
8. A signed system update can be staged and booted, and the operator can deliberately return to the previous deployment.
9. The complete QEMU acceptance suite passes.
10. A separately approved physical install and hardware acceptance run passes on the reference computer without writing to the Windows/BitLocker NVMe.

“Alpha” means one hardware target supported deeply. It does not mean an unbounded list of machines that probably boot.

## 5. Product invariants

The following are non-negotiable contracts:

1. **Linux works without an agent.** Applications, terminal, files, networking, settings, and recovery remain usable when no provider is installed, authenticated, available, or selected.
2. **Provider selection is explicit.** OpenMythos never silently routes, falls back, or switches between Codex and Claude.
3. **No LLM is privileged.** Models may propose a typed transaction; deterministic code validates, previews, authorizes, executes, and records it.
4. **World autonomy stops at the World boundary.** Writing inside a declared workspace may be autonomous. New host, device, secret, network, or external-service authority requires a visible capability grant.
5. **Evidence is user-readable.** Important actions produce exact diffs, commands, exit results, artifact hashes, capability grants, and rollback references.
6. **Updates do not mutate the running deployment in place.** System changes are built, signed, staged, and activated as deployments.
7. **A failed component does not trigger a different agent.** Provider and adapter failures pause and wait for the user.
8. **Credentials never enter handoffs, Hermes memory, or Chronicle receipts.** Provider authentication stores remain separate.
9. **One provider owns the write lease for a World at a time.** This prevents competing agents from editing the same worktree concurrently.
10. **Physical disk writes are a separate approval boundary.** Agreement to this architecture is not permission to repartition or erase any drive.

## 6. System architecture

```text
Human
  |
  +-- Hyprland + Quickshell World Deck
  +-- mythosctl CLI
           |
           v
    mythos-sessiond (unprivileged Rust user service)
      |       |          |             |
      |       |          |             +-- Hermes (unprivileged Python)
      |       |          +-- Provider adapters
      |       |                +-- official Codex CLI lane
      |       |                +-- official Claude CLI lane
      |       +-- Chronicle + World state (SQLite)
      +-- Rootless Podman Worlds
           |
           +-- typed privileged proposal over D-Bus
                         |
                         v
                  mythosd (minimal root service)
                         |
                         +-- sandboxed artifact-fetch unit
                         +-- bootc deployment operations
                         +-- reboot / rollback operations
                         +-- fixed system-policy operations

Stone below every layer:
UEFI -> Fedora shim -> GRUB -> linux-openmythos -> OpenMythos deployment
```

The architecture has four deliberate layers.

### 6.1 Human experience

The desktop, terminal, World Deck, approval surfaces, notifications, and recovery tools are presentation clients. They do not contain independent policy logic. Quickshell and `mythosctl` call the same versioned interfaces and must show the same state.

### 6.2 Project World

A World owns the reproducible project environment, worktree, declared capabilities, provider session identifiers, handoff history, and verification evidence. It is portable without including credentials or raw provider transcripts.

### 6.3 Deterministic control plane

The control plane materializes Worlds, maintains exclusive writer leases, launches provider processes, compiles policy, records state transitions, and converts approved host intents into typed requests. It contains no model inference and cannot accept arbitrary root shell strings.

### 6.4 Stone

Stone is the bootable, signed Linux system image. It contains the kernel, system services, desktop cohort, base firmware, and recovery tooling. It changes only through the release pipeline and bootc deployment mechanism.

## 7. Trust boundaries and threat model

### 7.1 Trusted computing base

The host trusted computing base consists of:

- platform firmware and Secure Boot databases;
- Fedora shim and GRUB;
- the signed `linux-openmythos` kernel and initramfs generation policy;
- the OpenMythos system image and systemd units;
- `mythosd` and its versioned protocol;
- release signing and verification policy.

`mythos-sessiond`, Quickshell, Hermes, provider CLIs, project dependencies, and code inside Worlds are not trusted to protect the host. They receive only the user-level and explicitly brokered access they need.

### 7.2 Threats addressed in v0.1

- accidental or agent-driven access outside a project workspace;
- undeclared network, device, secret, and host-service access;
- concurrent providers corrupting a shared worktree;
- arbitrary strings reaching a privileged shell;
- unsigned kernel modules loading under Secure Boot;
- provider updates changing behavior mid-session;
- unreviewed provider handoffs leaking credentials or hidden transcripts;
- installer selection of the wrong physical disk;
- release artifacts whose source and build evidence cannot be traced.

### 7.3 Honest limitations

Rootless containers share the host kernel. A World is a strong boundary against accidents and routine agent overreach; it is not a claim of protection against a hostile kernel exploit. A future microVM mode is the appropriate boundary for adversarial code.

The v0.1 GRUB path does not cryptographically bind an external initramfs or root filesystem into a signed UKI. Secure Boot authenticates the shim/GRUB/kernel path; deployment authenticity is enforced separately by signed release and update policy. A UKI/systemd-boot design is deferred until bootc’s relevant backend is production-ready for this product. Compromised firmware, physical attacks, release-key compromise, and compromised vendor accounts also remain outside the v0.1 threat claim.

## 8. Stone platform

### 8.1 Fedora bootc base

The system payload derives from the Fedora 44 bootc base and pins it by immutable OCI digest. Fedora 44 is the stable baseline recorded on 2026-08-31. A future Fedora major-version move is a reviewed image change with the complete QEMU and physical acceptance suite; it is never an automatic rebase.

The v0.1 image uses bootc’s stable OSTree-backed deployment model. Experimental composefs sealed images and bootc’s composefs-dependent systemd-boot path are not release dependencies.

The image follows bootc’s kernel layout contract: the kernel is present under `/usr/lib/modules/$kver/vmlinuz`, and the container image does not own mutable `/boot` content. bootc installs deployment boot artifacts from image content.

### 8.2 Build artifacts

The unified `image-builder` tooling produces the release artifacts while keeping one payload digest authoritative:

- **QCOW2:** built directly from the signed OpenMythos payload for QEMU development and CI acceptance;
- **`bootc-generic-iso`:** built from a separate OpenMythos installer image that embeds or targets that exact signed payload digest for Anaconda-based physical installation.

The deprecated standalone `bootc-image-builder` workflow and historical `bootc-installer` image type are not adopted. Each release publishes the payload digest, QCOW2 and ISO checksums, package manifest, SBOM, provenance, kernel source/config digest, signatures, and acceptance evidence.

### 8.3 Package ownership

OpenMythos-owned RPMs include:

- `kernel-openmythos` and its split core/module packages;
- pinned Hyprland ecosystem packages;
- an OpenMythos-owned Quickshell 0.3.1 RPM, its exact Qt/Wayland cohort, configuration, and desktop assets;
- Rust control-plane packages;
- installer, policy, and recovery packages;
- firmware or driver packages that are legally redistributable and required by the supported hardware contract.

System files are package-owned. User customization lives under documented user configuration paths. Generated state lives under XDG data/state directories. Updating the image must not overwrite user overrides silently.

## 9. `linux-openmythos` kernel contract

### 9.1 Baseline and ownership

The first Gate 01 build pins upstream Linux 6.18.48, whose release tarball and PGP signature are recorded in the source lock. The release line is 6.18.y, projected upstream as longterm through December 2028 at design time. `linux-openmythos` is the product label; Fedora-compatible source and binary RPM names use the `kernel-openmythos` prefix.

OpenMythos owns:

- source verification;
- a version-controlled kernel configuration;
- reproducible build inputs and toolchain lock;
- RPM packaging and bootc image integration;
- PE kernel signing and module signing;
- the minimal downstream patch series and justification for every patch;
- QEMU boot and hardware acceptance;
- coordinated kernel, firmware, NVIDIA, and rollback releases.

Gate 01 reproducibility has a precise meaning: two clean builders using the locked source, patch series, config, and toolchain must produce identical SRPM content, identical installed file digests for the binary kernel RPMs, and an identical OCI payload manifest/layer digest. RPM container metadata that cannot be normalized is compared separately and documented. QCOW2 wrapper UUIDs and timestamps may differ, but the embedded bootc payload digest and normalized partition contents must match. Any unexplained difference fails the gate.

OpenMythos does not promise a permanent independent kernel fork. Fixes should go upstream whenever feasible. Downstream patches are small, reviewable, rebased per 6.18.y update, and removable.

### 9.2 Required configuration families

The final config is generated and audited as code. At minimum it enables:

- AMD graphics: `CONFIG_DRM`, `CONFIG_DRM_KMS_HELPER`, `CONFIG_DRM_AMDGPU`;
- firmware loading: `CONFIG_FW_LOADER`;
- Wi-Fi: `CONFIG_CFG80211`, `CONFIG_MAC80211`, `CONFIG_RTW89`, `CONFIG_RTW89_PCI`, `CONFIG_RTW89_8851BE`;
- Ethernet: `CONFIG_R8169`;
- storage: `CONFIG_NVME_CORE`, `CONFIG_BLK_DEV_NVME`;
- module integrity: `CONFIG_MODULE_SIG`, `CONFIG_MODULE_SIG_ALL`, `CONFIG_MODULE_SIG_FORCE`, `CONFIG_SECONDARY_TRUSTED_KEYRING`, and an explicit `CONFIG_SYSTEM_TRUSTED_KEYS` module certificate;
- platform trust: `CONFIG_INTEGRITY_PLATFORM_KEYRING` and UEFI key loading needed by the tested shim/MOK path;
- lockdown: `CONFIG_SECURITY_LOCKDOWN_LSM`, with early lockdown enabled for the release config;
- EFI handoff: `CONFIG_EFI_STUB`.

Config audits fail when a required symbol is disabled, silently changed by dependency resolution, or built in the wrong form for the initramfs and early-boot contract.

### 9.3 Firmware and NVIDIA cohort

The full reference-hardware firmware lock enters at Gate 03, not Gate 01. It includes the Granite Ridge AMDGPU firmware families and `rtw89/rtw8851b_fw.bin`. The reference Ethernet device is PCI ID `10ec:8168`, revision 15, using `r8169`; Gate 03 records the exact firmware filename requested by that MAC revision from kernel evidence instead of assuming an `rtl8168g-*` file. Every included blob has its upstream source, license, filename, and digest in the manifest.

The reference RTX 5070 is Blackwell-class hardware and therefore uses NVIDIA’s open kernel modules. The initial reference cohort is NVIDIA 595.84: open kernel module source, userspace driver, and GSP firmware must match exactly. The modules are built against the exact OpenMythos kernel using the same kernel build toolchain and version, signed during the release build, and delivered in the same bootc image. Release evidence records and compares the kernel and NVIDIA module compiler strings. End-user DKMS/akmods rebuilds are not supported in v0.1.

A distinct OpenMythos module-signing public certificate is built into the kernel trust set. Its private key is not shipped. Beginning with Gate 03, kernel and NVIDIA updates advance together; a new hardware-supported deployment is rejected by CI if its matching signed NVIDIA modules are absent. Gate 01 contains only the firmware and drivers needed by its QEMU virtual hardware.

## 10. Secure Boot and installer bootstrap

### 10.1 Installed-system chain

The installed boot path is:

```text
UEFI Secure Boot
  -> Microsoft-trusted Fedora shim
  -> Fedora-signed GRUB managed through bootupd
  -> selected bootc/OSTree deployment entry
  -> OpenMythos-signed PE kernel, with a deployment-specific external initramfs loaded by that boot entry
  -> kernel-enforced signed modules
  -> selected OpenMythos deployment root
```

OpenMythos does not claim Microsoft-trusted zero-touch boot for its custom kernel. That would require a separate shim signing and release program. Secure Boot does not authenticate the complete v0.1 root filesystem; signed OCI update policy controls which deployment may be staged.

### 10.2 First-install enrollment

The installer environment must boot before the OpenMythos MOK is trusted. Therefore the installer bootstrap environment uses Fedora’s signed shim, GRUB, and installer kernel. The OpenMythos installer flow must provision the OpenMythos certificate for shim/MOK enrollment, display its fingerprint, collect a one-time enrollment secret without logging it, and make the next-boot MokManager flow available. This is an OpenMythos requirement to prove in Gate 02, not an assumed bootc or image-builder feature.

Successful Secure Boot of the installed OpenMythos kernel depends on completing MokManager enrollment. Gate 02 uses a fresh disposable OVMF variable store and scripted QEMU keyboard input to exercise enrollment, captures screenshots plus enrolled-key evidence, and separately boots with the test certificate pre-seeded to test the signed-kernel rejection/acceptance matrix. If enrollment is abandoned or fails physically, the Fedora-signed installer/rescue ISO remains bootable and can repair or retry the Linux installation.

### 10.3 Artifact signing

Separate release identities cover different artifact classes:

- GPG-signed RPM repository metadata and packages;
- cosign-signed OCI payloads pinned by digest;
- PE-signed kernels;
- kernel-signed external modules;
- signed release manifests plus SHA-256 checksums for QCOW2 and ISO artifacts.

Private keys never enter the system image. Alpha release keys are distinct from developer personal keys. Key fingerprints and rotation rules are documented with each release.

## 11. Updates, rollback, and recovery

### 11.1 Update flow

1. A transient, sandboxed `mythos-fetch@.service` retrieves a specifically selected image digest and its signatures into root-owned staging/container storage. It has allowlisted registry access but no bootc, bootloader, module, reboot, or arbitrary system-write authority.
2. The control plane verifies signature policy, architecture, required manifest fields, disk space, current deployment health, and kernel/NVIDIA cohort completeness.
3. World Deck and `mythosctl` show the exact current and proposed digests, version notes, required reboot, migrations, and known rollback boundary.
4. The user approves the typed update transaction.
5. `mythosd` imports or selects the verified local image through bootc’s supported `containers-storage` transport, stages the deployment, and records the result.
6. Reboot is separately visible. The existing deployment remains available.

`mythosd` has no general internet or provider access. Network retrieval is isolated from privileged application of a staged artifact.

### 11.2 Rollback promise

v0.1 promises operator-invoked previous-deployment rollback, not automatic failed-boot recovery. If the new deployment boots, the user can invoke rollback from the desktop or TTY. If it does not boot, the documented recovery path is the firmware boot picker plus the installer/rescue ISO.

Rollback reorders deployments; it is not a full-state rewind. `/var` and home data persist. `/etc` returns to the previous deployment’s `/etc` state because `bootc rollback` reorders existing deployments rather than creating a newly merged deployment. World data has independent backups and receipts.

### 11.3 Bootloader policy

bootupd is used for the supported shim/GRUB path. Bootloader updates are explicit release transactions with their own compatibility test and recovery evidence; they are not silently coupled to every userspace update.

Factory reset, automatic boot counting/blessing, and experimental bootc reset operations are deferred.

## 12. Reference computer and install safety

The v0.1 physical acceptance target is:

| Component | Reference hardware |
|---|---|
| System | CyberPowerPC GamingPC, ASRock B850M-C, AMI UEFI |
| CPU | AMD Ryzen 7 9800X3D, 8 cores / 16 threads |
| Memory | 29 GiB usable |
| Discrete GPU | NVIDIA GB205 GeForce RTX 5070, 12 GiB |
| Integrated GPU | AMD Granite Ridge iGPU |
| Wi-Fi | Realtek RTL8851BE using `rtw89_8851be` |
| Ethernet | Realtek RTL8168 family using `r8169` |
| Storage | Samsung 990 PRO 2 TB Windows/BitLocker NVMe plus T-FORCE 2 TB Linux NVMe |
| Displays | 1920×1080@60, 1360×768@60, and 1920×1080@143.88 primary |
| Boot state | UEFI Secure Boot enabled; Windows Boot Manager remains present |

### 12.1 Disk rules

- The installer must enforce one reviewed Linux target and abort before writing if its model, serial, path, capacity, partition map, or expected role changes. Windows/BitLocker disks are out of scope for writes, and no physical install is supported until this exclusion is demonstrated in the acceptance flow.
- v0.1 does not promise non-destructive “install alongside Ubuntu” on the same Linux disk.
- Reusing the current Linux NVMe means replacing its Ubuntu layout and requires a later, explicit destructive-operation approval after an exact partition plan is shown.
- The installer displays target model, serial, capacity, existing partitions, ESP effects, and resulting layout. Confirmation must name the target; a generic “continue” is insufficient.
- QEMU install, update, rollback, and recovery gates complete before any physical installation attempt.

The architecture approval in this document authorizes no physical disk change.

## 13. Desktop and World Deck

### 13.1 Desktop cohort

Hyprland, `xdg-desktop-portal-hyprland`, `xdg-desktop-portal-gtk`, hyprlock, hypridle, hyprpaper, UWSM, required Hyprland libraries, OpenMythos-packaged Quickshell 0.3.1, its exact Qt/Wayland dependencies, Xwayland, and portal dependencies are treated as a tested bill of materials. They advance together instead of drifting package by package. Quickshell 0.3.1 is built from its verified upstream tag rather than silently mixing Fedora 44’s older snapshot with newer configuration.

`greetd` plus `tuigreet` is the v0.1 login path. A graphical Quickshell greeter is deferred. At least one virtual console remains functional when the compositor, shell, or NVIDIA stack fails.

The NVIDIA Wayland path enables and verifies DRM KMS. For the 595.84 open-module cohort, `NVreg_UseKernelSuspendNotifiers=1` is the required first-choice memory-preservation path. If Gate 03 evidence shows that the reference system requires NVIDIA’s `/proc/driver/nvidia/suspend` path instead, the locked fallback enables `NVreg_PreserveVideoMemoryAllocations=1`, the NVIDIA suspend/hibernate/resume units, and a non-tmpfs backing store sized to total VRAM plus at least five percent. The selected mode and module parameters are release evidence, not an undocumented machine-local tweak.

Multi-GPU selection uses stable DRM device identities discovered on the reference system, never assumed card numbers. `AQ_DRM_DEVICES` ordering must survive reboot, hotplug, and suspend. When firmware and connectors expose outputs on both GPUs, Gate 03 deliberately runs one output from each GPU. The portal suite tests PipeWire screen sharing through the DMA-BUF path and the documented shared-memory fallback, plus the GTK file chooser. The wider acceptance suite covers mixed refresh, Xwayland, Electron, suspend/resume, and both GPU drivers.

### 13.2 World Deck interaction model

Normal Linux applications remain the center of the desktop. AI chat does not permanently occupy screen space.

- `Super+Space` opens the World Deck overlay.
- The top bar always shows the active World and explicitly selected provider, or `none`.
- The deck lists Worlds, current worktree state, tests, capability grants, provider choices, pending approvals, and recent Chronicle evidence.
- Starting a task requires a visible Codex or Claude selection.
- Switching providers opens the handoff preview before the write lease moves.
- Every deck action has a stable `mythosctl` equivalent.
- Native Codex and Claude terminal interfaces remain directly available.

The visual language may evolve, but this interaction contract may not be replaced by a chat-first desktop without a new architecture decision.

## 14. World contract

### 14.1 Files and state

A portable World uses:

- `.mythos/world.toml` — human-authored intent;
- `.mythos/world.lock.json` — machine-generated exact OCI, repository, provider, and tool digests;
- `$XDG_DATA_HOME/openmythos/worlds/<world-id>/` — materialized worktree and persistent volumes;
- `$XDG_STATE_HOME/openmythos/worlds/<world-id>/` — session identifiers, logs, evidence, and local state not committed to the project.

v0.1 materializes Git repositories. Non-Git arbitrary-folder import is deferred so rollback and diff evidence remain well-defined.

The manifest includes a schema version, stable World identifier, repository and revision intent, OCI toolchain reference, commands, services, declared mounts, network policy, devices, resource budgets, named secret references, and allowed host-intent classes. The lock file resolves every mutable reference to an immutable digest or commit.

### 14.2 Runtime boundary

Worlds run through rootless Podman with user namespaces, SELinux labeling, seccomp, capability dropping, read-only base filesystems, and explicit writable volumes. The host home directory, rootful container socket, rootless Podman control socket, SSH agent, D-Bus, Wayland socket, devices, and unrelated projects are absent unless the manifest grants a specific need.

Provider API egress and project/tool egress are distinct policy concepts. A provider may receive the minimum egress required for its authenticated service after the user selects it. Project processes receive `off`, allowlisted, or declared outbound policy. Policy compilation must fail closed when it cannot enforce the requested distinction; it may not silently grant general host networking.

Exactly one provider lane holds the World write lease. Multiple Worlds may exist, but Codex and Claude cannot write the same World concurrently in v0.1.

### 14.3 Capability model

Capabilities are typed objects, not shell text. Classes include:

- filesystem read or write to a canonical path;
- named network egress policy;
- named secret injection;
- device access;
- GUI/Wayland access;
- external-service credential or push authority;
- bounded host transaction.

Each grant records scope, actor, World, reason, creation time, expiration, and revocation state. Path authorization resolves symlinks and mount boundaries before launch and again when applying a host transaction. A manifest change invalidates the lock and blocks launch until reviewed and relocked.

## 15. Rust control plane

### 15.1 `mythos-sessiond`

This unprivileged user service:

- validates and locks World manifests;
- materializes and resumes Worlds;
- owns the per-World writer lease;
- launches official provider processes with provider-specific homes;
- compiles capabilities into runtime policy;
- coordinates handoffs;
- manages Hermes integration;
- stores state and Chronicle events;
- serves a versioned user D-Bus API to Quickshell and `mythosctl`.

It cannot mutate boot deployments, repartition disks, load modules, or grant itself new host authority.

### 15.2 `mythosd`

This minimal root service exposes only versioned, typed system D-Bus methods. Initial method classes are limited to:

- inspect deployment and boot health;
- apply a locally staged, already verified bootc digest;
- select previous-deployment rollback;
- request a reboot tied to an approved transaction;
- run fixed recovery or validation operations owned by an installed OpenMythos package.

There is no `run(command)` method, arbitrary environment map, caller-selected executable, or unrestricted caller-selected path. Authorization uses polkit plus transaction-bound approval data. Systemd hardening removes unneeded capabilities, network families, writable paths, devices, and namespaces.

### 15.3 Protocol discipline

All D-Bus request and response types have explicit schema versions. Unknown fields, unsupported versions, expired approvals, changed artifact digests, and mismatched World identity fail closed. Requests are idempotent through transaction IDs. Retrying a completed transaction returns its recorded result rather than applying it twice.

Policy and protocol crates prohibit unsafe Rust in OpenMythos-authored code. Third-party dependencies remain subject to lockfile, license, vulnerability, and provenance review.

## 16. Chronicle and state model

SQLite in WAL mode is the authoritative state store for Worlds, capabilities, provider lanes, transactions, and an append-only `chronicle_events` table. Chronicle rows contain:

- monotonically ordered event identifier and schema version;
- timestamp, actor, World, and provider lane;
- requested action and normalized parameters;
- approval identity and scope when applicable;
- result and exit classification;
- evidence and artifact digests;
- previous-event hash and current-event hash.

The hash link detects deletion or alteration; it does not claim non-repudiation against a user who controls the machine. Human-readable JSONL and Markdown views are derived exports from the authoritative database, avoiding an inconsistent dual-write design.

Database migrations are transactional and versioned. Before a migration, the service creates a verified backup. If integrity checks fail, services open the database read-only, keep Worlds stopped, and offer evidence export and restoration instead of inventing or discarding state.

## 17. Codex and Claude provider contract

### 17.1 Verified first-use installation

The ISO ships OpenMythos provider adapters, not repackaged proprietary tooling or unofficial wrappers. Provider Setup offers separate Codex and Claude installations. Each requires user approval and retrieves a selected official version from the vendor’s documented source.

Where a vendor publishes signatures or signed manifests, OpenMythos verifies them. Every artifact also receives a locally recorded SHA-256 digest and source URL. Provider versions live in content-addressed user storage under `$XDG_DATA_HOME/openmythos/providers/<provider>/<version>/`; an active session keeps its exact version until it exits.

Stable vendor channels are the default. Latest channels are opt-in. Background self-update is disabled inside managed provider lanes so an executable cannot change mid-session. An update is downloaded separately, adapter-tested, shown to the user, and selected only for a new launch.

### 17.2 Native operation

OpenMythos does not replace either provider’s model, permission system, terminal UI, or session format.

- The Codex adapter uses documented non-interactive JSON event output and documented resume identifiers where needed.
- The Claude adapter uses documented print/`stream-json` operation and documented resume identifiers where needed.
- A native interactive terminal session is always available for either provider.
- Provider-specific model and effort controls remain provider controls.

Adapters accept only tested event schema versions. An unknown breaking event pauses the managed view and offers the native terminal path; it never guesses at a tool call or approval.

### 17.3 Authentication and secrets

Authentication occurs through each provider’s native browser/device or documented key flow. Provider credential homes are separate. Secret values are never written into World manifests, lock files, Chronicle, handoffs, Hermes memory, logs, or crash reports.

OpenMythos brokers access by reference and launch scope. Selecting Codex gives Claude no credential access, and vice versa. Removing a provider removes its executable and managed session metadata only after a preview; vendor credentials follow that vendor’s explicit logout/removal procedure.

## 18. Manual switching and handoff capsules

### 18.1 Switching flow

1. The user chooses `Switch to Codex` or `Switch to Claude`.
2. The current lane stops accepting new work and checkpoints its native session identifier.
3. The control plane captures deterministic workspace evidence.
4. The outgoing provider may contribute a clearly labeled narrative summary.
5. OpenMythos renders Markdown and JSON handoff views.
6. The user reviews, edits, or cancels.
7. On approval, the edited capsule is versioned, the source lane releases the write lease, and the selected target lane starts or resumes with the visible capsule.

There is no background classifier, quality score, quota detector, failure handler, or model preference that can select a target automatically.

### 18.2 Capsule schema

The versioned capsule contains:

- World, source provider, target provider, time, and capsule revision;
- objective and user-approved decisions;
- branch, base commit, head commit, worktree status, changed file list, and diff digest;
- commands/tests run, exit status, and evidence digest;
- current capability grants relevant to the work;
- blockers, unresolved questions, and next recommended action;
- labeled provider-authored summary, when present;
- redaction report.

It excludes raw transcripts, hidden reasoning, credentials, secret values, unrelated memories, and files outside the World. User edits produce a new capsule revision and Chronicle event rather than altering history invisibly.

### 18.3 Failure behavior

- If the source provider crashes, OpenMythos records the exit and builds a deterministic evidence-only capsule; the user decides whether to resume or switch.
- If capsule generation or storage fails, the switch does not transfer the write lease.
- If the target provider fails to start, the World remains intact and the user may retry, return to the source lane, or choose the other provider explicitly.
- A provider failure never starts the other provider by itself.

## 19. Personal Hermes role

The existing Python Personal Hermes remains part of the product as a resident, user-owned continuity layer. Its v0.1 responsibilities are:

- durable identity and preferences;
- user-approved memories and project notes;
- journal and continuity summaries;
- local task and briefing support;
- optional local-model generation when configured by the user.

Hermes runs as the desktop user, not root. It cannot approve capabilities, apply bootc updates, choose a provider, read provider credentials, or receive raw provider transcripts by default. It may read a handoff or Chronicle export only through an explicit user action or World capability.

The current Python `PermissionPolicy` remains useful for application behavior but is not treated as a security boundary. Rust control-plane policy and the kernel-enforced World runtime become the authority. Existing `~/.open_mythos/mind` data remains user data and is migrated only through a separately tested, backed-up migration.

The recurrent-depth model research code remains a Python package. It is neither PID 1 nor part of the boot or privilege path.

## 20. Error handling contract

| Failure | Required behavior |
|---|---|
| Source, package, or image signature invalid | Reject artifact; keep current deployment; record evidence |
| Required reproducible artifact comparison differs | Fail the release gate; publish no release artifact |
| Kernel lacks required config or matching NVIDIA modules | Fail image validation before boot testing |
| Update download interrupted | Discard or resume staging; never alter current deployment |
| bootc staging fails | Keep current boot default; emit failed transaction receipt |
| New deployment does not boot | Use previous deployment or rescue ISO; no false automatic-rollback claim |
| World manifest and lock differ | Refuse launch and show a semantic lock diff |
| Runtime cannot enforce a capability | Refuse the capability and World start; never widen silently |
| Agent exits unexpectedly | Preserve worktree and native session metadata; wait for user selection |
| Provider event schema is unknown | Pause managed adapter; offer native TUI; require adapter update |
| Handoff cannot be saved | Keep source write lease; do not start target writer |
| Chronicle integrity fails | Stop mutating state, open read-only recovery, verify backup/export |
| Privileged transaction is retried | Resolve by transaction ID; do not apply twice |
| Provider update fails | Keep the last verified provider version active |
| Installer target identity changes | Abort before writing and require a new disk review |

Errors shown in World Deck include the failed invariant, exact component, stable error code, evidence location, safe next actions, and whether any state changed.

## 21. Verification strategy

### 21.1 Unit and property tests

- manifest and lock schema validation;
- path canonicalization, symlink escape, mount boundary, and expiration logic;
- capability compilation and default-deny behavior;
- D-Bus version and authorization handling;
- transaction idempotency;
- Chronicle hash-chain and migration integrity;
- handoff redaction and deterministic evidence;
- disk identity and exclusion rules;
- provider event parser fixtures, including unknown and malformed events.

### 21.2 Integration tests

- rootless World creation, restart, deletion preview, and export;
- write-lease transfer between captured Codex and Claude adapter fixtures;
- secret non-persistence checks across logs, database, capsule, and crash output;
- staged provider update with old-version retention;
- typed privileged request authorization and rejection;
- Hermes access denial without explicit capability;
- desktop and World Deck startup with neither provider installed, configured, nor authenticated.

### 21.3 QEMU acceptance

CI uses UEFI and Secure Boot-capable OVMF and validates:

- QCOW2 boot of the exact `linux-openmythos` version;
- installer ISO installation to an empty virtual NVMe;
- virtual MOK/key enrollment path;
- deployment N to N+1 update and deliberate rollback;
- boot with corrupted or invalidly signed candidate artifacts rejected;
- fresh boot, login, ordinary applications, terminal, networking, portals, and World Deck with no provider installed or authenticated;
- GTK portal file selection and PipeWire screen sharing through both the DMA-BUF path and forced shared-memory fallback;
- desktop login, World materialization, provider-adapter fixture switch, TTY recovery, and rescue ISO;
- a disabled compositor and a killed Quickshell process each leave an independently reachable virtual console and documented recovery path;
- image validation rejects a fixture whose NVIDIA userspace, kernel modules, or GSP cohort does not match before that deployment reaches physical boot testing.

### 21.4 Physical acceptance

After separate install approval, the reference machine validates:

- Secure Boot and lockdown state;
- signed `nvidia`, `nvidia_modeset`, `nvidia_uvm`, and `nvidia_drm` modules;
- NVIDIA GSP firmware reporting and a Vulkan/OpenGL workload;
- AMDGPU binding and firmware health;
- stable-identity `AQ_DRM_DEVICES` ordering across reboot, hotplug, and suspend, including one active output per GPU when the available connectors permit it;
- all three displays, mixed refresh, 143.88 Hz primary, hotplug, DMA-BUF and shared-memory screen sharing, GTK file selection, Xwayland, and Electron;
- Wi-Fi scan/associate/transfer/resume and Ethernet link/DHCP/transfer;
- both NVMe devices, root boot, and suspend/resume stability;
- audio, Bluetooth, headset, mouse, and independent TTY;
- safe desktop failure drills with the compositor disabled and Quickshell terminated, proving TTY login and recovery without touching the Windows disk;
- a controlled, one-boot NVIDIA failure drill that temporarily inhibits the NVIDIA modules without installing mismatched binaries, proving a local virtual-console login and recovery path before the normal boot entry is restored;
- Codex start, switch to Claude through reviewed capsule, and switch back;
- system update and manual previous-deployment rollback.

The Windows NVMe is inspected read-only during these tests.

### 21.5 Release evidence

A gate is complete only when CI outputs machine-readable test results, artifact digests, logs, SBOM, provenance, and signature verification. A human-written statement without attached evidence does not satisfy a gate.

## 22. Release gates and decomposition

### Gate 01 — Stone Boot Proof

Build a Fedora 44 bootc payload with `kernel-openmythos` 6.18.48, only the locked firmware and drivers needed by its QEMU virtual hardware, and reproducible inputs. Produce a UEFI QCOW2 image. It must boot in QEMU and report the expected OS identity, image digest, kernel NEVR, source digest, and config digest.

This is the only scope of the first implementation plan. It performs no physical disk writes and does not yet include NVIDIA, the full reference-hardware firmware cohort, the final desktop, providers, or installer.

### Gate 02 — Trust, update, and recovery

Add artifact signing, virtual Secure Boot, installer bootstrap/MOK validation, staged bootc N-to-N+1 update, manual rollback, and rescue artifact. CI must demonstrate the full transition and rejection of invalid signatures.

### Gate 03 — Reference hardware and desktop

Add the complete reference-hardware firmware lock, the exactly matched and signed NVIDIA userspace/module/GSP cohort, Hyprland, Quickshell, portals, login, TTY recovery, and hardware tests. Exit requires a non-destructive live boot and hardware smoke pass before an installed-system test is requested.

### Gate 04 — World control plane

Add Rust protocol, user/system daemons, `mythosctl`, rootless World materialization, capabilities, writer lease, SQLite Chronicle, and failure recovery. Exit requires a sample repository to run, survive restart, and fail closed on escape attempts.

### Gate 05 — Native provider lanes

Add verified provider setup, native Codex and Claude adapters, explicit selection, provider-specific state, handoff capsules, and unprivileged Hermes continuity. Exit requires successful switches in both directions with secrets absent from evidence.

### Gate 06 — Installable alpha

Finish World Deck, branding, guarded installer flow, first boot, release documentation, full QEMU suite, and separately approved physical install. Publish only after every earlier gate remains green against the final payload digest.

Each gate receives its own implementation plan. A later gate may not paper over a failed earlier gate.

## 23. Target repository boundaries

The project remains a monorepo for v0.1 so cross-layer versioning is explicit, but ownership is separated:

```text
open_mythos/                 existing Python model and Hermes package
os/
  images/                    bootc payload definitions
  kernel/                    source lock, config, patches, packaging
  packages/                  OpenMythos RPMs, systemd units, and repository metadata
  installer/                 installer image, disk policy, rescue assets
  desktop/                   Hyprland cohort, Quickshell, themes, session policy
crates/
  mythos-protocol/           versioned shared types
  mythos-sessiond/           user control plane
  mythosd/                   privileged typed system service
  mythosctl/                 CLI client
  mythos-world/              manifest, lock, runtime, capabilities
  mythos-chronicle/          state and evidence
  mythos-providers/          Codex and Claude adapters
tests/
  qemu/                      boot, install, update, rollback
  hardware/                  reference-machine acceptance
  fixtures/providers/        sanitized provider event fixtures
docs/
  architecture/              durable architecture and ADRs
  operations/                install, recovery, signing, release runbooks
```

Gate 01 creates only the boundaries it needs. Existing Python files are not moved or refactored as collateral work.

## 24. Explicitly deferred work

The following are outside v0.1:

- automatic failed-boot rollback or boot counting/blessing;
- systemd-boot, UKI-only boot, and bootc composefs sealed images;
- factory reset;
- same-disk coexistence with the current Ubuntu installation;
- generalized hardware support, ARM64, laptops, and battery policy;
- multiple simultaneous writers in one World;
- microVM World isolation;
- team synchronization and multi-user administration;
- plugin/theme marketplace or execution of untrusted installer scripts;
- provider auto-routing, scoring, or fallback;
- unattended host mutations;
- dynamic kernel patching or a permanent Linux fork;
- a claim that the local recurrent-depth model replaces Codex or Claude;
- graphical Quickshell greeter;
- arbitrary non-Git folder import.

Deferral is a release boundary, not a hidden promise. Adding any item requires a new design decision and acceptance criteria.

## 25. References

### Primary Linux and hardware sources

- [kernel.org current releases](https://www.kernel.org/)
- [kernel.org longterm release schedule](https://www.kernel.org/releases.html)
- [Linux 6.18 module-signing documentation](https://www.kernel.org/doc/html/v6.18/admin-guide/module-signing.html)
- [AMD APU hardware table for Linux 6.18](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/Documentation/gpu/amdgpu/apu-asic-info-table.csv?h=v6.18)
- [Linux 6.18 `rtw89` Kconfig](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/drivers/net/wireless/realtek/rtw89/Kconfig?h=v6.18)
- [Linux 6.18 RTL8851B driver source](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/drivers/net/wireless/realtek/rtw89/rtw8851b.c?h=v6.18)
- [Linux 6.18 `r8169` driver source](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/drivers/net/ethernet/realtek/r8169_main.c?h=v6.18)
- [linux-firmware `WHENCE` manifest](https://git.kernel.org/pub/scm/linux/kernel/git/firmware/linux-firmware.git/tree/WHENCE)
- [NVIDIA 595.84 supported chips](https://download.nvidia.com/XFree86/Linux-x86_64/595.84/README/supportedchips.html)
- [NVIDIA 595.84 GSP firmware](https://download.nvidia.com/XFree86/Linux-x86_64/595.84/README/gsp.html)
- [NVIDIA 595.84 power management](https://download.nvidia.com/XFree86/Linux-x86_64/595.84/README/powermanagement.html)
- [NVIDIA open kernel-module source and compatibility contract](https://github.com/NVIDIA/open-gpu-kernel-modules/blob/main/README.md)

### Authoritative project documentation

- [bootc overview](https://bootc.dev/bootc/)
- [bootc image layout](https://bootc.dev/bootc/bootc-images.html)
- [bootc installation](https://bootc.dev/bootc/bootc-install.html)
- [booting local bootc builds](https://bootc.dev/bootc/booting-local-builds.html)
- [bootc upgrades and rollback](https://bootc.dev/bootc/upgrades.html)
- [bootc bootloaders](https://bootc.dev/bootc/bootloaders.html)
- [bootc composefs status](https://bootc.dev/bootc/experimental-composefs.html)
- [image-builder usage](https://osbuild.org/docs/developer-guide/projects/image-builder/usage/)
- [image-builder bootc installer ISOs](https://osbuild.org/docs/developer-guide/projects/image-builder/advanced/bootc/isos/)
- [bootc-image-builder deprecation notice](https://osbuild.org/docs/bootc/deprecation-notice/)
- [shim behavior](https://github.com/rhboot/shim/blob/main/README.md)
- [bootupd](https://github.com/coreos/bootupd)
- [Hyprland NVIDIA guidance](https://wiki.hypr.land/Nvidia/)
- [Hyprland multi-GPU guidance](https://wiki.hypr.land/Configuring/Advanced-and-Cool/Multi-GPU/)
- [xdg-desktop-portal-hyprland](https://wiki.hypr.land/Hypr-Ecosystem/xdg-desktop-portal-hyprland/)
- [Quickshell 0.3.1 release](https://github.com/quickshell-mirror/quickshell/releases/tag/v0.3.1)
- [Quickshell installation and setup](https://quickshell.org/docs/v0.3.0/guide/install-setup/)
- [Codex CLI reference](https://developers.openai.com/codex/cli/reference)
- [Codex authentication](https://developers.openai.com/codex/auth)
- [Claude Code CLI reference](https://code.claude.com/docs/en/cli-usage)
- [Claude Code installation, signatures, and channels](https://code.claude.com/docs/en/setup)

### Workflow inspiration

- [Omarchy](https://github.com/omacom/omarchy)
- [Omarchy ISO](https://github.com/omacom-io/omarchy-iso)
- [Omarchy packages](https://github.com/omacom-io/omarchy-pkgs)
- [Omarchy update workflow](https://github.com/omacom/omarchy/blob/quattro/manual/30-updates.md)
