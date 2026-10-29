# uring-gate

Sandbox de agentes que **no tiene que prohibir `io_uring`**: en vez de bloquear
`io_uring_setup` entero (lo que rompe runtimes rápidos), aplica a las
operaciones del anillo la misma política que a las syscalls.

*An agent sandbox that **does not have to ban `io_uring`**: instead of blocking
`io_uring_setup` outright (which breaks fast runtimes), it applies the same
policy to ring operations as to syscalls.*

> **ES** primero · **EN** below

---

## ES

### El problema

`seccomp` filtra por número de syscall, pero **no ve** las operaciones que se
ejecutan dentro de un anillo `io_uring`: un `IORING_OP_OPENAT` no pasa por
`openat(2)`. Por eso la práctica común en sandboxes es **prohibir `io_uring`
entero**, lo que mata a los runtimes y servidores que lo usan, y deja un agujero
si alguien lo vuelve a habilitar. Se demostraron rootkits que usan `io_uring`
para evadir monitoreo de syscalls.

### Qué hace uring-gate

Tres capas, de menor a mayor privilegio:

| Capa | Mecanismo | Privilegio | Qué cubre |
|------|-----------|-----------|-----------|
| 1. Allowlist de opcodes | `IORING_SETUP_R_DISABLED` → `IORING_REGISTER_RESTRICTIONS` → `ENABLE_RINGS` | ninguno | el kernel rechaza con `-EACCES` cualquier opcode fuera de la lista, en el **propio anillo** de la app |
| 2. seccomp + Landlock | filtro seccomp-BPF + ruleset Landlock | ninguno | Landlock aplica a `security_file_open`, que el kernel llama **también** para `IORING_OP_OPENAT` |
| 3. Backstop BPF-LSM | programa eBPF en `file_open` / `uring_cmd`, filtrado por cgroup | root + `bpf` en la lista LSM | aplica política a los ops de `io_uring` de un proceso que **no controlás** (anillo sin restringir), porque los workers `io-wq` heredan el cgroup del emisor |

La capa 1 es la defensa que una app adopta en su propio anillo. La capa 3 es el
backstop para binarios que no podés modificar.

### Lo que está probado en esta box (2026-10-28, kernel 6.12.94+)

`landlock ABI 6`, `lsm = capability,landlock,selinux,bpf`,
`io_uring_disabled = 0`.

| Afirmación | Estado |
|------------|--------|
| Allowlist de opcodes rechaza `OPENAT`/`SOCKET`/`CONNECT` con `-EACCES` | **medido** (unit + integ) |
| Bypass suite: 3/3 técnicas evaden seccomp solo; 0/3 evaden uring-gate | **medido** |
| Rendimiento del anillo restringido vs nativo | **medido** ≈ 1.00× |
| Landlock cubre `io_uring OPENAT` (mismo deny que syscall) | **medido** → `covers=true` |
| Backstop BPF-LSM niega `io_uring OPENAT` del cgroup sandbox, no al control | **medido con sudo** |

#### Criterio de aceptación (a): 0 bypasses

```sh
cargo run --release --bin uring-gate -- bypass
```

```text
technique  mode       direct     io_uring
openat     baseline   blocked    ESCAPED
openat     gated      blocked    blocked
socket     baseline   blocked    ESCAPED
socket     gated      blocked    blocked
connect    baseline   blocked    ESCAPED
connect    gated      blocked    blocked

MEASURE baseline_escapes=3/3 gated_escapes=0/3
```

Cada técnica hace la operación prohibida como SQE. Bajo una política
**seccomp-solo** las 3 se escapan (prueba de que el agujero existe); bajo
uring-gate (anillo con allowlist) las 3 dan `-EACCES`. Objetivo: `0` → cumplido.

#### Criterio de aceptación (b): ≥ 85% de throughput

```sh
cargo run --release --bin uring-gate -- bench --iters 1000000
```

```text
iters         1000000
native        3749771 ops/s
gated         3759322 ops/s
MEASURE throughput_ratio=1.0025 (target >= 0.85)
```

El anillo restringido conserva ≈ **100%** del throughput del anillo nativo
(el check de allowlist es una comparación de bitmask por submission), contra
**0%** si se prohibiera `io_uring`. Objetivo: `≥ 85%` → cumplido. Es un
micro-benchmark de lecturas de archivo (`IORING_OP_READ`) en esta box; mide el
costo que agrega la capa 1. Existe un servidor HTTP io_uring de referencia
(`github.com/federiconbaez/uring-http`); acá se usa un benchmark de archivo
autocontenido porque aísla mejor el overhead de las restricciones.

#### Landlock e io_uring

```sh
cargo run --release --bin uring-gate -- probe
```

```text
landlock_abi  6
landlock_covers_uring_openat true  (syscall_denied=true, uring_denied=true)
```

En este kernel **Landlock ya cubre `io_uring OPENAT`**: el deny de un directorio
vale tanto por syscall como por SQE. Por eso la política de filesystem no
necesita trabajo específico de io_uring; los huecos que quedan son ops que no
son de archivo (`connect`/`socket`/`uring_cmd`) y la allowlist de opcodes.

#### Backstop BPF-LSM (root)

```sh
sudo ./target/release/uring-gate-lsm ci-check
```

```text
active LSMs:  capability,landlock,selinux,bpf
bpf in LSM:  true
sandboxed     direct=denied uring=denied
control       direct=allowed uring=allowed
MEASURE lsm_file_open_denied=2 ...
```

El programa eBPF engancha `security_file_open` y `security_uring_cmd` y filtra
por **cgroup id** (no por comm/pid: un op de io_uring puede correr en un worker
`io-wq`, que no comparte el comm del emisor pero sí su cgroup). Un proceso en el
cgroup sandbox recibe `-EPERM` tanto en `openat(2)` como en `IORING_OP_OPENAT`;
un proceso de control fuera del cgroup no se ve afectado.

### Límites honestos

- **La política demo del backstop es "denegar todo `file_open` del cgroup"**,
  suficiente para probar que el hook cubre `io_uring` igual que la syscall. Una
  política de producción consultaría un mapa allowlist por inode/path (trabajo
  CO-RE adicional); está fuera de alcance acá.
- **Los runners hosteados de GitHub no activan BPF-LSM**: tienen
  `CONFIG_BPF_LSM=y` pero `bpf` no está en `lsm=` del arranque
  ([runner-images #14783](https://github.com/actions/runner-images/issues/14783)).
  Por eso la medición real de enforcement del backstop está hecha en esta box
  (comando de arriba). En CI, el job `ebpf` compila y linkea el objeto (con BTF)
  y el job `lsm` **lo mide en vez de saltearlo**: en el runner (LSMs activos
  `lockdown,capability,landlock,yama,apparmor,ima,evm`) el **attach tiene éxito**
  porque el kernel trae `CONFIG_BPF_LSM=y`, pero como `bpf` no es un LSM activo
  el hook **nunca se invoca**. El job arma el cgroup y verifica empíricamente
  que el hook queda **inerte: 0 denegaciones** y la apertura del sandbox pasa.
  Esto muestra que un attach exitoso **no** prueba enforcement. Donde `bpf` sí
  esté en la lista LSM, el mismo job corre la medición completa y exige la
  denegación.
- `IORING_REGISTER_RESTRICTIONS` es una allowlist **por opcode**, no por
  path/destino: no puede decir "este `OPENAT` sí y este no". Eso lo cubren
  Landlock (filesystem) y el backstop LSM.
- La capa 1 protege el anillo que la propia app crea restringido; no un anillo
  que otro proceso abra sin restricciones (eso es la capa 3).
- Fuera de alcance: parchear el kernel, SQPOLL compartido entre tenants.

### Build y test

```sh
# Core sin privilegios (estable):
cargo test --workspace
cargo run --release --bin uring-gate -- probe

# Objeto eBPF (nightly + bpf-linker):
cd uring-gate-ebpf && cargo build --release

# Backstop (root + feature lsm):
export URING_GATE_EBPF_OBJ="$PWD/uring-gate-ebpf/target/bpfel-unknown-none/release/uring-gate-ebpf"
cargo build --release --features lsm --bin uring-gate-lsm
sudo ./target/release/uring-gate-lsm ci-check
```

### Licencia

Apache-2.0.

---

## EN

### The problem

`seccomp` filters by syscall number but **cannot see** operations run inside an
`io_uring` ring: an `IORING_OP_OPENAT` never goes through `openat(2)`. So the
common sandbox practice is to **ban `io_uring` entirely**, which kills the
runtimes and servers that rely on it and leaves a hole if anyone re-enables it.
`io_uring`-based rootkits that evade syscall monitoring have been demonstrated.

### What uring-gate does

Three layers, lowest to highest privilege:

| Layer | Mechanism | Privilege | Covers |
|-------|-----------|-----------|--------|
| 1. Opcode allowlist | `IORING_SETUP_R_DISABLED` → `IORING_REGISTER_RESTRICTIONS` → `ENABLE_RINGS` | none | kernel rejects any opcode outside the list with `-EACCES`, on the app's **own** ring |
| 2. seccomp + Landlock | seccomp-BPF filter + Landlock ruleset | none | Landlock hooks `security_file_open`, which the kernel calls **also** for `IORING_OP_OPENAT` |
| 3. BPF-LSM backstop | eBPF program on `file_open` / `uring_cmd`, filtered by cgroup | root + `bpf` in the LSM list | applies policy to io_uring ops of a process you **do not control** (unrestricted ring), because `io-wq` workers inherit the submitter's cgroup |

### Proven on this box (2026-10-28, kernel 6.12.94+)

`landlock ABI 6`, `lsm = capability,landlock,selinux,bpf`,
`io_uring_disabled = 0`.

- **(a) 0 bypasses** — `uring-gate bypass`: 3/3 techniques escape a
  seccomp-only policy; **0/3** escape uring-gate.
- **(b) ≥ 85% throughput** — `uring-gate bench --iters 1000000`:
  **ratio ≈ 1.00×** of native (vs 0% if io_uring were banned).
- **Landlock covers io_uring OPENAT** — `uring-gate probe`: `covers=true`.
- **BPF-LSM backstop** — `sudo uring-gate-lsm ci-check`: sandboxed cgroup gets
  both direct and io_uring `OPENAT` denied; control process unaffected.

### Honest limits

- The backstop's demo policy is "deny all `file_open` for the cgroup": enough to
  prove the hook covers io_uring like the syscall. A production policy would
  consult a per-inode/path allowlist map (extra CO-RE work), out of scope here.
- **GitHub hosted runners do not activate BPF-LSM** (`CONFIG_BPF_LSM=y` but `bpf`
  not in the boot `lsm=` list,
  [runner-images #14783](https://github.com/actions/runner-images/issues/14783)).
  The real backstop enforcement is therefore measured on this box (command
  above). In CI the `ebpf` job builds and links the object (with BTF) and the
  `lsm` job **measures instead of skipping**: on the runner (active LSMs
  `lockdown,capability,landlock,yama,apparmor,ima,evm`) the **attach succeeds**
  because the kernel has `CONFIG_BPF_LSM=y`, but since `bpf` is not an active
  LSM the hook is **never invoked**. The job arms the cgroup and empirically
  checks the hook is **inert: 0 denials** and the sandboxed open goes through.
  So a successful attach does **not** prove enforcement. Where `bpf` is in the
  LSM list the same job runs the full measurement and requires the denial.
- `IORING_REGISTER_RESTRICTIONS` is a **per-opcode** allowlist, not per
  path/target; Landlock and the LSM backstop cover the path/target policy.
- Layer 1 protects the ring the app itself creates restricted, not an
  unrestricted ring opened by another process (that is layer 3).
- Out of scope: patching the kernel, SQPOLL shared across tenants.

### References read while building this

- ARMO, *io_uring Is Back, This Time as a Rootkit* (the "Curing" PoC runs
  entirely on io_uring to evade syscall monitoring; argues KRSI / eBPF-on-LSM
  hooks are the robust answer — which is uring-gate's layer 3) —
  https://www.armosec.io/blog/io_uring-rootkit-bypasses-linux-security/
- `io_uring_register(2)` — `IORING_REGISTER_RESTRICTIONS` is an allowlist and
  returns `EACCES` for a disallowed opcode; needs `IORING_SETUP_R_DISABLED`
  then `IORING_REGISTER_ENABLE_RINGS` —
  https://man7.org/linux/man-pages/man2/io_uring_register.2.html
- GitHub runner-images #14783 (BPF-LSM compiled in but not in the boot `lsm=`
  list on hosted runners) —
  https://github.com/actions/runner-images/issues/14783

### License

Apache-2.0.
