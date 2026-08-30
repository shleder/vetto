# Kubernetes Manifests and Deployment Architecture for Vetto

This directory contains production Kubernetes manifests for running AI agent sandboxes at scale:

- [`deployment.yaml`](deployment.yaml): Autonomous agent worker pods with embedded Vetto daemon REST API.
- [`daemonset.yaml`](daemonset.yaml): Node-level Vetto daemon providing shared sandboxing to pods on the node.
- [`vetto-sidecar.yaml`](vetto-sidecar.yaml): Multi-container pod sidecar pattern (Agent + Vetto execution engine over a shared Unix domain socket).

---

## Security Context & Confinement

All manifests adhere to the principle of least privilege:
- `privileged: false` (strictly unprivileged).
- `allowPrivilegeEscalation: false`.
- `runAsNonRoot: true` (UID 1000).
- `capabilities.drop: ["ALL"]`.

---

## Technical Constraints & Landlock Compatibility in Kubernetes

### The Landlock Seccomp Conflict
Landlock LSM filesystem confinement relies on the Linux kernel syscalls:
- `landlock_create_ruleset` (syscall 444 on x86_64)
- `landlock_add_rule` (syscall 445 on x86_64)
- `landlock_restrict_self` (syscall 446 on x86_64)

In default Kubernetes container runtimes (containerd/CRI-O) using older default seccomp profiles, syscalls unknown to the runtime profile return `EPERM` or `ENOSYS`.

### Resolution Options
1. **Container-level `seccompProfile: { type: "Unconfined" }` (Recommended for Pod Sandboxes)**:
   Disables the outer container seccomp filter so the container process can invoke Landlock. Because Vetto internally enforces Landlock LSM + Seccomp BPF filters, the executing process remains fully secured and confined.
2. **Cluster Custom Seccomp Profile**:
   Deploy a Custom Seccomp Profile via `security-profiles-operator` that explicitly allows `landlock_*` syscalls while denying dangerous primitives.
3. **Host-Level Installation**:
   Install Vetto directly on the Kubernetes worker nodes (outside container runtimes) and invoke via node-level SSH or volume-mounted daemon socket.
