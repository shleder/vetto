# Docker-in-Vetto & Hybrid Container Sandboxing

Combining Docker containers with Vetto provides **two distinct layers of kernel isolation (Defense-in-Depth)** for autonomous AI coding agents:

1. **Outer Boundary (Container Engine)**: Linux cgroups, unprivileged user namespaces, network namespace, rootfs isolation.
2. **Inner Boundary (Vetto Kernel Sandbox)**: Landlock LSM filesystem restriction, Seccomp-BPF network/syscall filtering, secret file masking, and audit observation.

Even if an agent exploits a vulnerability in a Python/Node dependency to escape the immediate project tree, Landlock and Vetto prevent access to mounted credentials, environment secrets, and lateral egress networks.

---

## 1. Building the Docker Hybrid Image

Build using [`Dockerfile.vetto`](../../Dockerfile.vetto):

```bash
docker build -f Dockerfile.vetto -t vetto-agent:latest .
```

---

## 2. Running Agents Inside the Hybrid Container

Run the container mounting your workspace:

```bash
docker run --rm -it \
  --security-opt seccomp=unconfined \
  -v "$(pwd):/workspace:rw" \
  -e PROJECT=/workspace \
  vetto-agent:latest \
  claude -p "Refactor API module and run test suite"
```

> [!IMPORTANT]
> **Why `--security-opt seccomp=unconfined` is required for Landlock**:
> Older default Docker seccomp profiles block the `landlock_create_ruleset` syscall (`syscall 444`). Running with `seccomp=unconfined` allows the container process to call Landlock directly. Because Vetto applies its own strict Landlock + Seccomp BPF restrictions from within, the overall sandbox remains strictly bounded.

---

## 3. Safe Container Registry & Image Egress (Docker Outside Sandbox)

### The `docker.sock` Hazard
> [!CAUTION]
> **NEVER mount `/var/run/docker.sock` into an AI agent sandbox.**
> Mounting the host Docker daemon socket grants root-equivalent control over the host system. Any compromised tool or prompt injection can spawn a privileged container to bypass all sandbox controls.

### Secure Alternatives for Registry & Image Building
1. **Out-of-band CI Pipeline**: The agent generates or modifies the `Dockerfile`, but the actual `docker build` / `docker push` step runs outside the agent sandbox in a dedicated CI job.
2. **Daemonless Builders (Kaniko / Buildah)**: Use rootless `kaniko` or `buildah` running inside the unprivileged container with network allowlists restricted solely to your internal container registry.
3. **Vetto Network Egress Gate**:
   ```bash
   vetto --net=allowlist:registry.hub.docker.com,ghcr.io,auth.docker.io -- skopeo copy ...
   ```
