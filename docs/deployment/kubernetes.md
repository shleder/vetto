# Vetto in Kubernetes

Vetto can be deployed as a node-level runtime within a Kubernetes cluster to enforce strict kernel-level boundaries for AI agent execution in Pods.

## Architecture

In a Kubernetes environment, Vetto is deployed as a **DaemonSet**. The Vetto daemon runs with privileges (e.g. `CAP_SYS_ADMIN`, `CAP_NET_ADMIN`, `CAP_SETUID`, `CAP_SETGID`) to configure Landlock, seccomp-bpf, and namespaces. 

When a CI/CD runner or orchestrator creates an "Agent Pod", Vetto transparently intercepts the entrypoint or executes the payload securely by mounting the necessary runtime sockets. This architecture guarantees that even if the container runtime (e.g., containerd or CRI-O) allows certain capabilities, the underlying kernel sandbox restricts the agent process at the `fork()` and `execve()` boundary.

### CI/CD Runner Integration

Vetto integrates natively with popular CI/CD pipelines to sandbox AI tasks:

- **GitLab CI**: By mapping `/var/run/vetto` into the GitLab Runner execution environment, tasks labeled for AI workloads are executed strictly through the Vetto socket.
- **GitHub Actions**: Self-hosted runners can utilize the `agent-pod-template.yaml` to spin up ephemeral runners strictly bounded by Vetto.
- **Argo Workflows**: Workflows can use `vetto run` within steps, delegating isolation enforcement directly to the node-level DaemonSet.

## Installation via Helm

The recommended way to install Vetto into your cluster is via the provided Helm chart.

### Prerequisites

- Helm v3+
- Kubernetes cluster (Linux nodes required for Tier 1 capabilities)
- Administrator access

### Install the Chart

```bash
# Add the repository (if published)
# helm repo add vetto https://shleder.github.io/vetto/charts
# helm repo update

# Install from local source
helm install vetto ./deploy/helm/vetto -n vetto-system --create-namespace
```

### Configuration (values.yaml)

You can customize the DaemonSet by overriding `values.yaml`:

```yaml
daemonset:
  enabled: true
  securityContext:
    privileged: true # Required for Landlock and Namespaces setup
resources:
  limits:
    memory: "512Mi"
    cpu: "500m"
```

## Manual Installation (Manifests)

For environments without Helm, use the static manifests in `deploy/k8s/`:

```bash
kubectl apply -f deploy/k8s/rbac.yaml
kubectl apply -f deploy/k8s/daemonset.yaml
```

To test launching an agent pod:

```bash
kubectl apply -f deploy/k8s/agent-pod-template.yaml
```

Verify that the Vetto runtime has successfully instrumented the node:

```bash
kubectl get daemonsets
kubectl logs -l app=vetto,component=runtime
```
