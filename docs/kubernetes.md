# Kubernetes manifests

`soroban-scan` is a **CLI scanner**, not a server. It has no HTTP API, database,
or long-running process, so there is no `Deployment`, `Service`, or `Ingress` to
deploy. The `deploy/kubernetes/` directory contains the resources that actually
match the program:

| File | Resource | Purpose |
| ---- | -------- | ------- |
| `namespace.yaml` | `Namespace` | Isolates the workload. |
| `configmap.yaml` | `ConfigMap` | The `soroban-scan.toml` used by every scan. |
| `pvc.yaml` | two `PersistentVolumeClaim`s | Read-only source tree and report output. |
| `job.yaml` | `Job` | One-off scan; use it to validate an image, source tree, or config. |
| `cronjob.yaml` | `CronJob` | Scheduled scans, one UTC run per day by default. |

The one-off `Job` is the "migration job" for this project: there is no database
schema to migrate. Use it after an upgrade, or before enabling the schedule, to
prove the image and mounted source still work.

All files are plain YAML with no templating, so they can be read and diffed
directly. If you prefer Helm, the chart in `deploy/helm/soroban-scan/` renders
the same resources with configurable values; see [Helm chart](#helm-chart)
below.

## Helm chart

The chart deploys the **batch Job and CronJob**, not a server. There is no
`Deployment`, `Service`, `Ingress`, or listening port, so there are no
liveness/readiness/startup probes: a batch container has no endpoint to probe.
A scan either finishes (exit 0 or 1) or the Job fails. This is an intentional
adaptation of the service-oriented "API/worker chart" pattern.

```bash
helm install soroban-scan deploy/helm/soroban-scan \
  --namespace soroban-scan --create-namespace \
  --set image.repository=registry.example.com/security/soroban-scan \
  --set image.tag=0.2.0
```

The chart does not publish or build an image, and it creates no namespace
(use `--create-namespace`, as above). Populate the source claim after install,
just as for the plain manifests.

Common values:

| Value | Default | Purpose |
| ----- | ------- | ------- |
| `image.repository`, `image.tag`, `image.digest` | `soroban-scan:0.2.0` | Image reference; a digest pins it immutably. |
| `imagePullSecrets` | `[]` | Names of existing registry pull secrets. |
| `job.enabled` | `true` | Render the one-off validation Job. |
| `cronjob.enabled`, `cronjob.schedule` | `true`, `0 2 * * *` | Scheduled scans. |
| `scan.failOn`, `scan.extraArgs` | `high`, `[]` | Exit-code gate and extra CLI arguments. |
| `config` | the `soroban-scan.toml` above | ConfigMap contents. |
| `resources` | 100m/128Mi requests, 500m/1Gi limits | Container requests and limits. |
| `source` / `reports` | 10Gi / 5Gi claims | Size, access mode, storage class, or `existingClaim`. |
| `extraEnv`, `extraEnvFrom` | `[]` | Optional environment and Secret/ConfigMap references. |

The scanner needs **no credentials**, and the chart ships no default passwords,
tokens, or Secret objects. `imagePullSecrets` and `extraEnvFrom` exist only for
a private registry or an operator-supplied runtime Secret.

Render and inspect the chart before installing:

```bash
helm lint deploy/helm/soroban-scan
helm template soroban-scan deploy/helm/soroban-scan --namespace soroban-scan
```

`tests/test_helm_chart.py` runs `helm lint` and `helm template`, then asserts the
rendered resource kinds, probes are absent, the workload is locked down, and
image/resources/secrets/claims are parameterized. It is skipped when `helm` is
not installed; CI installs Helm for the Python test job.

## Required image

The project publishes release archives but **does not publish a registry
image**. Build the opt-in image from a checkout or release archive as described
in [Docker image](docker.md), push it where your cluster can pull it, and
replace `image: soroban-scan:0.2.0` in `job.yaml` and `cronjob.yaml` with that
reference. Pin a digest or an immutable tag in production.

The supplied image runs as `65532:65532`, matching the manifests' security
context, and its Alpine base provides the `/bin/sh` used to name reports after
the pod. If you replace it with a shell-less image (for example a distroless
build), change `command`/`args` to invoke `soroban-scan` directly and write to a
fixed filename such as `/reports/report.json`; adjust retention accordingly.

## Storage

Two claims are required:

- **`soroban-scan-source`** (10Gi, `ReadWriteOnce`) is mounted read-only at
  `/workspace/src`. Populate it with the repository you want to scan, for
  example with a separate sync job. The scanner never modifies the source.
- **`soroban-scan-reports`** (5Gi, `ReadWriteOnce`) is writable at `/reports`.
  Each run writes `$POD_NAME.json`, so runs do not overwrite one another.

`ReadWriteOnce` is enough for a single scheduled scan and a manual Job as long
as they do not run on different nodes at the same time. `concurrencyPolicy:
Forbid` prevents overlapping CronJob runs; a manually created Job can still
overlap, so do not run one during a scheduled scan. Use a
`ReadWriteMany`-capable storage class if you need concurrent writers.

Retention is **not automated**. The report claim grows by one file per run.
Copy reports to your artifact store and delete old files on a schedule; see
[Report retention](retention.md) for naming guidance.

## Secrets

The scanner itself needs **no secrets**. It does not require keys, tokens,
wallets, or network access, and the pod does not mount a service-account token
(`automountServiceAccountToken: false`). There is no RBAC to grant.

If you populate the source claim from a private repository, that credential
belongs to the sync job, not to the scanner. Keep it in a `Secret` owned by that
job and do not mount it into the scan pod. If your registry is private, add an
`imagePullSecret` to the pod spec; it is optional and omitted here.

## Apply and run

Build the image and publish it to your registry first, then edit the image in
both workload files and populate the source claim. Apply in order:

```bash
kubectl apply -f deploy/kubernetes/namespace.yaml
kubectl apply -f deploy/kubernetes/configmap.yaml
kubectl apply -f deploy/kubernetes/pvc.yaml
kubectl apply -f deploy/kubernetes/job.yaml
kubectl apply -f deploy/kubernetes/cronjob.yaml
```

Watch the one-off scan:

```bash
kubectl -n soroban-scan get jobs,pods
kubectl -n soroban-scan logs job/soroban-scan-once
```

Reports are written to the `soroban-scan-reports` claim as
`<pod-name>.json`. There is no Deployment to `exec` into, so read the claim with
your storage tooling or mount it in a short-lived pod. The report is ordinary
JSON and does not require the scanner to read it.

A scan exits non-zero when findings meet `--fail-on high`. The `Job` therefore
shows as failed when the target has high or critical findings. That is the
intended gate, not a pod crash: inspect the report before changing the
threshold. The example uses `--fail-on high`; edit the ConfigMap or args to
match your policy.

## Validation

CI runs a structural test, not a live-cluster validation:

```bash
python -m unittest tests.test_kubernetes_manifests -v
```

The test parses each YAML document and asserts the required fields, that the
ConfigMap contains `soroban-scan.toml`, that workloads mount both claims and the
config, that the source mount is read-only, that the CronJob has a schedule and
`concurrencyPolicy: Forbid`, and that the pod security context is locked down.

This is deliberately **not** `kubectl apply --dry-run=client --validate=false`.
That command only checks client-side shape and cannot prove the resources are
accepted by a cluster. No Kubernetes API server or offline schema validator is
available in this repository, so the test checks structure and required fields
only. Run `kubectl apply --dry-run=server -f deploy/kubernetes/` against a real
cluster before production use to validate against your cluster's API versions
and admission policies.
