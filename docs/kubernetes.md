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

All files are plain YAML with no templating or Helm chart, so they can be read
and diffed directly.

## Required image

The project publishes release archives but **does not publish a container
image**. Build one from a release archive or a checkout, push it where your
cluster can pull it, and replace `image: soroban-scan:0.2.0` in `job.yaml` and
`cronjob.yaml` with that reference. Pin a digest or an immutable tag in
production.

The example runs through `/bin/sh` to name the report after the pod. If your
image has no shell (for example a distroless build), change `command`/`args` to
invoke `soroban-scan` directly and write to a fixed filename such as
`/reports/report.json`; adjust the retention process accordingly.

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
