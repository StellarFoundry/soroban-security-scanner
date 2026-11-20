"""Structural and template checks for the soroban-scan Helm chart.

Requires `helm` on PATH. The chart targets a batch Job/CronJob, not a server, so
the assertions reject Deployment, Service, Ingress and probe fields. Run with:

    python -m unittest tests.test_helm_chart -v
"""

from __future__ import annotations

import shutil
import subprocess
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
CHART = ROOT / "deploy" / "helm" / "soroban-scan"
HELM = shutil.which("helm")


def run_helm(*args: str) -> str:
    if HELM is None:
        raise unittest.SkipTest("helm is not installed")
    result = subprocess.run(
        [HELM, *args],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout


def render(*args: str) -> list[dict]:
    output = run_helm("template", "soroban-scan", str(CHART), *args)
    return [document for document in yaml.safe_load_all(output) if document]


def by_kind(documents: list[dict], kind: str) -> list[dict]:
    return [document for document in documents if document.get("kind") == kind]


@unittest.skipUnless(HELM, "helm is not installed")
class HelmChartTests(unittest.TestCase):
    def test_chart_lints(self):
        output = run_helm("lint", str(CHART))
        self.assertIn("0 chart(s) failed", output)

    def test_default_install_renders_a_batch_workload(self):
        documents = render("--namespace", "soroban-scan")
        kinds = {document["kind"] for document in documents}

        self.assertEqual(
            kinds,
            {"ConfigMap", "PersistentVolumeClaim", "Job", "CronJob"},
            "this is a CLI, not a server: do not add Deployment, Service, or Ingress",
        )
        self.assertEqual(len(by_kind(documents, "PersistentVolumeClaim")), 2)

        for workload in (*by_kind(documents, "Job"), *by_kind(documents, "CronJob")):
            pod = (
                workload["spec"]["template"]["spec"]
                if workload["kind"] == "Job"
                else workload["spec"]["jobTemplate"]["spec"]["template"]["spec"]
            )
            self.assertNotIn("ports", pod["containers"][0])
            self.assertNotIn("livenessProbe", pod["containers"][0])
            self.assertNotIn("readinessProbe", pod["containers"][0])
            self._assert_scan_pod(pod)

        cronjob = by_kind(documents, "CronJob")[0]
        self.assertEqual(cronjob["spec"]["concurrencyPolicy"], "Forbid")

    def test_image_resources_secrets_and_claims_are_parameterized(self):
        documents = render(
            "--namespace",
            "soroban-scan",
            "--set",
            "image.repository=registry.example.com/security/scanner",
            "--set",
            "image.tag=1.2.3",
            "--set",
            "image.digest=sha256:0123456789abcdef",
            "--set",
            "resources.requests.cpu=250m",
            "--set",
            "resources.requests.memory=256Mi",
            "--set",
            "resources.limits.cpu=1",
            "--set",
            "resources.limits.memory=512Mi",
            "--set",
            "imagePullSecrets[0]=registry-credentials",
            "--set",
            "extraEnvFrom[0].secretRef.name=scan-runtime",
            "--set",
            "source.existingClaim=my-source",
            "--set",
            "reports.existingClaim=my-reports",
            "--set",
            "job.enabled=false",
        )

        self.assertFalse(by_kind(documents, "Job"))
        self.assertEqual(by_kind(documents, "PersistentVolumeClaim"), [])

        cronjob = by_kind(documents, "CronJob")[0]
        pod = cronjob["spec"]["jobTemplate"]["spec"]["template"]["spec"]
        container = pod["containers"][0]

        self.assertEqual(
            container["image"],
            "registry.example.com/security/scanner:1.2.3@sha256:0123456789abcdef",
        )
        self.assertEqual(
            container["resources"]["requests"], {"cpu": "250m", "memory": "256Mi"}
        )
        limits = container["resources"]["limits"]
        self.assertEqual(str(limits["cpu"]), "1")
        self.assertEqual(limits["memory"], "512Mi")
        self.assertEqual(
            pod["imagePullSecrets"], [{"name": "registry-credentials"}]
        )
        self.assertEqual(
            container["envFrom"], [{"secretRef": {"name": "scan-runtime"}}]
        )

        volumes = {volume["name"]: volume for volume in pod["volumes"]}
        self.assertEqual(
            volumes["source"]["persistentVolumeClaim"]["claimName"], "my-source"
        )
        self.assertEqual(
            volumes["reports"]["persistentVolumeClaim"]["claimName"], "my-reports"
        )

    def test_no_credentials_are_shipped_by_default(self):
        documents = render("--namespace", "soroban-scan")
        self.assertFalse(by_kind(documents, "Secret"))
        rendered = yaml.safe_dump_all(documents).lower()
        for field in ("password:", "secretkeyref:"):
            self.assertNotIn(field, rendered)

    def _assert_scan_pod(self, pod):
        self.assertFalse(pod["automountServiceAccountToken"])
        self.assertEqual(pod["restartPolicy"], "Never")
        self.assertTrue(pod["securityContext"]["runAsNonRoot"])
        self.assertEqual(
            pod["securityContext"]["seccompProfile"]["type"], "RuntimeDefault"
        )

        self.assertEqual(len(pod["containers"]), 1)
        container = pod["containers"][0]
        self.assertNotIn(":latest", container["image"])

        command = " ".join(container.get("command", []) + container.get("args", []))
        for fragment in ("soroban-scan", " scan ", "--config", "--fail-on"):
            self.assertIn(fragment, f" {command} ")

        security = container["securityContext"]
        self.assertFalse(security["allowPrivilegeEscalation"])
        self.assertTrue(security["readOnlyRootFilesystem"])
        self.assertIn("ALL", security["capabilities"]["drop"])

        self.assertEqual(
            set(container["resources"]["requests"]), {"cpu", "memory"}
        )
        self.assertEqual(set(container["resources"]["limits"]), {"cpu", "memory"})

        mounts = {mount["name"]: mount for mount in container["volumeMounts"]}
        self.assertEqual(set(mounts), {"source", "reports", "config"})
        self.assertTrue(mounts["source"]["readOnly"])
        self.assertTrue(mounts["config"]["readOnly"])
        self.assertFalse(mounts["reports"].get("readOnly", False))

        volumes = {volume["name"]: volume for volume in pod["volumes"]}
        self.assertIn("persistentVolumeClaim", volumes["source"])
        self.assertIn("persistentVolumeClaim", volumes["reports"])
        self.assertIn("configMap", volumes["config"])


if __name__ == "__main__":
    unittest.main()
