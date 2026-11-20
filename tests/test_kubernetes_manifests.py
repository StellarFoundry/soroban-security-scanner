"""Structural checks for the plain Kubernetes manifests in deploy/kubernetes/.

This is not a Kubernetes schema validator. It parses the YAML and asserts the
fields this project relies on, because no API server or offline schema validator
is available in CI.
"""

from __future__ import annotations

import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
MANIFESTS = ROOT / "deploy" / "kubernetes"


def load_documents(name: str):
    with (MANIFESTS / name).open(encoding="utf-8") as handle:
        return [doc for doc in yaml.safe_load_all(handle) if doc is not None]


def single_kind(name: str, kind: str):
    documents = [doc for doc in load_documents(name) if doc.get("kind") == kind]
    assert len(documents) == 1, f"{name}: expected one {kind}, got {len(documents)}"
    return documents[0]


class KubernetesManifestTests(unittest.TestCase):
    def test_all_resources_are_namespaced_except_the_namespace(self):
        kinds = set()
        for path in sorted(MANIFESTS.glob("*.yaml")):
            for document in load_documents(path.name):
                kinds.add(document["kind"])
                self.assertTrue(document.get("apiVersion"), path.name)
                self.assertTrue(document.get("metadata", {}).get("name"), path.name)
                if document["kind"] != "Namespace":
                    self.assertEqual(
                        document["metadata"].get("namespace"),
                        "soroban-scan",
                        f"{path.name}: {document['kind']} must use the soroban-scan namespace",
                    )
        self.assertEqual(
            kinds,
            {"Namespace", "ConfigMap", "PersistentVolumeClaim", "Job", "CronJob"},
            "this is a CLI, not a server: do not add Deployment, Service, or Ingress",
        )

    def test_configmap_contains_a_scanner_config(self):
        config_map = single_kind("configmap.yaml", "ConfigMap")
        config = config_map["data"]["soroban-scan.toml"]
        self.assertIn("[rules]", config)
        self.assertIn("follow_symlinks = false", config)

    def test_claims_are_declared_with_storage(self):
        claims = load_documents("pvc.yaml")
        self.assertEqual({claim["metadata"]["name"] for claim in claims}, {
            "soroban-scan-source",
            "soroban-scan-reports",
        })
        for claim in claims:
            self.assertIn("ReadWriteOnce", claim["spec"]["accessModes"])
            self.assertIn("storage", claim["spec"]["resources"]["requests"])

    def test_job_is_a_locked_down_one_off_scan(self):
        job = single_kind("job.yaml", "Job")
        self.assertEqual(job["spec"]["template"]["spec"]["restartPolicy"], "Never")
        self._assert_scan_pod(job["spec"]["template"]["spec"])

    def test_cronjob_is_a_scheduled_locked_down_scan(self):
        cronjob = single_kind("cronjob.yaml", "CronJob")
        self.assertTrue(cronjob["spec"]["schedule"])
        self.assertEqual(cronjob["spec"]["concurrencyPolicy"], "Forbid")
        pod = cronjob["spec"]["jobTemplate"]["spec"]["template"]["spec"]
        self.assertEqual(pod["restartPolicy"], "Never")
        self._assert_scan_pod(pod)

    def _assert_scan_pod(self, pod):
        self.assertFalse(pod["automountServiceAccountToken"])
        self.assertTrue(pod["securityContext"]["runAsNonRoot"])
        self.assertEqual(pod["securityContext"]["seccompProfile"]["type"], "RuntimeDefault")

        containers = pod["containers"]
        self.assertEqual(len(containers), 1)
        container = containers[0]
        self.assertNotIn(":latest", container["image"])

        command = " ".join(container.get("command", []) + container.get("args", []))
        for fragment in ("soroban-scan", " scan ", "--config", "--fail-on"):
            self.assertIn(fragment, f" {command} ")

        security = container["securityContext"]
        self.assertFalse(security["allowPrivilegeEscalation"])
        self.assertTrue(security["readOnlyRootFilesystem"])
        self.assertIn("ALL", security["capabilities"]["drop"])

        mounts = {mount["name"]: mount for mount in container["volumeMounts"]}
        self.assertEqual(set(mounts), {"source", "reports", "config"})
        self.assertTrue(mounts["source"]["readOnly"])
        self.assertTrue(mounts["config"]["readOnly"])
        self.assertFalse(mounts["reports"].get("readOnly", False))

        volumes = {volume["name"]: volume for volume in pod["volumes"]}
        self.assertEqual(
            volumes["source"]["persistentVolumeClaim"]["claimName"],
            "soroban-scan-source",
        )
        self.assertEqual(
            volumes["reports"]["persistentVolumeClaim"]["claimName"],
            "soroban-scan-reports",
        )
        self.assertEqual(volumes["config"]["configMap"]["name"], "soroban-scan-config")


if __name__ == "__main__":
    unittest.main()
