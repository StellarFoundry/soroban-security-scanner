"""Tests for the OpenAPI contract validator."""

from __future__ import annotations

import copy
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TOOLS = ROOT / "tools"
sys.path.insert(0, str(TOOLS))

import check_openapi  # noqa: E402


def load_published() -> dict:
    path = ROOT / "docs" / "integration" / "openapi.json"
    return json.loads(path.read_text(encoding="utf-8"))


class CheckOpenApiTests(unittest.TestCase):
    def test_published_contract_is_valid(self):
        doc = load_published()
        self.assertEqual(check_openapi.validate(doc), [])

    def test_rejects_internal_endpoints(self):
        doc = copy.deepcopy(load_published())
        doc["paths"]["/internal/metrics"] = {
            "get": {
                "operationId": "internalMetrics",
                "responses": {"200": {"description": "ok"}},
            }
        }
        problems = check_openapi.validate(doc)
        self.assertTrue(any("/internal/metrics" in p for p in problems), problems)

    def test_rejects_route_drift(self):
        doc = copy.deepcopy(load_published())
        del doc["paths"]["/v1/rules"]
        problems = check_openapi.validate(doc)
        self.assertTrue(any("/v1/rules" in p for p in problems), problems)

    def test_rejects_unresolved_ref_and_secrets(self):
        doc = copy.deepcopy(load_published())
        doc["info"]["description"] = "leaked token ghp_secret123"
        doc["paths"]["/v1/health"]["get"]["responses"]["200"] = {
            "$ref": "#/components/responses/MissingResponse"
        }
        problems = check_openapi.validate(doc)
        self.assertTrue(any("ghp_" in p for p in problems), problems)
        self.assertTrue(any("MissingResponse" in p for p in problems), problems)


if __name__ == "__main__":
    unittest.main()
