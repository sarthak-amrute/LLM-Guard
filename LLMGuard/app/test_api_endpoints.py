"""
Test LLMGuard FastAPI server endpoints using TestClient.
"""

import sys
import os
import unittest
from fastapi.testclient import TestClient

_DIR = os.path.dirname(os.path.abspath(__file__))
if _DIR not in sys.path:
    sys.path.insert(0, _DIR)

from server import app
import target_storage


class TestApiEndpoints(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)

    def test_01_get_providers(self):
        resp = self.client.get("/api/providers")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("providers", data)
        prov_ids = [p["id"] for p in data["providers"]]
        self.assertIn("gemini", prov_ids)
        self.assertIn("openai", prov_ids)
        self.assertIn("anthropic", prov_ids)
        self.assertIn("openrouter", prov_ids)
        self.assertIn("custom", prov_ids)
        self.assertIn("techmart", prov_ids)

    def test_02_get_targets(self):
        resp = self.client.get("/api/targets")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("targets", data)
        self.assertIn("active_target_id", data)
        # Verify no target exposes raw api_key or encrypted_api_key
        for t in data["targets"]:
            self.assertNotIn("api_key", t)
            self.assertNotIn("encrypted_api_key", t)

    def test_03_ssrf_and_auth_validation_on_target_create(self):
        # 1. Missing authorization confirmed
        payload = {
            "name": "Unauthorized Target",
            "provider": "custom",
            "base_url": "https://api.example.com/chat",
            "authorization_confirmed": False
        }
        resp = self.client.post("/api/targets", json=payload)
        self.assertEqual(resp.status_code, 400)
        self.assertIn("authorization", resp.json()["detail"].lower())

        # 2. SSRF URL blocked
        payload_ssrf = {
            "name": "SSRF Target",
            "provider": "custom",
            "base_url": "http://169.254.169.254/latest/meta-data",
            "authorization_confirmed": True
        }
        resp = self.client.post("/api/targets", json=payload_ssrf)
        self.assertEqual(resp.status_code, 400)
        self.assertIn("ssrf", resp.json()["detail"].lower())

    def test_04_target_crud_lifecycle(self):
        # Create
        create_payload = {
            "name": "API Test Gemini",
            "provider": "gemini",
            "model": "gemini-2.5-flash",
            "api_key": "AIzaSyD-ApiTestKey-998877",
            "authorization_confirmed": True
        }
        create_resp = self.client.post("/api/targets", json=create_payload)
        self.assertEqual(create_resp.status_code, 200)
        created = create_resp.json()
        target_id = created["id"]
        self.assertEqual(created["name"], "API Test Gemini")
        self.assertTrue(created["has_api_key"])
        self.assertNotIn("api_key", created)

        # Select
        sel_resp = self.client.post(f"/api/targets/{target_id}/select")
        self.assertEqual(sel_resp.status_code, 200)

        # Get active
        active_resp = self.client.get("/api/targets/active")
        self.assertEqual(active_resp.status_code, 200)
        self.assertEqual(active_resp.json()["id"], target_id)

        # Status check
        status_resp = self.client.get("/api/status")
        self.assertEqual(status_resp.status_code, 200)
        status_data = status_resp.json()
        self.assertEqual(status_data["active_target"]["id"], target_id)

        # Update
        update_resp = self.client.put(f"/api/targets/{target_id}", json={"name": "Updated Gemini Title"})
        self.assertEqual(update_resp.status_code, 200)
        self.assertEqual(update_resp.json()["name"], "Updated Gemini Title")

        # Delete
        del_resp = self.client.delete(f"/api/targets/{target_id}")
        self.assertEqual(del_resp.status_code, 200)


if __name__ == "__main__":
    unittest.main()
