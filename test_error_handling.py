import os
import unittest
from unittest.mock import AsyncMock, patch
import httpx

# Set dummy environment variables required by defense_mcp module
os.environ["DEFENSE_API_TOKEN"] = "dummy_token"
os.environ["DEFENSE_API_BASE_URL"] = "https://api.defense.com"

from defense_mcp import format_http_error_message, get_biggest_risks, get_threat_to_remediate_first, get_new_threats


class TestHttpErrorFormatting(unittest.TestCase):
    def test_401_revoked_key(self):
        req = httpx.Request("GET", "https://api.defense.com/v1/threats")
        resp = httpx.Response(401, text="API key revoked", request=req)
        err = httpx.HTTPStatusError("Unauthorized", request=req, response=resp)

        formatted = format_http_error_message(err)
        self.assertIn("API request failed: 401", formatted)
        self.assertIn("Your API key was rejected (revoked or expired)", formatted)
        self.assertIn("restart Claude Desktop", formatted)

    def test_401_expired_key(self):
        req = httpx.Request("GET", "https://api.defense.com/v1/threats")
        resp = httpx.Response(401, json={"error": "API key expired"}, request=req)
        err = httpx.HTTPStatusError("Unauthorized", request=req, response=resp)

        formatted = format_http_error_message(err)
        self.assertIn("API request failed: 401", formatted)
        self.assertIn("Your API key was rejected (revoked or expired)", formatted)
        self.assertIn("restart Claude Desktop", formatted)

    def test_401_generic_invalid_token(self):
        req = httpx.Request("GET", "https://api.defense.com/v1/threats")
        resp = httpx.Response(401, text="Invalid token supplied", request=req)
        err = httpx.HTTPStatusError("Unauthorized", request=req, response=resp)

        formatted = format_http_error_message(err)
        self.assertIn("API request failed: 401", formatted)
        self.assertIn("Please check your API token", formatted)
        self.assertNotIn("revoked or expired", formatted)

    def test_403_forbidden(self):
        req = httpx.Request("GET", "https://api.defense.com/v1/threats")
        resp = httpx.Response(403, text="Forbidden", request=req)
        err = httpx.HTTPStatusError("Forbidden", request=req, response=resp)

        formatted = format_http_error_message(err)
        self.assertIn("API request failed: 403", formatted)
        self.assertIn("API token lacks required permissions", formatted)

    def test_500_server_error(self):
        req = httpx.Request("GET", "https://api.defense.com/v1/threats")
        resp = httpx.Response(500, text="Internal Server Error", request=req)
        err = httpx.HTTPStatusError("Internal Server Error", request=req, response=resp)

        formatted = format_http_error_message(err)
        self.assertEqual(formatted, "API request failed: 500")


class TestToolErrorHandlingIntegration(unittest.IsolatedAsyncioTestCase):
    async def test_get_biggest_risks_revoked_key(self):
        req = httpx.Request("GET", "https://api.defense.com/v1/threats")
        resp = httpx.Response(401, text="API key revoked", request=req)
        http_err = httpx.HTTPStatusError("Unauthorized", request=req, response=resp)

        mock_client = AsyncMock()
        mock_client.get_threats.side_effect = http_err

        with patch("defense_mcp.get_defense_client", return_value=mock_client):
            result = await get_biggest_risks()
            self.assertEqual(result["threats"], [])
            self.assertIn("error", result)
            self.assertIn("Your API key was rejected (revoked or expired)", result["error"])
            self.assertIn("restart Claude Desktop", result["error"])

    async def test_get_threat_to_remediate_first_generic_401(self):
        req = httpx.Request("GET", "https://api.defense.com/v1/threats")
        resp = httpx.Response(401, text="Unauthorized", request=req)
        http_err = httpx.HTTPStatusError("Unauthorized", request=req, response=resp)

        mock_client = AsyncMock()
        mock_client.get_threats.side_effect = http_err

        with patch("defense_mcp.get_defense_client", return_value=mock_client):
            result = await get_threat_to_remediate_first()
            self.assertEqual(result["threats"], [])
            self.assertIn("error", result)
            self.assertIn("Please check your API token", result["error"])


if __name__ == "__main__":
    unittest.main()
