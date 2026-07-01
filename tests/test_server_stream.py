import json
import unittest

from server import normalize_openai_sse_chunk
from health_checker import HealthChecker


class StreamChunkNormalizationTests(unittest.TestCase):
    def test_detects_content_without_usage_in_multi_event_chunk(self):
        first = {
            "choices": [
                {
                    "delta": {
                        "content": "hello",
                        "reasoning_content": "hidden",
                    }
                }
            ]
        }
        second = {"choices": [{"delta": {}, "finish_reason": "stop"}]}
        raw = (
            f"data: {json.dumps(first)}\n\n"
            f"data: {json.dumps(second)}\n\n"
            "data: [DONE]\n\n"
        ).encode()

        normalized, diagnostics = normalize_openai_sse_chunk(raw)
        text = normalized.decode()

        self.assertTrue(diagnostics["has_content"])
        self.assertEqual(diagnostics["finish_reason"], "stop")
        self.assertIsNone(diagnostics["usage"])
        self.assertIn('"content": "hello"', text)
        self.assertNotIn("reasoning_content", text)
        self.assertIn("data: [DONE]", text)

    def test_extracts_usage_when_provider_sends_it(self):
        usage = {"prompt_tokens": 3, "completion_tokens": 2, "total_tokens": 5}
        raw = f"data: {json.dumps({'choices': [], 'usage': usage})}\n\n"

        _, diagnostics = normalize_openai_sse_chunk(raw)

        self.assertEqual(diagnostics["usage"], usage)


class HealthClassificationTests(unittest.TestCase):
    def test_empty_response_is_not_assumed_to_be_rate_limit(self):
        checker = HealthChecker.__new__(HealthChecker)
        checker.RATE_LIMIT_PATTERNS = HealthChecker.RATE_LIMIT_PATTERNS

        self.assertFalse(checker.is_rate_limit_error("Empty upstream response"))
        self.assertTrue(checker.is_rate_limit_error("HTTP 429 rate limit"))


if __name__ == "__main__":
    unittest.main()
