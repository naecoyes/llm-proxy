import json
import unittest

from server import normalize_openai_sse_chunk


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


if __name__ == "__main__":
    unittest.main()
