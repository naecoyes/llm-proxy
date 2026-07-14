import json
import unittest
from types import SimpleNamespace

from server import _prepare_openai_request_body, normalize_openai_sse_chunk


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

    def test_preserves_reasoning_content_when_requested(self):
        raw = f"data: {json.dumps({'choices': [{'delta': {'reasoning_content': 'private thought'}}]})}\n\n".encode()
        normalized, _ = normalize_openai_sse_chunk(raw, preserve_reasoning_content=True)
        self.assertIn("reasoning_content", normalized.decode())

    def test_deepseek_thinking_uses_high_and_keeps_tool_turn_reasoning(self):
        model = SimpleNamespace(provider="deepseek", thinking_enabled=True, reasoning_effort="high")
        body = _prepare_openai_request_body(model, {
            "messages": [
                {"role": "assistant", "content": "", "reasoning_content": "tool context", "tool_calls": [{"id": "call_1"}]},
                {"role": "assistant", "content": "done", "reasoning_content": "ordinary context"},
            ],
            "temperature": 0.2,
            "top_p": 0.8,
        })
        self.assertEqual(body["thinking"], {"type": "enabled"})
        self.assertEqual(body["reasoning_effort"], "high")
        self.assertNotIn("temperature", body)
        self.assertNotIn("top_p", body)
        self.assertEqual(body["messages"][0]["reasoning_content"], "tool context")
        self.assertNotIn("reasoning_content", body["messages"][1])

    def test_deepseek_xhigh_maps_to_max(self):
        model = SimpleNamespace(provider="deepseek", thinking_enabled=True, reasoning_effort="xhigh")
        body = _prepare_openai_request_body(model, {"messages": []})
        self.assertEqual(body["reasoning_effort"], "max")


if __name__ == "__main__":
    unittest.main()
