from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock

from codex_rescue.alpha7.graph import SurfaceVisibility
from codex_rescue.alpha7.recovery.salvage_stream import (
    SourceStatus,
    StreamSalvageEngine,
)
from codex_rescue.alpha7.surfaces.app_server import (
    AppServerAdapter,
    JsonRpcError,
    RealAppServerClient,
)


class CompactionResiliencyTests(unittest.TestCase):
    def test_app_server_observe_thread_handles_404_as_compaction_not_supported(self) -> None:
        adapter = AppServerAdapter()
        mock_client = MagicMock(spec=RealAppServerClient)
        mock_transport = MagicMock()
        mock_transport.is_initialized = True
        mock_client._client = mock_transport

        # Mock read_thread raising JsonRpcError 404
        mock_client.read_thread.side_effect = JsonRpcError(code=404, message="Not Found")

        obs = adapter.observe_thread("thread-123", client=mock_client)
        self.assertEqual(obs.visibility, SurfaceVisibility.UNSUPPORTED)
        self.assertEqual(obs.error_code, "COMPACTION_NOT_SUPPORTED")

    def test_app_server_observe_thread_handles_32601_as_compaction_not_supported(self) -> None:
        adapter = AppServerAdapter()
        mock_client = MagicMock(spec=RealAppServerClient)
        mock_transport = MagicMock()
        mock_transport.is_initialized = True
        mock_client._client = mock_transport

        # Mock read_thread raising JsonRpcError -32601 (Method not found)
        mock_client.read_thread.side_effect = JsonRpcError(code=-32601, message="Method not found")

        obs = adapter.observe_thread("thread-123", client=mock_client)
        self.assertEqual(obs.visibility, SurfaceVisibility.UNSUPPORTED)
        self.assertEqual(obs.error_code, "COMPACTION_NOT_SUPPORTED")

    def test_app_server_observe_thread_handles_timeout_as_endpoint_unavailable(self) -> None:
        adapter = AppServerAdapter()
        mock_client = MagicMock(spec=RealAppServerClient)
        mock_transport = MagicMock()
        mock_transport.is_initialized = True
        mock_client._client = mock_transport

        # Mock read_thread raising TimeoutError
        mock_client.read_thread.side_effect = TimeoutError("Request timed out")

        obs = adapter.observe_thread("thread-123", client=mock_client)
        self.assertEqual(obs.visibility, SurfaceVisibility.UNSUPPORTED)
        self.assertEqual(obs.error_code, "ENDPOINT_UNAVAILABLE")

    def test_forensic_tail_salvage_preserves_source_and_stitches_recovered_tail(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            src_file = Path(td) / "source_session.jsonl"
            tgt_file = Path(td) / "salvaged_session.jsonl"

            # Create a session with a lost tail after compaction
            lines = [
                {"type": "session_meta", "payload": {"id": "test-uuid"}},
                {"type": "compacted", "payload": {"message": "summary", "replacement_history": []}},
            ]
            src_file.write_text("".join(json.dumps(l) + "\n" for l in lines), encoding="utf-8")
            orig_src_content = src_file.read_bytes()

            recovered_tail = [
                {"type": "response_item", "payload": {"type": "function_call_output", "call_id": "c1", "output": {"status": "ok"}}},
                {"type": "event_msg", "payload": {"type": "user_message", "message": "continue"}},
            ]

            engine = StreamSalvageEngine()
            manifest = engine.salvage_forensic_session(
                source_path=src_file,
                target_path=tgt_file,
                recovered_tail_events=recovered_tail,
            )

            # 1. Source file is untouched (Zero In-Place Mutation)
            self.assertEqual(src_file.read_bytes(), orig_src_content)

            # 2. Target file contains all original valid prefix plus provenance marker plus recovered tail
            self.assertTrue(tgt_file.exists())
            self.assertEqual(manifest.valid_records_count, len(lines) + len(recovered_tail))
            tgt_lines = [json.loads(line) for line in tgt_file.read_text(encoding="utf-8").splitlines() if line.strip()]
            self.assertEqual(len(tgt_lines), 5)
            self.assertEqual(tgt_lines[2]["type"], "rescue_recovered_tail")
            self.assertEqual(tgt_lines[2]["payload"]["provenance"], "codex-rescue-forensic-salvage")
            self.assertEqual(tgt_lines[-1]["payload"]["message"], "continue")


if __name__ == "__main__":
    unittest.main()
