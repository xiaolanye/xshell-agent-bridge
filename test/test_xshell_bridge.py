import os
from pathlib import Path
import runpy
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch


BRIDGE_SCRIPT = Path(__file__).resolve().parents[1] / "xshell" / "xshell_agent_bridge.py"


class BridgeExecutionTests(unittest.TestCase):
    def setUp(self):
        config_dir = tempfile.TemporaryDirectory()
        self.addCleanup(config_dir.cleanup)
        config = Path(config_dir.name) / "local.json"
        config.write_text("{}", encoding="utf-8")
        with patch.dict(os.environ, {"XSHELL_BRIDGE_CONFIG": str(config)}):
            self.execute_job = runpy.run_path(str(BRIDGE_SCRIPT))["execute_job"]
        self.execute_job.__globals__["atomic_write_json"] = self.write_result
        self.execute_job.__globals__["xsh"] = SimpleNamespace(
            Screen=SimpleNamespace(Send=self.send),
            Dialog=SimpleNamespace(MessageBox=self.message_box),
        )

    def write_result(self, _path, value):
        self.result = value

    def send(self, text):
        self.sent.append(text)

    def message_box(self, _message, _title, _dialog_type):
        self.dialogs += 1
        if isinstance(self.answer, Exception):
            raise self.answer
        return self.answer

    def run_job(self, mode, action, answer=6, **fields):
        self.sent = []
        self.dialogs = 0
        self.answer = answer
        job = {"id": "test", "action": action, **fields}
        if mode is not None:
            job["safetyMode"] = mode
        self.execute_job(job)

    def test_send_matrix_and_dangerous_command_reclassification(self):
        cases = [
            (None, "pwd", ["pwd", "\r"], True),
            ("safe", "rm ./discard-me", [], False),
            ("normal", "pwd", ["pwd", "\r"], False),
            ("normal", "rm ./discard-me", ["rm ./discard-me", "\r"], True),
            ("full", "pwd", ["pwd", "\r"], False),
            ("full", "rm ./discard-me", ["rm ./discard-me", "\r"], False),
        ]
        for mode, command, sent, confirmation in cases:
            with self.subTest(mode=mode, command=command):
                action = {"type": "send", "text": command, "enter": True, "riskLevel": "low"}
                self.run_job(mode, action, confirmationRequired=False)
                self.assertEqual(self.sent, sent)
                self.assertEqual(self.dialogs, int(confirmation))
                self.assertEqual(self.result["ok"], bool(sent))
                self.assertEqual(self.result["result"]["confirmationShown"], confirmation)
                self.assertEqual(self.result["result"]["approvedByUser"], confirmation)

    def test_rejection_or_dialog_error_sends_no_input(self):
        action = {"type": "send", "text": "rm ./discard-me", "enter": True}
        for answer in (7, RuntimeError("dialog unavailable")):
            with self.subTest(answer=answer):
                self.run_job("normal", action, answer=answer, confirmationRequired=True)
                self.assertFalse(self.result["ok"])
                self.assertEqual(self.sent, [])
                self.assertEqual(self.dialogs, 1)
                self.assertFalse(self.result["result"]["approvedByUser"])
                self.assertEqual(self.result["result"]["confirmationShown"], answer == 7)

    def test_interrupt_behavior_and_unknown_mode(self):
        action = {"type": "interrupt"}
        for mode, dialogs, sent in (("safe", 1, ["\x03"]), ("normal", 1, ["\x03"]),
                                    ("full", 0, ["\x03"]), ("typo", 0, [])):
            with self.subTest(mode=mode):
                self.run_job(mode, action, confirmationRequired=False)
                self.assertEqual(self.dialogs, dialogs)
                self.assertEqual(self.sent, sent)


if __name__ == "__main__":
    unittest.main()
