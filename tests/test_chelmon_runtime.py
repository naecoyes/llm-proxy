import unittest
from unittest.mock import patch

import chelmon_runtime


class ChelmonRuntimeTests(unittest.TestCase):
    def setUp(self):
        chelmon_runtime._cached_at = 0
        chelmon_runtime._cached_status = None

    @patch("chelmon_runtime.shutil.which", return_value="docker")
    @patch("chelmon_runtime._has_eligible_model", return_value=(True, None))
    @patch("chelmon_runtime._run", side_effect=[(True, ""), (True, ""), (True, "")])
    def test_ready_when_image_network_proxy_and_model_checks_pass(self, _run, _model, _which):
        status = chelmon_runtime.get_chelmon_runtime_status(force=True)
        self.assertTrue(status["ready"])
        self.assertEqual(set(status["checks"]), {"image", "network", "proxy", "model"})

        commands = [call.args[0] for call in _run.call_args_list]
        self.assertEqual(commands[0][3:5], ["--format", "{{.Id}}"])
        self.assertEqual(commands[1][3:5], ["--format", "{{.Name}}"])

    @patch("chelmon_runtime.shutil.which", return_value="docker")
    @patch("chelmon_runtime._run", side_effect=[(True, ""), (False, "network missing")])
    def test_unready_when_network_check_fails(self, _run, _which):
        status = chelmon_runtime.get_chelmon_runtime_status(force=True)
        self.assertFalse(status["ready"])
        self.assertFalse(status["checks"]["network"]["ok"])
