"""Runtime selection remains deterministic and never prompts headless workers."""
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
from lua_re_ida import runtime

class RuntimeTests(unittest.TestCase):
    def setUp(self):
        runtime._probe.cache_clear()
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.java = self.root/'bin'/'java'
        self.java.parent.mkdir()
        self.java.write_text('not executed in this test')
        self.java.chmod(0o755)
        self.config = self.root/'config.json'
        mock = patch.object(runtime, 'config_path', return_value=self.config)
        mock.start()
        self.addCleanup(mock.stop)
        env = patch.dict(runtime.os.environ, {}, clear=True)
        env.start()
        self.addCleanup(env.stop)

    def process(self, version='21.0.8', returncode=0):
        return subprocess.CompletedProcess([], returncode, '', f'openjdk version "{version}"\n')

    def test_legacy_and_current_version_detection(self):
        for version,major in (('1.8.0_462',8),('11.0.29',11),('21.0.8',21)):
            runtime._probe.cache_clear()
            with patch.object(runtime.subprocess,'run',return_value=self.process(version)):
                self.assertEqual(runtime.probe_java(self.root).major,major)

    def test_old_version_and_broken_launcher(self):
        for result in (self.process('1.7.0_80'), self.process(returncode=1)):
            runtime._probe.cache_clear()
            with patch.object(runtime.subprocess,'run',return_value=result), self.assertRaises(runtime.JavaRuntimeError):
                runtime.probe_java(self.java)

    def test_selection_persists_and_auto_clears_only_java(self):
        self.config.write_text(json.dumps({'jar':'/example/unluac.jar'}))
        with patch.object(runtime.subprocess,'run',return_value=self.process()):
            runtime.select_java(self.java)
            self.assertEqual(runtime.selected_java().path,str(self.java.resolve()))
        runtime.select_java()
        self.assertEqual(json.loads(self.config.read_text()),{'jar':'/example/unluac.jar'})

    def test_missing_selection_never_silently_changes_java(self):
        self.config.write_text(json.dumps({'java':'/does-not-exist/java'}))
        with patch.object(runtime,'discover_java') as discover, self.assertRaises(runtime.JavaRuntimeError):
            runtime.selected_java()
        discover.assert_not_called()

    def test_missing_java_reports_onboarding_without_input(self):
        with patch.object(runtime,'discover_java',return_value=[]), self.assertRaisesRegex(runtime.JavaRuntimeError,'--configure-java'):
            runtime.selected_java()
        with patch.object(runtime.sys.stdin,'isatty',return_value=False), self.assertRaisesRegex(runtime.JavaRuntimeError,'--java PATH'):
            runtime.choose_java_cli()

    def test_discovery_deduplicates_real_paths(self):
        link=self.root/'alias';link.symlink_to(self.java)
        with patch.object(runtime,'candidate_paths',return_value=[str(self.java),str(link)]), patch.object(runtime.subprocess,'run',return_value=self.process()) as run:
            self.assertEqual(len(runtime.discover_java()),1)
            self.assertEqual(run.call_count,1)
