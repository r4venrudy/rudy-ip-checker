import json
import tempfile
import unittest
from pathlib import Path
from rudy_runtime.config import load_config

class DeepConfigurationTests(unittest.TestCase):
    def test_depth_boundary_and_quoted_brackets(self):
        with tempfile.TemporaryDirectory() as temp:
            filename=Path(temp)/'config.json'
            filename.write_text('{"TOKEN":"dummy","deep":'+ '['*63+'0'+']'*63+'}')
            self.assertEqual(load_config({'TOKEN':'DISCORD_TOKEN'},env={},filename=filename)['TOKEN'],'dummy')
            filename.write_text('{"TOKEN":"dummy","deep":'+ '['*64+'0'+']'*64+'}')
            with self.assertRaisesRegex(ValueError,'nesting'):
                load_config({'TOKEN':'DISCORD_TOKEN'},env={},filename=filename)
            filename.write_text(json.dumps({'TOKEN':'dummy','quoted':'[{'*300+'"quoted"'+'}]'*300}))
            self.assertEqual(load_config({'TOKEN':'DISCORD_TOKEN'},env={},filename=filename)['TOKEN'],'dummy')
