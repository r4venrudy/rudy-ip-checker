import json
import tempfile
import unittest
from pathlib import Path
from rudy_runtime.config import load_config

class CredentialControlTests(unittest.TestCase):
    def test_embedded_controls_are_rejected_without_echoing_the_value(self):
        with tempfile.TemporaryDirectory() as temp:
            for code in [*range(32),127]:
                value='dummy-left'+chr(code)+'right'
                with self.assertRaisesRegex(ValueError,'control characters') as caught:
                    load_config({'TOKEN':'DISCORD_TOKEN'},env={'DISCORD_TOKEN':value},filename=Path(temp)/'missing.json')
                self.assertNotIn('dummy-left',str(caught.exception))
            self.assertEqual(load_config({'TOKEN':'DISCORD_TOKEN'},env={'DISCORD_TOKEN':' \tdummy-normal\n'},filename=Path(temp)/'missing.json')['TOKEN'],'dummy-normal')
