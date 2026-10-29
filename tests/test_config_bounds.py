import json
import tempfile
import unittest
from pathlib import Path
from rudy_runtime.config import load_config

class BoundedConfigTests(unittest.TestCase):
    def test_byte_boundary_and_invalid_utf8(self):
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp)/'config.json'
            body=json.dumps({'TOKEN':'dummy'}).encode('utf-8')
            path.write_bytes(body+b' '*(65536-len(body)))
            self.assertEqual(load_config({'TOKEN':'DISCORD_TOKEN'},env={},filename=path)['TOKEN'],'dummy')
            for raw in (body+b' '*(65537-len(body)),json.dumps({'TOKEN':'\u00e9'*32768},ensure_ascii=False).encode('utf-8')):
                path.write_bytes(raw)
                with self.assertRaisesRegex(ValueError,'exceeds 64 KiB'):
                    load_config({'TOKEN':'DISCORD_TOKEN'},env={},filename=path)
            path.write_bytes(b'{"TOKEN":"\xff"}')
            with self.assertRaises(UnicodeDecodeError):
                load_config({'TOKEN':'DISCORD_TOKEN'},env={},filename=path)
