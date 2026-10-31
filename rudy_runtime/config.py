import json
import os
from pathlib import Path

def _read_config_file(filename):
    with filename.open('rb') as stream:
        raw = stream.read(65537)
    if len(raw) > 65536:
        raise ValueError('Configuration file exceeds 64 KiB')
    return json.loads(raw.decode('utf-8-sig'))

def load_config(spec, env=None, filename=None):
    env = os.environ if env is None else env
    selected = filename is None and bool(env.get('RUDY_CONFIG'))
    filename = Path(filename or env.get('RUDY_CONFIG', 'config.json'))
    if selected and not filename.is_file():
        raise ValueError('RUDY_CONFIG must identify an existing regular file')
    data = _read_config_file(filename) if filename.is_file() else {}
    if not isinstance(data, dict):
        raise ValueError('Configuration must be a JSON object')
    config = {key: env.get(variable) or data.get(key, '') for key, variable in spec.items()}
    config = {key: value.strip() if isinstance(value, str) else value for key, value in config.items()}
    controls = [spec[key] for key, value in config.items() if isinstance(value, str) and any(ord(char) < 32 or ord(char) == 127 for char in value)]
    if controls:
        raise ValueError('Invalid control characters in configuration: ' + ', '.join(controls))
    missing = [spec[key] for key, value in config.items() if not isinstance(value, str) or not value.strip() or value.startswith('YOUR_')]
    if missing:
        raise ValueError('Missing configuration: ' + ', '.join(missing))
    return config
