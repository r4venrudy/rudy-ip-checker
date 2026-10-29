import json
import os
from pathlib import Path

def load_config(spec, env=None, filename=None):
    env = os.environ if env is None else env
    filename = Path(filename or env.get('RUDY_CONFIG', 'config.json'))
    data = json.loads(filename.read_text(encoding='utf-8-sig')) if filename.is_file() else {}
    if not isinstance(data, dict):
        raise ValueError('Configuration must be a JSON object')
    config = {key: env.get(variable) or data.get(key, '') for key, variable in spec.items()}
    config = {key: value.strip() if isinstance(value, str) else value for key, value in config.items()}
    missing = [spec[key] for key, value in config.items() if not isinstance(value, str) or not value.strip() or value.startswith('YOUR_')]
    if missing:
        raise ValueError('Missing configuration: ' + ', '.join(missing))
    return config
