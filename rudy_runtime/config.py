import json
import os
from pathlib import Path

def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('Configuration must not contain duplicate object keys')
        result[key] = value
    return result

def _reject_constant(_value):
    raise ValueError('Configuration must not contain NaN or Infinity')

def _check_nesting(text):
    depth = 0
    quoted = escaped = False
    for char in text:
        if quoted:
            if escaped:
                escaped = False
            elif char == '\\':
                escaped = True
            elif char == '"':
                quoted = False
        elif char == '"':
            quoted = True
        elif char in '{[':
            depth += 1
            if depth > 64:
                raise ValueError('Configuration JSON nesting exceeds 64 levels')
        elif char in '}]':
            depth -= 1

def _read_config_file(filename):
    with filename.open('rb') as stream:
        raw = stream.read(65537)
    if len(raw) > 65536:
        raise ValueError('Configuration file exceeds 64 KiB')
    text = raw.decode('utf-8-sig')
    _check_nesting(text)
    try:
        return json.loads(text, object_pairs_hook=_unique_object, parse_constant=_reject_constant)
    except RecursionError:
        raise ValueError('Configuration JSON nesting is too deep') from None

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
    malformed = [spec[key] for key, value in config.items() if isinstance(value, str) and any(0xD800 <= ord(char) <= 0xDFFF for char in value)]
    if malformed:
        raise ValueError('Invalid Unicode in configuration: ' + ', '.join(malformed))
    missing = [spec[key] for key, value in config.items() if not isinstance(value, str) or not value.strip() or value.startswith('YOUR_')]
    if missing:
        raise ValueError('Missing configuration: ' + ', '.join(missing))
    return config
