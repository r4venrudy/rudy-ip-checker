# Configuration reference

Environment values take priority over local file values. Configuration files are bounded to 64 KiB and must contain a UTF-8 JSON object; an initial UTF-8 BOM is supported. Validation uses no network credentials or external service calls.

## Explicit file selection

A nonempty `RUDY_CONFIG` selects an existing regular JSON file. Missing or non-file selections are errors even when environment credentials are complete. A programmatic filename override takes precedence. The optional default file may be absent when environment settings supply the required values.

## Credential text

After trimming surrounding whitespace, embedded C0 control characters and DEL are rejected in required settings before client initialization. Diagnostics identify setting names without echoing credential values.

## Unicode integrity

Required setting values reject unpaired UTF-16 surrogate code points. Valid Unicode, including supplementary characters, is retained unchanged; the loader does not silently replace malformed credential text.

## Unambiguous JSON

Object keys must be unique at every nesting level, including escaped spellings of the same key. Non-JSON NaN/Infinity constants are rejected. Separate objects may still reuse ordinary key names. These errors do not print key values or modify the file.

## Nesting budget

JSON containers are limited to 64 levels, counting the root object. Brackets and escaped quotes inside strings do not consume depth. Over-budget documents raise a configuration ValueError before JSON decoding. The 64 KiB byte cap remains independent.

## Placeholder labels

Example labels beginning with YOUR_, DISCORD TOKEN or YOUR CLIENT are rejected case-insensitively. Missing-setting diagnostics identify the environment variable without echoing its value. A non-placeholder value still needs valid credentials supplied by its owner.
