# Configuration reference

Environment values take priority over local file values. Configuration files are bounded to 64 KiB and must contain a UTF-8 JSON object; an initial UTF-8 BOM is supported. Validation uses no network credentials or external service calls.

## Explicit file selection

A nonempty `RUDY_CONFIG` selects an existing regular JSON file. Missing or non-file selections are errors even when environment credentials are complete. A programmatic filename override takes precedence. The optional default file may be absent when environment settings supply the required values.
