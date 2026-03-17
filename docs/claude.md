# Integrating pii with Claude Code

Automatically redact PDFs before Claude reads them — using a Claude Code [PreToolUse hook](https://docs.anthropic.com/en/docs/claude-code/hooks).

Whenever Claude tries to read a `.pdf` file, the hook intercepts the call, runs `pii redact`, and redirects Claude to the redacted copy. The original file is never seen by the model.

## Setup

Add to `~/.claude/settings.json`:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Read",
        "hooks": [
          {
            "type": "command",
            "command": "pii claude"
          }
        ]
      }
    ]
  }
}
```

## Notes

- Only `.pdf` files are affected — all other file reads pass through unchanged.
- Redacted files are stored in `/tmp/piibyebye/`, keyed by a hash of the original. They are cleaned up automatically by the OS and never clutter your project directory.
- The same PDF is only redacted once per session — subsequent reads reuse the cached copy.
- Only text-based PDFs are supported; scanned documents are passed through unchanged.
