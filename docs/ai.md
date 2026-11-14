# AI analysis layer

NXT-Security can use an AI model to help analyze findings. Two rules govern it:

1. **AI is advisory, never authoritative.** It annotates findings and writes
   summaries; it never creates a finding, changes a severity, or changes a
   status. A human always decides. `ai analyze --annotate` attaches the output
   as a note — the finding itself is untouched.
2. **No provider is hard-coded, and keys live only in the environment.**
   `ai.provider` selects the adapter; API keys are read from environment
   variables (never from `config.yaml`), and every finding is **redacted before
   it is sent** to any provider, so secrets never leave the process.

## Providers

| `ai.provider` | Adapter | Key | Notes |
|---|---|---|---|
| `offline` (default) | built-in deterministic analyzer | none | No network, no key, no package. Always works. |
| `claude` | Anthropic Claude (`anthropic` SDK) | `ANTHROPIC_API_KEY` | Default model `claude-opus-5-5`; set `ai.model` to change. |
| `openai` | OpenAI Chat Completions (`openai` SDK) | `OPENAI_API_KEY` | Set `ai.model` (default `gpt-4o-mini`). |
| `local` | OpenAI-compatible local server | usually none | Defaults `ai.base_url` to Ollama (`http://localhost:11434/v1`). |

Install the optional SDK for a remote provider: `pip install -e ".[claude]"` or
`.[openai]`. An unconfigured or unavailable provider degrades to a clear
"not ready" status rather than breaking the platform.

## Commands

```sh
nxtsec ai status                         # which provider, and is it ready
nxtsec ai analyze <finding-id>           # risk, true/false-positive view, remediation
nxtsec ai analyze <finding-id> --annotate  # also attach the analysis as a finding note
nxtsec ai summarize [--open] [--min-severity HIGH]   # short prioritized summary
```

## Configuration

```yaml
ai:
  provider: offline           # offline | claude | openai | local
  model: null                 # provider default if null
  base_url: null              # for local / OpenAI-compatible servers
  api_key_env: OPENAI_API_KEY # NAME of the env var holding the key (never the key)
```

Every AI call is written to the audit log (`ai.analyze`, `ai.summarize`) with
the provider and model used.
