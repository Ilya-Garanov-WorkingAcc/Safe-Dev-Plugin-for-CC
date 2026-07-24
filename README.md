# Safe_Development

Claude Code plugin: redacts secrets (AWS, GitHub, Stripe, Slack, Google, npm,
JWT, PEM, dotenv assignments, URL credentials, Bearer tokens) from tool output
and blocks/asks on outgoing calls that carry them — **and** enforces a
mandatory test battery every time a hook file is created or edited, blocking
the edit until the battery passes.

Contents:
- `hooks/secret_redactor.py` — PreToolUse (ask on egress with secrets) +
  PostToolUse (redact tool output) hook.
- `hooks/hook_test_runner.py` — PostToolUse meta-hook: after any `Write`/`Edit`/
  `MultiEdit` under a `.claude/hooks/` directory (project or global), runs that
  hook's `<name>.tests.py` battery; blocks (exit 2) on failure.
- `skills/hook-development/` — methodology for writing, testing, and validating
  Claude Code hooks (also usable stand-alone as `/safe-development:hook-development`).

Each hook ships with its own test battery (`hooks/secret_redactor.tests.py`,
`hooks/hook_test_runner.tests.py`) — run manually with `python3 <file>`.

## Install on another account / another computer

Requires Python 3 on PATH. Published at:
https://github.com/Ilya-Garanov-WorkingAcc/Safe-Dev-Plugin-for-CC
(public repo — GitHub does not allow spaces in repo names, so "Safe Dev Plugin
for CC" became the slug `Safe-Dev-Plugin-for-CC`; the plugin's own internal
name, used in install commands below, stays `safe-development` regardless —
that comes from `plugin.json`, not the repo name).

### Option A — install from the published GitHub repo

On the other account/computer, inside Claude Code:

```
/plugin marketplace add Ilya-Garanov-WorkingAcc/Safe-Dev-Plugin-for-CC
/plugin install safe-development@safe-development-marketplace
```

Restart the Claude Code session afterward (hooks load at session start) — or
run `/reload-plugins` if available in your version.

To update later, after pulling new commits into the repo:
```
/plugin marketplace update safe-development-marketplace
/plugin update safe-development@safe-development-marketplace
```

### Option B — copy the folder directly (no GitHub, no publishing)

Copy the whole `safe-development/` directory to the other computer by any
means (USB, scp, zip+email, etc.), then inside Claude Code on that machine:

```
/plugin marketplace add /absolute/path/to/safe-development
/plugin install safe-development@safe-development-marketplace
```

Restart the session afterward.

### Choosing scope

Both options default to **user scope** (applies across all of that user's
projects — equivalent to what was previously hand-installed under
`~/.claude/hooks` + `~/.claude/settings.json` in this session). To scope it to
one project instead:

```
/plugin install safe-development@safe-development-marketplace --scope project
```

### Verify it's working

```
/plugin list
```

should show `safe-development` enabled. Then run, in any project:

```bash
echo "AWS_KEY=AKIAIOSFODNN7EXAMPLE" > /tmp/probe.env
```

and `Read` that file back — you should see `AWS_ACCESS_KEY_ID=[REDACTED:AWS_ACCESS_KEY_ID]`
instead of the real value. Create a throwaway hook under `.claude/hooks/foo.py`
without a `foo.tests.py` next to it — you should get a reminder that a battery
is missing.

## Notes

- Audit log for redactions: `~/.claude/safe-development-audit.log` (fixed
  location, independent of the plugin's cache path so it survives plugin
  updates — plugin files themselves live under
  `~/.claude/plugins/cache/.../` and get replaced/pruned on update).
- No official Anthropic or community marketplace plugin currently covers hook
  development/testing (checked July 2026) — this plugin and its bundled skill
  fill that gap; it's a personal/team plugin, not something published to the
  official marketplace.
- Validate the manifest any time with `claude plugin validate .` from inside
  `safe-development/`.
