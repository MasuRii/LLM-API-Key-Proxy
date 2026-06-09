---
description: 
alwaysApply: true
---

# LLM-API-Key-Proxy — Agent Instructions

## ⚠️ MANDATORY: Read Before Any Code Change

This repository is a **fork** maintained as a linear commit stack on top of `upstream/dev`.

Agents MUST NOT create commits, run autosquash/rebase, or push changes unless the user explicitly requests that git operation. The workflow below documents the repository's preferred git history when git operations are requested.

---

## How the Fork Works

```
upstream/dev
  ├── feat(anthropic): ...        ← one clean commit per feature area
  ├── feat(chutes): ...
  ├── feat(codex): ...
  ├── ... (15 more) ...
  └── feat: add health endpoints  ← HEAD (dev)
```

- `dev` is a **linear stack** of squashed, self-contained commits on `upstream/dev`
- Each commit has a **topic prefix**: `feat(codex):`, `fix(core):`, `feat(tui):`, etc.
- There are **no merge commits** — the history is always flat and linear

### Release Notes

The automated build workflow (`build.yml`) generates release changelogs from
commit messages. It works by comparing topic prefixes between builds — each
topic prefix is treated as a stable feature identifier.

- **New topics** appear in the "What's New" section of the release
- **Renamed topics** show as both "removed" (old name) and "new" (new name) — avoid unless intentional
- **Upstream syncs** are detected and reported when `upstream/dev` advances

---

## Making a Change Without Automatic Git Operations

### Step 1: Identify which commit owns the files you're changing

```bash
git log --oneline upstream/dev..HEAD
```

Match files to commits:

| File Pattern | Owning Commit Prefix |
|-------------|---------------------|
| `providers/<name>_provider.py` | `feat(<name>):` |
| `providers/utilities/<name>_*` | `feat(<name>):` |
| `providers/copilot_*` | `feat(copilot):` |
| `client/rotating_client.py` | `feat(core):` |
| `client/executor.py`, `streaming.py`, `errors.py` | `feat(core):` |
| `client/transforms.py` | `feat(core):` |
| `proxy_app/main.py` | `feat(core):` |
| `proxy_app/quota_viewer.py` | `feat(tui):` |
| `proxy_app/log_viewer.py` | `feat(tui):` |
| `model_alias_registry.py`, `cross_provider_executor.py` | `feat(model-routing):` |
| `error_handler.py`, `error_tracker.py` | `feat(core):` |
| `credential_manager.py`, `credential_tool.py` | `feat(core):` |
| `tests/*` | `feat: add local test suite` |

### Step 2: Lint all changed Python files before completion

**MANDATORY — do not skip this step for Python edits.** Run the following on every `.py` file you touched before reporting completion, and before staging if a commit was explicitly requested:

```bash
# Syntax check (stdlib — zero deps)
uv run python3 -m py_compile src/path/to/file.py

# Undefined names / missing imports / unused imports
uv run ruff check src/path/to/file.py --select F401,F811,F821,E9
```

> This project uses `uv` for environment management. Always prefix `python3` and
> `ruff` commands with `uv run` rather than relying on system-level installations.

The pre-commit hook (`.git/hooks/pre-commit`) also runs these automatically when
a commit is explicitly requested, but running them manually first gives faster feedback.

Common things to verify after a change:
- Every name used in the file is either defined locally or imported.
- No import statements were accidentally deleted while editing.
- `py_compile` exits 0.

### Step 3: Stop unless git operations were explicitly requested

Do not stage, commit, rebase, or push by default. If the user explicitly asks for a commit, use the repository's linear-stack convention:

```bash
# Edit files...
git add -A
git commit -m "fixup! feat(codex): Responses API rewrite, dynamic model discovery, and OAuth exports"
```

> **CRITICAL:** The text after `fixup!` must **exactly match** the first line of the
> target commit. Copy it from `git log --oneline`.

Only run autosquash/rebase or push when the user explicitly requests that operation.

---

## Adding an Entirely New Feature

When the user explicitly requests a commit for an entirely new feature, commit at the tip with a new prefix:

```bash
git add -A
git commit -m "feat(newprovider): add SomeProvider with quota tracking"
```

No fixup needed — new features go at the end of the stack naturally. Do not push unless the user explicitly requests a push.

---

## Upstream Sync

Do not sync upstream automatically. When the user explicitly requests an upstream sync:

```bash
git fetch upstream
git rebase upstream/dev
# Resolve any conflicts in the specific commit that breaks
git push origin dev --force-with-lease
```

Each commit is replayed one at a time. Conflicts are localized to the specific
commit that touched the affected lines — resolve it there and continue. Do not push unless the user explicitly requests a push.

---

## Rules

1. **NEVER stage, commit, rebase, autosquash, or push** unless the user explicitly requests that git operation.

2. **NEVER add raw commits** without a topic prefix. Every commit must be
   `feat(<area>):`, `fix(<area>):`, or `fixup! <exact target commit message>`.

3. **NEVER merge branches into dev.** Dev is a linear rebase-only branch.

4. **Always use `--force-with-lease`** when the user explicitly requests pushing dev (it's a rewritten branch).

5. **One commit per feature area.** If you're fixing something in an existing
   area and the user explicitly requests autosquash, use `fixup!` + autosquash to fold it back in.

6. **Keep the stack ordered.** Independent providers come first, shared
   infrastructure (`core`) in the middle, cross-cutting features (`tui`,
   `model-routing`, `copilot`) at the end.

7. **When a rebase conflict occurs during an explicitly requested autosquash**, stop and resolve it
   carefully. You can always compare with the current file content using
   `git stash` to save your work and inspect.

8. **Always lint Python files before committing.** Run `uv run python3 -m py_compile
   <file>` and `uv run ruff check <file> --select F401,F811,F821,E9` on every file
   you changed. The pre-commit hook enforces this automatically, but treat it
   as a manual checklist item too — catching errors before `git add` is faster
   than fixing a broken deployment.

9. **Keep topic prefixes stable.** The automated release changelog uses commit
   messages as feature identifiers. Renaming a topic prefix (e.g.
   `feat(codex):` → `feat(openai-codex):`) causes the release notes to show
   both a "removed" entry and a "new" entry. If a rename is intentional, do it
   in a single rebase so the changelog shows both sides cleanly.

---

## Quick Reference

```bash
# See the full fork stack
git log --oneline upstream/dev..HEAD

# Find which commit owns a file
git log --oneline upstream/dev..HEAD -- path/to/file.py

# Lint changed Python files before completion; also before git add if committing was requested
uv run python3 -m py_compile src/path/to/file.py
uv run ruff check src/path/to/file.py --select F401,F811,F821,E9

# Commit only when explicitly requested
git commit -m "fixup! <exact commit message from git log>"

# Autosquash/rebase only when explicitly requested
GIT_SEQUENCE_EDITOR=: git rebase -i --autosquash upstream/dev

# Sync with upstream only when explicitly requested
git fetch upstream && git rebase upstream/dev

# Push only when explicitly requested
git push origin dev --force-with-lease
```

## Additional References

- **Local Docker testing** (container info, hot-patching, remote folder structure): `.private/README.md`
