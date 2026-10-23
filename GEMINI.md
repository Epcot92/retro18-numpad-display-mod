# Workspace Rules (`GEMINI.md`)

These guidelines apply to all files and directories within `D:\GEMINI_ANTI`.

## 1. General Coding Principles
- Keep implementations simple, modular, and easy to verify.
- Preserve existing comments, docstrings, and formatting in unrelated code.
- Prefer explicit error handling and clear diagnostic messages over silent failures.

## 2. Project Structure & Conventions
- Place project source code in dedicated directories (e.g., `src/`, `tests/`, `scripts/`).
- Keep workspace-specific agent skills in `.agents/skills/<skill-name>/SKILL.md`.
- Keep bulky reference documentation inside a skill's `references/` folder so it is loaded on demand.

## 3. Verification & Safety
- Run relevant tests or validation scripts after making code changes.
- Do not commit secrets, credentials, or environment-specific `.env` files to version control.
