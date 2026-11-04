---
name: review
description: Security code review for Spring Security (servlet stack). Runs a rule-based scanner, then reads the flagged code, removes false positives and explains each risk with a fix and an official source. Use when the user asks to review, audit or check the security of a Spring Boot project, a SecurityFilterChain, JWT or method-security setup.
---

# review

Read-only. This skill never edits the project.

```
PY=$(for c in python3 python py; do "$c" -c "import sys; sys.exit(sys.version_info[0] != 3)" 2>/dev/null && { echo "$c"; break; }; done)
SCAN="$PY ${CLAUDE_PLUGIN_ROOT}/scripts/scan.py"
```

If `$PY` is empty, no working Python 3 was found (on Windows `python3` is often a Microsoft Store stub that does not run). Tell the user to install Python 3 and stop; do not work around it.

## Steps

1. **Find the project root** (the directory with `pom.xml` or `build.gradle`). If unclear, ask once.
2. **Run the scanner:** `$SCAN scan <root>` (JSON). Note `detected.spring_boot_version`, `scope` and `notes`. If the Boot version is below 3, say the rules assume the `SecurityFilterChain` lambda style and results may be incomplete.
3. **Verify every finding by reading the code** around `file:line`. Drop findings that are false positives and say why in one line. Do not invent findings the scanner did not report; if you notice something else while reading, label it clearly as "observed while reading, not from a rule".
4. **Report** each finding in this format, most severe first:

```
[SEC003] medium — Method security is not enabled
Where: path/File.java:42
Risk: ...
Suggested fix: ...
Source: ...
Type: certain bug | risk to evaluate | improvement | style
Confidence: high | medium (heuristic)
```

   - Use the scanner's `type` and `confidence`. Heuristic findings (`confidence: medium`) are "risk to evaluate", never "certain bug".
   - Explain the *why* in plain words and, when it helps, a short before/after snippet. The developer decides; do not push a single "right" architecture.
5. **If there are no findings,** say so plainly and do not invent criticisms.
6. **Always end with** *Scope* (files analyzed, rules run), *Not covered* (dependencies, runtime behavior, infrastructure, secrets handling) and *Limits* (from the scanner output).

## Rules

- Never claim the project is "secure". The scanner finds known patterns, nothing more.
- Distinguish certain bugs, risks to evaluate, optional improvements and style preferences.
- Never print secrets found in the code; point to the file and line only.
- To change anything, the user has to ask explicitly; then make one small change at a time and re-run the scanner.
- If the scanner returns an error, show the message and fix the input; do not work around it.
