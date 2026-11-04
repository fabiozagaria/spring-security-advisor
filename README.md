# spring-security-advisor

[![tests](https://github.com/fabiozagaria/spring-security-advisor/actions/workflows/test.yml/badge.svg)](https://github.com/fabiozagaria/spring-security-advisor/actions/workflows/test.yml)

A Spring Security review and map for [Claude Code](https://claude.com/claude-code), built for developers who want to understand their setup, not just have it rewritten.

A small, tested Python scanner finds **known configuration mistakes** and prints reproducible results. The skills then read the flagged code, drop false positives and explain each risk with a fix and an official source. The model reasons and explains; the script checks.

> Early version (0.1). It covers the servlet stack and six rules. It is not a vulnerability scanner for dependencies and it cannot prove that a project is secure.

## What it does

| Skill | What it does |
|---|---|
| `/spring-security-advisor:review` | Runs the scanner, verifies each finding in the code, and reports risk, fix, source and confidence. Read-only. |
| `/spring-security-advisor:map` | Maps the filter chains, custom filters, providers, encoders, method security and authorization rules that really exist in your project, and how a request flows through them. Read-only. |

Planned next: `advise` (choosing between sessions, your own JWT, an OAuth2 resource server or an identity provider) and `apply` (one change at a time, with a diff and your confirmation). See the roadmap below.

## Rules (0.1)

Each rule was checked against the Spring Security 7.0 reference; the source is printed in every finding.

| ID | Severity | What it looks for |
|---|---|---|
| SEC001 | high | `NoOpPasswordEncoder` in production code |
| SEC002 | high | An authorization rule that can never be reached because an earlier one already matches |
| SEC003 | medium | `@PreAuthorize` and friends used without `@EnableMethodSecurity` |
| SEC004 | low | Deprecated `@EnableGlobalMethodSecurity` |
| SEC005 | medium / low | CSRF disabled (low when the same file sets a stateless session policy) |
| SEC006 | medium | Token-based authentication without an explicit `SessionCreationPolicy.STATELESS` (heuristic) |

Findings carry a type (certain bug, risk to evaluate, improvement) and a confidence (high, or medium for heuristics). Comments, imports and test sources are not reported.

## Install

```bash
claude plugin marketplace add fabiozagaria/spring-security-advisor
claude plugin install spring-security-advisor@spring-security-advisor
```

For local development: `claude --plugin-dir ./plugins/spring-security-advisor`.

## The scanner

`plugins/spring-security-advisor/scripts/scan.py` is a standalone CLI (Python 3, standard library only). It works without Maven or a JDK, reads source files only and makes no network calls.

```bash
python3 scripts/scan.py scan path/to/project              # JSON
python3 scripts/scan.py scan path/to/project --format text
python3 scripts/scan.py scan path/to/project --fail-on high   # exit 1 for CI
python3 scripts/scan.py map  path/to/project
```

## Limits

- Pattern matching on source text, not a full Java parser: unusual code styles can be missed or misread.
- It does not run your application, resolve dependencies or inspect infrastructure.
- No findings means "none of these rules matched", not "secure".
- Rules follow the Spring Security 7.0 reference; behavior in older versions can differ. The scanner warns when it detects Spring Boot 2.x.

## Roadmap

- **0.2**: more rules (JWT secret handling, key length, algorithm and expiry checks, filter error handling), each added only with a cited source; `advise` skill.
- **0.3**: `apply` skill with diff and confirmation.
- **Later**: login rate limiting and refresh-token heuristics, Gradle Kotlin support, a more precise Java-based scanner.

## Tests

```bash
python3 -m unittest discover -s tests
```

The tests run the scanner on three fixture projects (`vulnerable`, `fixed`, `stateless-api`) and check, among others, that the fixed project produces no findings.

## License

MIT
