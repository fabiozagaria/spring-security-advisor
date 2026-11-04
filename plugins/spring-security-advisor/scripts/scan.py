#!/usr/bin/env python3
"""Rule-based scanner for Spring Security configuration (servlet stack).

Standard library only. Output is JSON on stdout (or readable text with --format text).
Errors are JSON on stderr with exit code 2.

    scan.py scan <path> [--format json|text] [--fail-on low|medium|high]
    scan.py map  <path>

The scanner matches patterns in source text after stripping comments. It does not
parse Java fully, it does not run the application and it cannot prove that a
project is secure. Heuristic findings say so in their `confidence` field.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

VERSION = "0.2.0"
RULES_FILE = Path(__file__).resolve().parent.parent / "rules" / "rules.json"
SKIP_DIRS = {".git", "target", "build", "node_modules", ".gradle", ".idea", ".mvn", "out"}
SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3}
LIMITS = [
    "Rule-based pattern matching on source text, not a full Java parser.",
    "Does not run the application, resolve dependencies or inspect the network.",
    "Does not prove that a project is secure: absence of findings is not a security guarantee.",
    "Rules were checked against the Spring Security 7.0 reference; older versions can differ.",
]


class ScanError(Exception):
    pass


# --------------------------------------------------------------------------- helpers


def load_rules() -> dict[str, dict]:
    try:
        rules = json.loads(RULES_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ScanError(f"cannot read rules file {RULES_FILE}: {exc}") from exc
    return {rule["id"]: rule for rule in rules}


def strip_comments(text: str) -> str:
    """Blank out // and /* */ comments, keeping strings, offsets and line numbers."""
    out: list[str] = []
    i, n = 0, len(text)
    while i < n:
        two = text[i : i + 2]
        if text.startswith('"""', i):
            end = text.find('"""', i + 3)
            end = n if end == -1 else end + 3
            out.append(text[i:end])
            i = end
        elif text[i] in "\"'":
            quote = text[i]
            j = i + 1
            while j < n and text[j] != quote and text[j] != "\n":
                j += 2 if text[j] == "\\" else 1
            j = min(j + 1, n)
            out.append(text[i:j])
            i = j
        elif two == "//":
            j = text.find("\n", i)
            j = n if j == -1 else j
            out.append(" " * (j - i))
            i = j
        elif two == "/*":
            j = text.find("*/", i + 2)
            j = n if j == -1 else j + 2
            out.append("".join(c if c == "\n" else " " for c in text[i:j]))
            i = j
        else:
            out.append(text[i])
            i += 1
    return "".join(out)


def find_matching(text: str, open_idx: int) -> int:
    """Index of the parenthesis closing the one at open_idx (or end of text)."""
    depth, i, n = 0, open_idx, len(text)
    while i < n:
        c = text[i]
        if c in "\"'":
            j = i + 1
            while j < n and text[j] != c and text[j] != "\n":
                j += 2 if text[j] == "\\" else 1
            i = j
        elif c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return n


def line_of(text: str, pos: int) -> int:
    return text.count("\n", 0, pos) + 1


def is_test_path(path: Path, root: Path) -> bool:
    parts = path.relative_to(root).parts
    return any(p in ("test", "tests", "it", "integrationTest") for p in parts[:-1]) or path.name.endswith(
        ("Test.java", "Tests.java", "IT.java")
    )


class Project:
    def __init__(self, root: Path):
        if not root.is_dir():
            raise ScanError(f"not a directory: {root}")
        self.root = root.resolve()
        self.java: list[tuple[Path, str]] = []  # (path, comment-free text), main code only
        self.counts = {"java": 0, "java_test_skipped": 0, "config": 0, "build": 0}
        self.boot_version: str | None = None
        self._load()

    def _load(self) -> None:
        for path in sorted(self.root.rglob("*")):
            if not path.is_file() or any(p in SKIP_DIRS for p in path.relative_to(self.root).parts):
                continue
            name = path.name
            try:
                if name.endswith(".java"):
                    if is_test_path(path, self.root):
                        self.counts["java_test_skipped"] += 1
                        continue
                    self.java.append((path, strip_comments(path.read_text(encoding="utf-8", errors="replace"))))
                    self.counts["java"] += 1
                elif name == "pom.xml" or name.startswith("build.gradle"):
                    self.counts["build"] += 1
                    self._read_build(path.read_text(encoding="utf-8", errors="replace"))
                elif re.fullmatch(r"application.*\.(ya?ml|properties)", name):
                    self.counts["config"] += 1
            except OSError:
                continue

    def _read_build(self, text: str) -> None:
        patterns = [
            r"spring-boot-starter-parent\s*</artifactId>\s*<version>\s*([^<\s]+)",
            r"org\.springframework\.boot['\"]\)?\s*version\s*['\"]([^'\"]+)",
        ]
        for pattern in patterns:
            match = re.search(pattern, text)
            if match and not self.boot_version:
                self.boot_version = match.group(1)

    def rel(self, path: Path) -> str:
        return path.relative_to(self.root).as_posix()

    def grep(self, pattern: str, skip_imports: bool = True):
        """Yield (path, text, match, line) for each match in main Java code."""
        regex = re.compile(pattern)
        for path, text in self.java:
            for match in regex.finditer(text):
                line_start = text.rfind("\n", 0, match.start()) + 1
                line_end = text.find("\n", match.start())
                line_text = text[line_start : len(text) if line_end == -1 else line_end]
                if skip_imports and line_text.lstrip().startswith(("import ", "package ")):
                    continue
                yield path, text, match, line_of(text, match.start())


# --------------------------------------------------------------------------- checks


def make_finding(rules, rule_id, project, path, line, detail, confidence="high", severity=None):
    rule = rules[rule_id]
    return {
        "id": rule_id,
        "severity": severity or rule["severity"],
        "title": rule["title"],
        "file": project.rel(path) if path else None,
        "line": line,
        "detail": detail,
        "risk": rule["risk"],
        "fix": rule["fix"],
        "source": f'{rule["source"]} (checked {rule["checked"]})',
        "type": rule["type"],
        "confidence": confidence,
    }


def check_sec001(project, rules):
    for path, _text, _match, line in project.grep(r"\bNoOpPasswordEncoder\b"):
        yield make_finding(rules, "SEC001", project, path, line, "NoOpPasswordEncoder is used.")


def _matcher_info(args: str):
    """(patterns, restricted_by_method) from the argument text of a matcher call."""
    patterns = re.findall(r'"([^"]*)"', args)
    restricted = bool(re.search(r"HttpMethod|\bGET\b|\bPOST\b|\bPUT\b|\bDELETE\b|\bPATCH\b", args))
    return patterns, restricted


def _covers(general: str, specific: str) -> bool:
    if general == specific:
        return True
    if general.endswith("/**"):
        prefix = general[:-3]
        return specific.startswith(prefix + "/") or specific == prefix or prefix == ""
    return False


def check_sec002(project, rules):
    call = re.compile(r"\.(requestMatchers|antMatchers|mvcMatchers|anyRequest)\s*\(")
    for path, text in project.java:
        for chain in re.finditer(r"\.authorizeHttpRequests\s*\(", text):
            open_idx = chain.end() - 1
            body_start, body_end = open_idx + 1, find_matching(text, open_idx)
            body = text[body_start:body_end]
            seen: list[tuple[str, list[str]]] = []  # unrestricted rules so far: (kind, patterns)
            for m in call.finditer(body):
                kind = m.group(1)
                args = body[m.end() : find_matching(body, m.end() - 1)]
                line = line_of(text, body_start + m.start())
                patterns, restricted = _matcher_info(args) if kind != "anyRequest" else (["*"], False)
                if kind != "anyRequest" and not patterns:
                    continue  # matcher built from an object: cannot reason about it
                blocker = None
                for prev_kind, prev_patterns in seen:
                    if prev_kind == "anyRequest":
                        blocker = "anyRequest()"
                    else:
                        for prev in prev_patterns:
                            # anyRequest() is the fallback: only a catch-all or another anyRequest() hides it.
                            hit = prev == "/**" if kind == "anyRequest" else any(_covers(prev, p) for p in patterns)
                            if hit:
                                blocker = f'"{prev}"'
                                break
                    if blocker:
                        break
                if blocker:
                    target = "anyRequest()" if kind == "anyRequest" else ", ".join(f'"{p}"' for p in patterns)
                    yield make_finding(
                        rules,
                        "SEC002",
                        project,
                        path,
                        line,
                        f"{target} is unreachable: the earlier rule {blocker} already matches those requests.",
                    )
                if not restricted:
                    seen.append((kind, patterns))


ANNOTATIONS = r"@(?:PreAuthorize|PostAuthorize|PreFilter|PostFilter)\b"


def check_sec003(project, rules):
    enabled = False
    for _p, _t, match, _l in project.grep(r"@EnableMethodSecurity\b(?:\s*\(([^)]*)\))?"):
        if not re.search(r"prePostEnabled\s*=\s*false", match.group(1) or ""):
            enabled = True
    for _p, _t, match, _l in project.grep(r"@EnableGlobalMethodSecurity\s*\(([^)]*)\)"):
        if re.search(r"prePostEnabled\s*=\s*true", match.group(1)):
            enabled = True
    if enabled:
        return
    first = next(iter(project.grep(ANNOTATIONS)), None)
    if first:
        path, _text, match, line = first
        yield make_finding(
            rules,
            "SEC003",
            project,
            path,
            line,
            f"{match.group(0)} is used but no @EnableMethodSecurity (or @EnableGlobalMethodSecurity(prePostEnabled = true)) was found in the project.",
        )


def check_sec004(project, rules):
    for path, _text, _match, line in project.grep(r"@EnableGlobalMethodSecurity\b"):
        yield make_finding(rules, "SEC004", project, path, line, "@EnableGlobalMethodSecurity is deprecated.")


CSRF_DISABLE = re.compile(
    r"\.csrf\s*\(\s*\)\s*\.\s*disable\s*\(\s*\)"
    r"|\.csrf\s*\(\s*(\w+)\s*->\s*\1\s*\.\s*disable\s*\(\s*\)\s*\)"
    r"|\.csrf\s*\(\s*AbstractHttpConfigurer\s*::\s*disable\s*\)"
    r"|\.csrf\s*\(\s*\(\s*(\w+)\s*\)\s*->\s*\2\s*\.\s*disable\s*\(\s*\)\s*\)"
)


def check_sec005(project, rules):
    for path, text, _match, line in project.grep(CSRF_DISABLE.pattern):
        stateless = "SessionCreationPolicy.STATELESS" in text
        if stateless:
            yield make_finding(
                rules,
                "SEC005",
                project,
                path,
                line,
                "CSRF is disabled and the same file sets a STATELESS session policy: reasonable for a token-only API, but confirm that no cookie-based authentication is used.",
                confidence="medium",
                severity="low",
            )
        else:
            yield make_finding(
                rules,
                "SEC005",
                project,
                path,
                line,
                "CSRF is disabled and no STATELESS session policy was found in the same file.",
                confidence="medium",
            )


TOKEN_HINTS = re.compile(r'"Bearer |oauth2ResourceServer|\bJwtDecoder\b|\bJwts\.|NimbusJwt|BearerTokenAuthentication')


def check_sec006(project, rules):
    if not any(TOKEN_HINTS.search(text) for _p, text in project.java):
        return
    for path, text in project.java:
        if "SecurityFilterChain" not in text or "@Bean" not in text:
            continue
        if "SessionCreationPolicy.STATELESS" in text:
            continue
        bean = re.search(r"SecurityFilterChain\s+\w+\s*\(", text)
        if bean:
            yield make_finding(
                rules,
                "SEC006",
                project,
                path,
                line_of(text, bean.start()),
                "Token-based authentication was detected in the project, but this SecurityFilterChain does not set SessionCreationPolicy.STATELESS.",
                confidence="medium",
            )


# Minimum HMAC key size in bytes: RFC 7518 section 3.2 (256, 384, 512 bits).
HMAC_MIN_BYTES = {"HmacSHA256": 32, "HmacSHA384": 48, "HmacSHA512": 64}
SECRET_KEY_SPEC = re.compile(
    r'new\s+SecretKeySpec\(\s*"((?:[^"\\\n]|\\.)*)"\s*\.getBytes\([^)]*\)\s*,\s*"(HmacSHA(?:256|384|512))"'
)
JJWT_HMAC_KEY = re.compile(r'Keys\.hmacShaKeyFor\(\s*"((?:[^"\\\n]|\\.)*)"\s*\.getBytes\([^)]*\)\s*\)')


def check_sec007(project, rules):
    """HMAC key built from a string literal that is shorter than the algorithm minimum."""
    for regex, algorithm_group in ((SECRET_KEY_SPEC, 2), (JJWT_HMAC_KEY, None)):
        for path, text, match, line in project.grep(regex.pattern):
            literal = match.group(1)
            if "\\" in literal:
                continue  # escapes: the byte length is not obvious, stay silent
            algorithm = match.group(algorithm_group) if algorithm_group else "HmacSHA256"
            needed = HMAC_MIN_BYTES[algorithm]
            size = len(literal.encode("utf-8"))
            if size < needed:
                yield make_finding(
                    rules,
                    "SEC007",
                    project,
                    path,
                    line,
                    f"The {algorithm} key is a string literal of {size} bytes ({size * 8} bits); the minimum is {needed * 8} bits.",
                )


CHECKS = {
    "SEC001": check_sec001,
    "SEC002": check_sec002,
    "SEC003": check_sec003,
    "SEC004": check_sec004,
    "SEC005": check_sec005,
    "SEC006": check_sec006,
    "SEC007": check_sec007,
}


# --------------------------------------------------------------------------- commands


def run_scan(root: Path) -> dict:
    rules = load_rules()
    project = Project(root)
    findings: list[dict] = []
    for rule_id, check in CHECKS.items():
        findings.extend(check(project, rules))
    findings.sort(key=lambda f: (-SEVERITY_ORDER[f["severity"]], f["id"], f["file"] or "", f["line"] or 0))
    notes = []
    if project.boot_version and project.boot_version.split(".")[0].isdigit() and int(project.boot_version.split(".")[0]) < 3:
        notes.append(
            f"Spring Boot {project.boot_version} detected: the rules assume the SecurityFilterChain and lambda DSL style, results may be incomplete."
        )
    if not project.java:
        notes.append("No Java sources found: nothing was analyzed.")
    return {
        "scanner": {"name": "spring-security-advisor", "version": VERSION},
        "root": str(project.root),
        "detected": {"spring_boot_version": project.boot_version},
        "scope": {
            "java_files_analyzed": project.counts["java"],
            "test_files_skipped": project.counts["java_test_skipped"],
            "config_files_seen": project.counts["config"],
            "rules_run": list(CHECKS),
        },
        "findings": findings,
        "notes": notes,
        "limits": LIMITS,
    }


def run_map(root: Path) -> dict:
    project = Project(root)

    def where(pattern: str):
        return [{"file": project.rel(p), "line": ln, "text": m.group(0).strip()} for p, _t, m, ln in project.grep(pattern)]

    chains = []
    for path, text in project.java:
        for m in re.finditer(r"SecurityFilterChain\s+(\w+)\s*\(", text):
            head = text[max(0, m.start() - 300) : m.start()]
            order = re.search(r"@Order\s*\(([^)]*)\)", head)
            chains.append(
                {
                    "file": project.rel(path),
                    "line": line_of(text, m.start()),
                    "method": m.group(1),
                    "order": order.group(1).strip() if order else None,
                    "stateless": "SessionCreationPolicy.STATELESS" in text,
                    "csrf_disabled": bool(CSRF_DISABLE.search(text)),
                }
            )
    filters = []
    for path, text in project.java:
        for m in re.finditer(r"class\s+(\w+)\s+extends\s+(OncePerRequestFilter|GenericFilterBean|AbstractAuthenticationProcessingFilter|BasicAuthenticationFilter)", text):
            filters.append({"file": project.rel(path), "line": line_of(text, m.start()), "class": m.group(1), "extends": m.group(2)})
    registrations = where(r"\.add(?:Filter|FilterBefore|FilterAfter|FilterAt)\s*\([^;]*")
    return {
        "scanner": {"name": "spring-security-advisor", "version": VERSION},
        "root": str(project.root),
        "detected": {"spring_boot_version": project.boot_version},
        "filter_chains": chains,
        "custom_filters": filters,
        "filter_registrations": registrations,
        "authentication_manager": where(r"\bAuthenticationManager\b[^;{]*"),
        "authentication_providers": where(r"\b(?:implements|extends)\s+[\w\s,<>]*\bAuthenticationProvider\b|\bDaoAuthenticationProvider\b"),
        "user_details_services": where(r"\bUserDetailsService\b[^;{]*"),
        "password_encoders": where(r"\bPasswordEncoder\b[^;{]*|\bBCryptPasswordEncoder\b|\bNoOpPasswordEncoder\b"),
        "method_security": {
            "enable": where(r"@Enable(?:Global)?MethodSecurity\b"),
            "annotations_used": len(list(project.grep(ANNOTATIONS + r"|@Secured\b|@RolesAllowed\b"))),
        },
        "auth_rules": where(r"\.(?:requestMatchers|antMatchers|mvcMatchers|anyRequest)\s*\([^)]*\)\s*\.\s*\w+(?:\([^)]*\))?"),
        "limits": LIMITS,
    }


def format_text(report: dict) -> str:
    lines = []
    scope = report["scope"]
    lines.append(f'spring-security-advisor {VERSION}: {scope["java_files_analyzed"]} Java files analyzed ({scope["test_files_skipped"]} test files skipped)')
    for note in report["notes"]:
        lines.append(f"note: {note}")
    if not report["findings"]:
        lines.append("No findings from the rules that were run.")
    for f in report["findings"]:
        lines.append("")
        lines.append(f'[{f["id"]}] {f["severity"]}: {f["title"]}')
        lines.append(f'Where: {f["file"]}:{f["line"]}')
        lines.append(f'Detail: {f["detail"]}')
        lines.append(f'Risk: {f["risk"]}')
        lines.append(f'Suggested fix: {f["fix"]}')
        lines.append(f'Source: {f["source"]}')
        lines.append(f'Type: {f["type"]} | Confidence: {f["confidence"]}')
    lines.append("")
    lines.append("Limits:")
    lines.extend(f"- {item}" for item in report["limits"])
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    scan = sub.add_parser("scan", help="run the security rules")
    scan.add_argument("path")
    scan.add_argument("--format", choices=["json", "text"], default="json")
    scan.add_argument("--fail-on", choices=list(SEVERITY_ORDER), help="exit 1 if a finding at or above this severity exists")
    mapping = sub.add_parser("map", help="inventory of security components")
    mapping.add_argument("path")
    args = parser.parse_args(argv)
    try:
        if args.command == "scan":
            report = run_scan(Path(args.path))
            print(format_text(report) if args.format == "text" else json.dumps(report, indent=2))
            if args.fail_on and any(SEVERITY_ORDER[f["severity"]] >= SEVERITY_ORDER[args.fail_on] for f in report["findings"]):
                return 1
        else:
            print(json.dumps(run_map(Path(args.path)), indent=2))
    except ScanError as exc:
        print(json.dumps({"error": str(exc)}), file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
