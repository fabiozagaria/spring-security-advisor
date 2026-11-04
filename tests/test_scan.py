import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "plugins" / "spring-security-advisor" / "scripts" / "scan.py"
RULES = ROOT / "plugins" / "spring-security-advisor" / "rules" / "rules.json"
FIXTURES = Path(__file__).resolve().parent / "fixtures"

sys.path.insert(0, str(SCRIPT.parent))
import scan  # noqa: E402


def findings(path):
    return scan.run_scan(Path(path))["findings"]


def ids(path):
    return sorted(f["id"] for f in findings(path))


class Fixtures(unittest.TestCase):
    def test_vulnerable_project_triggers_every_rule(self):
        self.assertEqual(
            ids(FIXTURES / "vulnerable"),
            ["SEC001", "SEC002", "SEC002", "SEC003", "SEC004", "SEC005", "SEC006", "SEC007"],
        )

    def test_fixed_project_has_no_findings(self):
        # Also covers false positives: comments, imports and a test class.
        self.assertEqual(findings(FIXTURES / "fixed"), [])

    def test_stateless_api_only_gets_a_low_csrf_note(self):
        result = findings(FIXTURES / "stateless-api")
        self.assertEqual([f["id"] for f in result], ["SEC005"])
        self.assertEqual(result[0]["severity"], "low")

    def test_test_sources_are_skipped_and_counted(self):
        scope = scan.run_scan(FIXTURES / "fixed")["scope"]
        self.assertEqual(scope["test_files_skipped"], 1)
        self.assertEqual(scope["java_files_analyzed"], 2)

    def test_boot_version_is_detected(self):
        self.assertEqual(scan.run_scan(FIXTURES / "fixed")["detected"]["spring_boot_version"], "3.5.0")


class Sec002(unittest.TestCase):
    def scan_snippet(self, body):
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "src" / "main" / "java"
            src.mkdir(parents=True)
            (src / "C.java").write_text(
                "class C { void f(HttpSecurity http) { http.authorizeHttpRequests(a -> a\n" + body + "); } }"
            )
            return [f for f in findings(tmp) if f["id"] == "SEC002"]

    def test_specific_before_general_is_fine(self):
        body = '.requestMatchers("/api/admin/**").hasRole("ADMIN").requestMatchers("/api/**").authenticated().anyRequest().denyAll()'
        self.assertEqual(self.scan_snippet(body), [])

    def test_general_before_specific_is_reported(self):
        body = '.requestMatchers("/api/**").authenticated().requestMatchers("/api/admin/**").hasRole("ADMIN")'
        self.assertEqual(len(self.scan_snippet(body)), 1)

    def test_catch_all_hides_everything_after_it(self):
        body = '.requestMatchers("/**").authenticated().requestMatchers("/login").permitAll().anyRequest().denyAll()'
        self.assertEqual(len(self.scan_snippet(body)), 2)

    def test_any_request_after_specific_rule_is_the_normal_fallback(self):
        body = '.requestMatchers("/api/public/**").permitAll().anyRequest().authenticated()'
        self.assertEqual(self.scan_snippet(body), [])

    def test_rules_after_any_request_are_reported(self):
        body = ".anyRequest().authenticated().requestMatchers(\"/health\").permitAll()"
        self.assertEqual(len(self.scan_snippet(body)), 1)

    def test_method_restricted_rule_does_not_shadow_other_methods(self):
        body = '.requestMatchers(HttpMethod.GET, "/api/**").permitAll().requestMatchers("/api/admin/**").hasRole("ADMIN")'
        self.assertEqual(self.scan_snippet(body), [])


class Helpers(unittest.TestCase):
    def test_strip_comments_keeps_line_numbers_and_strings(self):
        text = 'a // x\n/* y\nz */ b "// not a comment"\n'
        out = scan.strip_comments(text)
        self.assertEqual(out.count("\n"), text.count("\n"))
        self.assertIn('"// not a comment"', out)
        self.assertNotIn("x", out.replace("// not", ""))

    def test_find_matching_skips_parentheses_in_strings(self):
        text = 'f("a)b", g(1))'
        self.assertEqual(scan.find_matching(text, 1), len(text) - 1)


class Sec007(unittest.TestCase):
    def scan_snippet(self, body):
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "src" / "main" / "java"
            src.mkdir(parents=True)
            (src / "K.java").write_text("class K { Object f() { return " + body + "; } }")
            return [f for f in findings(tmp) if f["id"] == "SEC007"]

    def test_short_literal_hs256_key_is_reported(self):
        result = self.scan_snippet('new SecretKeySpec("short-secret".getBytes(), "HmacSHA256")')
        self.assertEqual(len(result), 1)
        self.assertIn("96 bits", result[0]["detail"])

    def test_32_byte_literal_is_fine(self):
        self.assertEqual(self.scan_snippet('new SecretKeySpec("0123456789abcdef0123456789abcdef".getBytes(), "HmacSHA256")'), [])

    def test_minimum_depends_on_the_algorithm(self):
        key = "0123456789abcdef0123456789abcdef"  # 32 bytes
        self.assertEqual(len(self.scan_snippet(f'new SecretKeySpec("{key}".getBytes(), "HmacSHA512")')), 1)
        self.assertEqual(len(self.scan_snippet(f'Keys.hmacShaKeyFor("{key[:20]}".getBytes(StandardCharsets.UTF_8))')), 1)

    def test_key_from_configuration_is_not_judged(self):
        self.assertEqual(self.scan_snippet('new SecretKeySpec(secret.getBytes(), "HmacSHA256")'), [])


class Catalogue(unittest.TestCase):
    def test_every_rule_has_a_check_and_a_source(self):
        rules = json.loads(RULES.read_text())
        self.assertEqual({r["id"] for r in rules}, set(scan.CHECKS))
        for rule in rules:
            self.assertTrue(rule["source"], rule["id"])
            self.assertIn(rule["status"], {"V", "D"}, rule["id"])

    def test_unverified_rules_are_not_released(self):
        # Release rule from the spec: a rule is not shipped until its source is verified.
        for rule in json.loads(RULES.read_text()):
            self.assertEqual(rule["status"], "V", rule["id"])


class Cli(unittest.TestCase):
    def run_cli(self, *args):
        return subprocess.run([sys.executable, str(SCRIPT), *args], capture_output=True, text=True)

    def test_json_output_and_fail_on(self):
        ok = self.run_cli("scan", str(FIXTURES / "fixed"), "--fail-on", "low")
        self.assertEqual(ok.returncode, 0)
        bad = self.run_cli("scan", str(FIXTURES / "vulnerable"), "--fail-on", "high")
        self.assertEqual(bad.returncode, 1)
        self.assertEqual(json.loads(bad.stdout)["scanner"]["name"], "spring-security-advisor")

    def test_text_format_lists_limits(self):
        out = self.run_cli("scan", str(FIXTURES / "vulnerable"), "--format", "text").stdout
        self.assertIn("[SEC002]", out)
        self.assertIn("Limits:", out)

    def test_missing_directory_is_a_json_error(self):
        result = self.run_cli("scan", "/no/such/dir")
        self.assertEqual(result.returncode, 2)
        self.assertIn("error", json.loads(result.stderr))

    def test_map_lists_components(self):
        data = json.loads(self.run_cli("map", str(FIXTURES / "vulnerable")).stdout)
        self.assertEqual(data["filter_chains"][0]["method"], "api")
        self.assertEqual(data["custom_filters"][0]["class"], "JwtFilter")
        self.assertEqual(data["method_security"]["annotations_used"], 1)


if __name__ == "__main__":
    unittest.main()
