# Changelog

## 0.2.0
- Rule SEC007: HMAC JWT signing key built from a string literal shorter than the algorithm minimum (RFC 7518 section 3.2).
- README: example output and a Windows note about Python.

## 0.1.1
- Skills find a working Python 3 (`python3`, `python` or `py`) instead of assuming `python3`, which on Windows is often a non-working Store stub. They stop with a clear message if none is found.

## 0.1.0
- Scanner (`scan.py scan` and `scan.py map`), Python standard library only.
- Rules SEC001 to SEC006, each checked against the Spring Security 7.0 reference.
- Skills `review` and `map`.
- Fixtures, tests and CI.
