---
name: map
description: Maps the security components of a Spring Boot project (filter chains, custom filters, authentication providers, password encoders, method security, authorization rules) and explains how a request flows through them. Use when the user wants to understand or document how security is wired in their project, or asks "how does a request go through my security configuration".
---

# map

Read-only. Describes the project as it is, from its real code.

```
SCAN="python3 ${CLAUDE_PLUGIN_ROOT}/scripts/scan.py"
```

## Steps

1. Find the project root and run `$SCAN map <root>`.
2. Build the map from the JSON and from reading the listed files:
   - each `SecurityFilterChain` (file, `@Order`, stateless or not, CSRF on or off) and which requests it covers;
   - custom filters and where they are registered in the chain (`addFilterBefore`, `addFilterAfter`);
   - `AuthenticationManager`, `AuthenticationProvider`, `UserDetailsService`, `PasswordEncoder` beans that actually exist;
   - whether method security is enabled and how many annotations rely on it;
   - the authorization rules in the order they are evaluated (first match wins).
3. Draw the path of one request as a short text diagram, for example:
   `request -> filter A -> filter B -> authorization rules -> controller (@PreAuthorize)`.
   Use only components found in the project.
4. Where an expected component is missing (for example no `PasswordEncoder` bean while users are stored), write it as a **question** to the developer, not as an error. The Spring Boot defaults may be doing the work.
5. Explain each component in one sentence: what it does and why it exists. The goal is that the developer understands their setup, not just a list.
6. End with *Not covered* and *Limits*. The map comes from pattern matching and can miss components created in unusual ways.

## Rules

- Do not edit files.
- Do not describe components that were not found.
- For design advice (JWT vs sessions vs OAuth2) say that it belongs to a design discussion and offer to discuss it; do not decide for the user.
