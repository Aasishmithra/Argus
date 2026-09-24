# `kotlin-command-injection-detection.yaml` — removed on import

The original file at
`semgrep-master/kotlin/kotlin-command-injection-detection.yaml` failed
Semgrep validation with `Pattern error: Stdlib.Parsing.Parse_error` in
Kotlin. The pattern used `@RequestBody(...) $SOURCE` on a function
parameter — Kotlin requires `paramName: Type` after the annotation, and
Semgrep's Kotlin parser rejects the shorter form.

Rewriting the rule requires a full Kotlin taint spec (spring @RequestBody /
@PathVariable / @RequestParam parameters with typed identifiers). Removed
here to keep the imported pack fully valid. Restore it if you author a
compatible replacement.
