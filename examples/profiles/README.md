# Configured analyzers

Copy a profile and replace repository paths, component roots, decision documents, and executable paths. Paths resolve relative to the profile file. `report_dir` and `--run-dir` must be outside the audited checkout and filtered snapshot. Enroll only repositories and commands you trust.

The examples require existing installations. They do not install tools, discover package scripts, run `npx`, or choose a model. The default analyzer PATH is the operating system default, HOME and TMPDIR are temporary directories, and all other inherited environment variables are removed. Use absolute executable paths for virtual environments and JavaScript runtimes. Commands that require environment configuration should use a reviewed wrapper that supplies only the required nonsecret values. No agent or publisher credentials belong in command arrays or wrappers.

Each configured analyzer starts in its own disposable copy of the filtered committed source. Installed dependencies, generated outputs, ignored files, Git metadata, and excluded credentials are absent from that copy. An installed executable may still use its own external installation directory. Tools that need repository-local packages or generated files require an explicitly configured trusted environment or wrapper. The auditor does not prepare one automatically. Commands with absolute host paths can access the host as the current user. This execution path supports trusted local tools and does not isolate hostile code.

Analyzer `cwd` is relative to the execution root. Optional `artifact` is relative to that cwd; otherwise stdout is parsed. Paths cannot traverse outside the copy, and artifact paths are rechecked after execution. Only explicit `version_command` arrays run version checks. Their output, exit code, and timing remain in the version object. No `--version` invocation is inferred.

`timeout_seconds` defaults to 300 and must be at most 86400. `max_output_bytes` defaults to 1048576 and must be at most 67108864. Stdout and stderr share this byte limit; a configured report artifact has a separate limit of the same size. Overflow and timeout terminate the process group. Captured bytes have a SHA-256 digest. A truncated digest covers the stored prefix, not the full original stream. The process group is also terminated when the command ends so background descendants cannot continue in the disposable copy. Processes that deliberately escape the process group are outside the trusted-command boundary.

`pass_exit_codes` defaults to `[0]`, and `finding_exit_codes` defaults to `[1]`. These lists cannot overlap. Other exits are check failures. Execution status and parser status are separate. An exit of zero with malformed JSON remains a parser error and makes collection incomplete. Missing executables, timeout, overflow, unsupported platforms, and unconfigured categories are explicit outcomes. The standard capability categories are `lint`, `typecheck`, `tests`, `dependencies`, and `unused`; custom category names are preserved.

## Report subsets

- `text` retains bounded raw evidence and has parser status `unstructured`.
- `json` validates JSON syntax and retains bounded raw evidence without inferring diagnostics.
- `eslint` accepts the native array of file results and messages, including nullable rule IDs and optional positions. Suppressed messages and fixes remain raw evidence.
- `ruff` accepts the native message array with filename, code, message, location, and end_location. Missing positions are null. Notebook cell metadata remains in the raw report.
- `knip` accepts the pinned 5.46.0 top-level files/issue-row shape and the newer issue-row files shape. Named entries, nested duplicate/cycle arrays, and historical member maps become advisory diagnostics. Unused reports require investigation of dynamic entry points and configuration before asserting that code is obsolete.
- `sarif` accepts version 2.1.0 inline runs/results with text messages, explicit local artifact URIs, and physical regions. External properties, URI fetching, artifact indexes, and uriBaseId resolution are unsupported. A location outside the execution root is a parser error.
- `junit` accepts testsuite/testsuites roots and nested testcase elements. Failure and error children become diagnostics; successful and skipped cases do not. Missing file/line attributes remain null. DOCTYPE and ENTITY declarations, non-UTF-8 XML, and non-JUnit roots are rejected. Attachments, XInclude, and external resources are never resolved.

A malformed supported report is rejected atomically. Parser errors produce no partial diagnostics, while raw artifacts remain available. The compatibility sources and fixture versions are recorded in `.agent-docs/proofs/evidence/T2-schema-research.md`.
