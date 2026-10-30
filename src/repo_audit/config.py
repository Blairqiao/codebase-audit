"""Strict TOML profiles with declaration-relative paths and value provenance."""

from __future__ import annotations

import copy
import json
import re
import sysconfig
import tomllib
from dataclasses import asdict, dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any


class ConfigError(ValueError):
    """Invalid profile or workspace."""


@dataclass
class Profile:
    repo_id: str
    root: Path
    decision_documents: list[str] = field(default_factory=list)
    component_roots: list[str] = field(default_factory=lambda: ["."])
    policy_packs: list[str] = field(default_factory=lambda: ["general"])
    rule_overrides: dict[str, dict[str, Any]] = field(default_factory=dict)
    analyzers: list[dict[str, Any]] = field(default_factory=list)
    exclusions: list[str] = field(default_factory=list)
    agent: dict[str, Any] = field(default_factory=dict)
    budgets: dict[str, Any] = field(
        default_factory=lambda: {
            "max_launches": 4,
            "wall_clock_seconds": 300,
            "max_processes": 8,
            "max_output_bytes": 2000000,
            "max_files_per_scope": 30,
        }
    )
    report_dir: Path = field(default_factory=lambda: Path("audit-runs"))
    github: dict[str, Any] = field(default_factory=dict)
    provenance: dict[str, str] = field(default_factory=dict)
    applicability: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["root"] = str(self.root)
        result["report_dir"] = str(self.report_dir)
        return result


TOP = set(Profile.__dataclass_fields__) - {"provenance"} | {"schema_version"}
AGENT = {
    "model",
    "backend",
    "executable",
    "restricted_runner",
    "capability_verified",
    "extra_runtime_paths",
}
BUDGETS = {
    "max_launches",
    "wall_clock_seconds",
    "max_processes",
    "max_output_bytes",
    "max_tokens",
    "max_files_per_scope",
    "usage_threshold",
}
ANALYZER = {
    "id",
    "category",
    "command",
    "cwd",
    "format",
    "timeout_seconds",
    "max_output_bytes",
    "pass_exit_codes",
    "finding_exit_codes",
    "artifact",
    "version_command",
}
GITHUB = {
    "repository",
    "enabled",
    "max_new_issues",
    "label",
    "allow_publish",
    "decision_cache_max_age_hours",
}


def resource_dir(name: str) -> Path:
    source = Path(__file__).resolve().parents[2] / name
    if source.is_dir():
        return source
    return Path(sysconfig.get_path("data")) / "share" / "repo-audit" / name


def _read(path: Path) -> dict[str, Any]:
    try:
        with path.open("rb") as handle:
            return tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise ConfigError(f"{path}: {exc}") from exc


def _unknown(data: dict[str, Any], allowed: set[str], label: str) -> None:
    if keys := data.keys() - allowed:
        raise ConfigError(f"{label}: unknown keys {sorted(keys)}")


def relative_path(value: str) -> str:
    path = PurePosixPath(value)
    if not value or path.is_absolute() or ".." in path.parts or "\\" in value:
        raise ConfigError(f"Path must remain within repository: {value}")
    return value


def _validate(data: dict[str, Any], *, partial: bool = False) -> None:
    _unknown(data, TOP, "profile")
    if not partial and (type(data.get("schema_version")) is not int or data["schema_version"] != 1):
        raise ConfigError("schema_version must be 1")
    for key in ["root", "repo_id", "report_dir"]:
        if key in data and not isinstance(data[key], str):
            raise ConfigError(f"{key} must be a string")
    for key in [
        "decision_documents",
        "component_roots",
        "policy_packs",
        "exclusions",
        "applicability",
    ]:
        if key in data and (
            not isinstance(data[key], list) or any(not isinstance(x, str) for x in data[key])
        ):
            raise ConfigError(f"{key} must be an array of strings")
    for key in ["decision_documents", "component_roots"]:
        for value in data.get(key, []):
            relative_path(value)
    for key, allowed in [("agent", AGENT), ("budgets", BUDGETS), ("github", GITHUB)]:
        if not isinstance(data.get(key, {}), dict):
            raise ConfigError(f"{key} must be a table")
        _unknown(data.get(key, {}), allowed, key)
    for key, value in data.get("budgets", {}).items():
        if type(value) not in (int, float) or value <= 0:
            raise ConfigError(f"budgets.{key} must be positive")
        if (
            key
            in {
                "max_launches",
                "max_processes",
                "max_output_bytes",
                "max_files_per_scope",
                "max_tokens",
            }
            and type(value) is not int
        ):
            raise ConfigError(f"budgets.{key} must be integer")
    for key, value in data.get("agent", {}).items():
        if key == "capability_verified":
            if type(value) is not bool:
                raise ConfigError("agent.capability_verified must be boolean")
        elif key == "extra_runtime_paths":
            if not isinstance(value, list) or any(not isinstance(x, str) for x in value):
                raise ConfigError("extra_runtime_paths must be string array")
        elif not isinstance(value, str):
            raise ConfigError(f"agent.{key} must be a string")
    github = data.get("github", {})
    for key in ["enabled", "allow_publish"]:
        if key in github and type(github[key]) is not bool:
            raise ConfigError(f"github.{key} must be boolean")
    for key in ["max_new_issues", "decision_cache_max_age_hours"]:
        if key in github and (type(github[key]) is not int or github[key] < 0):
            raise ConfigError(f"github.{key} must be nonnegative integer")
    if "label" in github and not isinstance(github["label"], str):
        raise ConfigError("github.label must be string")
    if "repository" in github and (
        not isinstance(github["repository"], str)
        or not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", github["repository"])
    ):
        raise ConfigError("github.repository must be owner/name")
    if not isinstance(data.get("analyzers", []), list):
        raise ConfigError("analyzers must be an array")
    ids = set()
    for analyzer in data.get("analyzers", []):
        if not isinstance(analyzer, dict):
            raise ConfigError("analyzer must be a table")
        _unknown(analyzer, ANALYZER, "analyzer")
        if not isinstance(analyzer.get("id"), str) or not analyzer["id"] or analyzer["id"] in ids:
            raise ConfigError("analyzer id must be unique and nonempty")
        ids.add(analyzer["id"])
        if analyzer.get("category", "other") not in {
            "lint",
            "typecheck",
            "tests",
            "dependencies",
            "unused",
            "testing",
            "other",
        }:
            raise ConfigError("Unknown analyzer category")
        if analyzer.get("format", "text") not in {
            "text",
            "json",
            "sarif",
            "junit",
            "eslint",
            "knip",
            "ruff",
        }:
            raise ConfigError("Unknown analyzer format")
        if set(analyzer.get("pass_exit_codes", [0])) & set(analyzer.get("finding_exit_codes", [1])):
            raise ConfigError("Pass and finding exit codes must not overlap")
        for command in ["command", "version_command"]:
            if command == "command" or command in analyzer:
                argv = analyzer.get(command)
                if (
                    not isinstance(argv, list)
                    or not argv
                    or any(not isinstance(x, str) or not x for x in argv)
                ):
                    raise ConfigError(f"analyzer {command} must be nonempty argv array")
        for key in ["cwd", "artifact"]:
            if key in analyzer:
                if not isinstance(analyzer[key], str):
                    raise ConfigError(f"analyzer {key} must be string")
                relative_path(analyzer[key])
        for key in ["timeout_seconds", "max_output_bytes"]:
            if key in analyzer and (type(analyzer[key]) not in (int, float) or analyzer[key] <= 0):
                raise ConfigError(f"analyzer {key} must be positive")
        for key in ["pass_exit_codes", "finding_exit_codes"]:
            if key in analyzer and (
                not isinstance(analyzer[key], list)
                or any(type(x) is not int for x in analyzer[key])
            ):
                raise ConfigError(f"analyzer {key} must be integer array")
    overrides = data.get("rule_overrides", {})
    if not isinstance(overrides, dict):
        raise ConfigError("rule_overrides must be table")
    for rule, override in overrides.items():
        if not isinstance(override, dict):
            raise ConfigError(f"{rule} override must be table")
        _unknown(override, {"mode", "reason", "instructions"}, rule)
        if override.get("mode", "advisory") not in {"advisory", "required", "disabled"}:
            raise ConfigError("rule mode must be advisory, required, or disabled")
        if any(not isinstance(v, str) for v in override.values()):
            raise ConfigError("rule overrides must contain strings")


def _merge(
    base: dict[str, Any],
    override: dict[str, Any],
    provenance: dict[str, str],
    origin: str,
    prefix: str = "",
) -> None:
    for key, value in override.items():
        full = f"{prefix}.{key}" if prefix else key
        if isinstance(value, dict):
            if not isinstance(base.get(key), dict):
                base[key] = {}
            _merge(base[key], value, provenance, origin, full)
        else:
            base[key] = copy.deepcopy(value)
            provenance[full] = origin


def load_profile(path: Path | str, defaults: dict[str, Any] | None = None) -> Profile:
    path = Path(path).resolve()
    explicit = _read(path)
    _validate(explicit)
    supplied = copy.deepcopy(defaults or {})
    default_origin = str(supplied.pop("__origin__", path))
    _validate(supplied, partial=True)
    base = Profile(repo_id="", root=path.parent, report_dir=path.parent / "audit-runs").to_dict()
    base.pop("provenance")
    provenance: dict[str, str] = {}
    initial: dict[str, Any] = {}
    _merge(initial, base, provenance, "built-in")
    for layer, origin in [(supplied, default_origin), (explicit, str(path))]:
        for key in ["root", "report_dir"]:
            if key in layer:
                layer[key] = str((Path(origin).parent / layer[key]).resolve())
        _merge(initial, layer, provenance, origin)
    initial.pop("schema_version", None)
    repo_id = initial["repo_id"]
    if not isinstance(repo_id, str) or not re.fullmatch(
        r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", repo_id
    ):
        raise ConfigError("repo_id must be stable identifier of 1-128 letters/digits/._-")
    if "root" not in explicit and "root" not in supplied:
        raise ConfigError("root is required")
    initial["root"] = Path(initial["root"])
    initial["report_dir"] = Path(initial["report_dir"])
    initial["provenance"] = provenance
    profile = Profile(**initial)
    effective_policy(profile)
    return profile


def load_workspace(path: Path | str) -> list[Profile]:
    path = Path(path).resolve()
    data = _read(path)
    _unknown(data, {"schema_version", "defaults", "repositories"}, "workspace")
    if type(data.get("schema_version")) is not int or data["schema_version"] != 1:
        raise ConfigError("workspace schema_version must be 1")
    defaults = data.get("defaults", {})
    if not isinstance(defaults, dict):
        raise ConfigError("defaults must be a table")
    _validate(defaults, partial=True)
    defaults = {**defaults, "__origin__": str(path)}
    entries = data.get("repositories")
    if not isinstance(entries, list) or not entries:
        raise ConfigError("repositories must be a nonempty array")
    profiles = []
    ids = set()
    for entry in entries:
        if (
            not isinstance(entry, dict)
            or set(entry) != {"id", "profile"}
            or not all(isinstance(v, str) for v in entry.values())
        ):
            raise ConfigError("workspace entries require id and profile strings")
        profile = load_profile(path.parent / entry["profile"], defaults)
        if profile.repo_id != entry["id"] or profile.repo_id in ids:
            raise ConfigError("workspace ID must match profile and be unique")
        ids.add(profile.repo_id)
        profiles.append(profile)
    return profiles


def effective_policy(profile: Profile) -> list[dict[str, Any]]:
    rules = []
    known: set[str] = set()
    for name in profile.policy_packs:
        if not re.fullmatch(r"[a-z0-9-]+", name):
            raise ConfigError(f"Invalid policy pack {name}")
        try:
            pack = json.loads((resource_dir("policies") / f"{name}.json").read_text())
        except (OSError, ValueError) as exc:
            raise ConfigError(f"Unknown or invalid policy pack {name}") from exc
        for original in pack["rules"]:
            rule = copy.deepcopy(original)
            known.add(rule["id"])
            if rule["applicability"] != ["all"] and not set(rule["applicability"]) & set(
                profile.applicability
            ):
                continue
            rule["pack_version"] = pack["version"]
            rule["mode"] = "advisory"
            rule["provenance"] = f"{name}@{pack['version']}"
            if override := profile.rule_overrides.get(rule["id"]):
                rule.update(override)
                rule["provenance"] = profile.provenance.get(
                    f"rule_overrides.{rule['id']}.mode", str(profile.root)
                )
            rules.append(rule)
    if unknown := profile.rule_overrides.keys() - known:
        raise ConfigError(f"Unknown override rules {sorted(unknown)}")
    return rules
