"""capa-rs adapter for xBenchLab (ResultDocument / --json-document parity with Python capa)."""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from benchlab_adapter import BaseAdapter, Empty, Finding, NormalizeResult, run_tool


class CapaRsAdapter(BaseAdapter):
    tool_name = "capa-rs"

    def version(self) -> str:
        res = subprocess.run(
            ["capa-rs", "--version"],
            capture_output=True,
            text=True,
            check=True,
        )
        out = (res.stdout or res.stderr).strip()
        m = re.search(r"(\d+\.\d+(?:\.\d+)*)", out)
        return m.group(1) if m else out

    def run(
        self,
        mode: str,
        input_path: Path,
        out_dir: Path,
        options: dict[str, str] | None = None,
    ) -> int:
        backend = self.option("backend")
        if backend == "ida":
            with tempfile.TemporaryDirectory(dir="/tmp") as tmpdir:
                writable_input = Path(tmpdir) / input_path.name
                shutil.copy2(input_path, writable_input)
                cmd = self.expand(
                    [
                        "capa-rs",
                        "--backend",
                        "{backend}",
                        "-r",
                        "/opt/{rules}",
                        "--json-document",
                        str(writable_input),
                    ]
                )
                return run_tool(cmd, out_dir, stdout_file="out.json")

        cmd = self.expand(
            [
                "capa-rs",
                "--backend",
                "{backend}",
                "-r",
                "/opt/{rules}",
                "--json-document",
                str(input_path),
            ]
        )
        return run_tool(cmd, out_dir, stdout_file="out.json")

    def normalize(self, mode: str, raw_dir: Path) -> list[Finding] | Empty | NormalizeResult:
        out_file = raw_dir / "out.json"
        if not out_file.is_file():
            return []
        try:
            doc = json.loads(out_file.read_text(encoding="utf-8"))
        except Exception:
            return []

        if not isinstance(doc, dict) or "rules" not in doc or not isinstance(doc["rules"], dict):
            return []

        rules: dict[str, Any] = doc["rules"]
        if not rules:
            return Empty()

        findings: list[Finding] = []
        seen_attack: set[str] = set()

        for rule_key in sorted(rules.keys()):
            rule_obj = rules[rule_key]
            if not isinstance(rule_obj, dict):
                continue
            meta = rule_obj.get("meta") if isinstance(rule_obj.get("meta"), dict) else {}
            rule_name = str(meta.get("name") or rule_key)
            namespace = meta.get("namespace")
            lib = bool(meta.get("lib", False))
            is_subscope = bool(meta.get("is_subscope_rule", meta.get("capa/subscope", False)))
            matches = rule_obj.get("matches")
            match_count = len(matches) if isinstance(matches, (list, dict)) else 0

            attrs: dict[str, Any] = {}
            if namespace:
                attrs["namespace"] = namespace
            if match_count:
                attrs["match_count"] = match_count

            findings.append(Finding(kind="rule_match", key=rule_name, attrs=attrs))

            if namespace and not lib and not is_subscope:
                findings.append(
                    Finding(
                        kind="capability",
                        key=rule_name,
                        attrs={"namespace": namespace},
                    )
                )

            attack_list = meta.get("attack") if "attack" in meta else meta.get("att&ck")
            if isinstance(attack_list, list):
                for att in attack_list:
                    if not isinstance(att, dict):
                        continue
                    att_id = att.get("id")
                    if att_id and str(att_id) not in seen_attack:
                        seen_attack.add(str(att_id))
                        att_attrs: dict[str, Any] = {"rule": rule_name}
                        if att.get("tactic"):
                            att_attrs["tactic"] = att["tactic"]
                        if att.get("technique"):
                            att_attrs["technique"] = att["technique"]
                        if att.get("subtechnique"):
                            att_attrs["subtechnique"] = att["subtechnique"]
                        findings.append(
                            Finding(
                                kind="attack_technique",
                                key=str(att_id),
                                attrs=att_attrs,
                            )
                        )

        return findings if findings else Empty()
