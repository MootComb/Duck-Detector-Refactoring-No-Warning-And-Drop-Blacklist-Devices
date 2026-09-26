#!/usr/bin/env python3
# Copyright (C) 2026 Duck Apps Contributor
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""The native boundary policy: its schema, the units it declares and their include exceptions."""

from __future__ import annotations

import dataclasses
import json


UNIT_KEYS = {"path", "owner", "target", "may_include"}
POLICY_KEYS = {
    "schema_version", "cmake_lists", "unit_registry", "unit_function", "aggregate_library",
    "units", "include_exceptions",
}


class PolicyError(ValueError):
    pass


@dataclasses.dataclass(frozen=True)
class Unit:
    name: str
    path: str
    owner: str
    target: str
    may_include: tuple[str, ...]


@dataclasses.dataclass(frozen=True)
class Policy:
    cmake_lists: str
    unit_registry: str
    unit_function: str
    aggregate_library: str
    units: dict[str, Unit]
    exceptions: dict[tuple[str, str], str]


def load_policy(path: str) -> Policy:
    with open(path, encoding="utf-8") as handle:
        document = json.load(handle)
    if not isinstance(document, dict) or set(document) != POLICY_KEYS or document["schema_version"] != 2:
        raise PolicyError(f"{path}: expected schema_version 2 with keys {sorted(POLICY_KEYS)}")
    for key in ("cmake_lists", "unit_registry", "unit_function", "aggregate_library"):
        if not isinstance(document[key], str) or not document[key]:
            raise PolicyError(f"{key} must be a non-empty string")
    if not isinstance(document["units"], dict) or not document["units"]:
        raise PolicyError("units must be a non-empty object")
    units = {}
    for name, entry in document["units"].items():
        if not isinstance(entry, dict) or set(entry) != UNIT_KEYS:
            raise PolicyError(f"unit {name}: expected keys {sorted(UNIT_KEYS)}")
        if not all(isinstance(entry[key], str) and entry[key] for key in ("path", "owner", "target")):
            raise PolicyError(f"unit {name}: path, owner and target must be non-empty strings")
        may_include = entry["may_include"]
        if not isinstance(may_include, list) or not all(isinstance(item, str) for item in may_include):
            raise PolicyError(f"unit {name}: may_include must be a list of unit names")
        units[name] = Unit(name, entry["path"].strip("/"), entry["owner"], entry["target"], tuple(may_include))
    for unit in units.values():
        for other in unit.may_include:
            if other == unit.name or other not in units:
                raise PolicyError(f"unit {unit.name}: may_include names {other}, which is not another unit")
    for attribute in ("path", "target"):
        values = [getattr(unit, attribute) for unit in units.values()]
        shared = sorted({value for value in values if values.count(value) > 1})
        if shared:
            raise PolicyError(f"units must not share a {attribute}: {shared}")
    exceptions = {}
    if not isinstance(document["include_exceptions"], list):
        raise PolicyError("include_exceptions must be a list")
    for entry in document["include_exceptions"]:
        if not isinstance(entry, dict) or set(entry) != {"unit", "header", "reason"}:
            raise PolicyError("each include exception needs exactly unit, header and reason")
        if entry["unit"] not in units:
            raise PolicyError(f"include exception names unknown unit {entry['unit']}")
        if not isinstance(entry["reason"], str) or not entry["reason"].strip():
            raise PolicyError(f"include exception {entry['unit']} -> {entry['header']} must state a reason")
        exceptions[(entry["unit"], entry["header"])] = entry["reason"]
    return Policy(
        document["cmake_lists"], document["unit_registry"], document["unit_function"],
        document["aggregate_library"], units, exceptions,
    )
