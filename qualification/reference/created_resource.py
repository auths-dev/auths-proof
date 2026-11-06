"""Independent test-only created-resource projection oracle (ADR 0019).

No gateway import, credential, I/O authority, mutable budget or execution claim.
The input corpus is synthetic; agreement establishes only the closed projection.
"""
import json
import math
from pathlib import Path
import re
import sys
import unicodedata


def pairs(values):
    result = {}
    for key, value in values:
        if key in result:
            raise ValueError("duplicate member")
        result[key] = value
    return result


def pointer_tokens(pointer):
    if (not isinstance(pointer, str) or not pointer.startswith("/")
            or len(pointer.encode("utf8")) > 128 or len(pointer.split("/")) > 9
            or re.search(r"~(?![01])", pointer)
            or any(unicodedata.category(c) == "Cc" for c in pointer)):
        raise ValueError("pointer")
    return [part.replace("~1", "/").replace("~0", "~") for part in pointer[1:].split("/")]


def lookup(document, tokens):
    for part in tokens:
        if isinstance(document, dict):
            document = document[part]
        elif isinstance(document, list) and re.fullmatch(r"0|[1-9][0-9]*", part):
            document = document[int(part)]
        else:
            raise ValueError("container")
    return document


def handle(value):
    return (isinstance(value, str) and 1 <= len(value.encode("utf8")) <= 256
            and not any(unicodedata.category(c) == "Cc" for c in value))


def overlap(a, b):
    return a == b or a.startswith(b + "/") or b.startswith(a + "/")


def select(selection, items_pointer, marker_pointer, token, parent, response):
    try:
        if set(selection) != {"schema", "resource_pointer", "parent_pointer", "parent_kind", "maximum_items", "complete"}:
            return None
        if (selection["schema"] != "auths.created-resource-selection/1"
                or type(selection["maximum_items"]) is not int
                or not 1 <= selection["maximum_items"] <= 64
                or selection["parent_kind"] not in {"scalar", "sole-string-array"}
                or not 1 <= len(selection["complete"]) <= 2
                or len(response) > 65536 or not handle(parent)
                or not re.fullmatch(r"auths-e1-[0-9a-f]{64}", token)):
            return None
        relative = [selection["resource_pointer"], selection["parent_pointer"], marker_pointer]
        for pointer in [items_pointer] + relative:
            pointer_tokens(pointer)
        if any(overlap(a, b) for i, a in enumerate(relative) for b in relative[i+1:]):
            return None
        complete = selection["complete"]
        pointers = [condition["pointer"] for condition in complete]
        if len(set(pointers)) != len(pointers):
            return None
        for condition in complete:
            pointer_tokens(condition["pointer"])
            if overlap(items_pointer, condition["pointer"]):
                return None
            if condition["kind"] == "absent":
                if set(condition) != {"kind", "pointer"}:
                    return None
            elif condition["kind"] == "boolean":
                if set(condition) != {"kind", "pointer", "equals"} or type(condition["equals"]) is not bool:
                    return None
            else:
                return None
        def invalid_constant(_):
            raise ValueError("nonfinite")
        document = json.loads(response.decode("utf8"), object_pairs_hook=pairs, parse_constant=invalid_constant)
        if not isinstance(document, dict):
            return None
        # Reject invalid Unicode/nonfinite values anywhere, including unused data.
        pending = [(document, 0)]
        while pending:
            value, depth = pending.pop()
            if depth > 128:
                return None
            if isinstance(value, str):
                value.encode("utf8")
            elif isinstance(value, float) and not math.isfinite(value):
                return None
            elif isinstance(value, list):
                pending.extend((child, depth + 1) for child in value)
            elif isinstance(value, dict):
                pending.extend((child, depth + 1) for child in value.values())
                for key in value:
                    key.encode("utf8")
        for condition in complete:
            tokens = pointer_tokens(condition["pointer"])
            if condition["kind"] == "boolean":
                value = lookup(document, tokens)
                if type(value) is not bool or value != condition["equals"]:
                    return None
            else:
                container = lookup(document, tokens[:-1])
                if not isinstance(container, dict) or tokens[-1] in container:
                    return None
        candidates = lookup(document, pointer_tokens(items_pointer))
        if not isinstance(candidates, list) or len(candidates) > selection["maximum_items"]:
            return None
        selected = []
        for candidate in candidates:
            if not isinstance(candidate, dict):
                return None
            marker = lookup(candidate, pointer_tokens(marker_pointer))
            if not handle(marker):
                return None
            if marker != token:
                continue
            resource = lookup(candidate, pointer_tokens(selection["resource_pointer"]))
            found_parent = lookup(candidate, pointer_tokens(selection["parent_pointer"]))
            if selection["parent_kind"] == "sole-string-array":
                if not isinstance(found_parent, list) or len(found_parent) != 1:
                    return None
                found_parent = found_parent[0]
            if not handle(resource) or not handle(found_parent):
                return None
            if found_parent == parent:
                selected.append(resource)
        return selected[0] if len(selected) == 1 else None
    except (ValueError, KeyError, IndexError, TypeError, UnicodeError, RecursionError, OverflowError):
        return None


def main():
    corpus = json.loads(Path(sys.argv[1]).read_bytes(), object_pairs_hook=pairs)
    assert corpus["schema"] == "auths.created-resource-selection-vectors/1"
    for case in corpus["cases"]:
        actual = select(case["selection"], case["items_pointer"], case["marker_pointer"], case["token"],
                        case["parent"], bytes.fromhex(case["response_hex"]))
        assert actual == case["selected_handle"], "projection disagreement: " + case["name"]
    print(json.dumps({"schema": "auths.created-resource-reference-result/1", "cases": len(corpus["cases"]),
                      "agreed": True, "authority_or_provider_truth": False}))


if __name__ == "__main__":
    main()
