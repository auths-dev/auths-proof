"""Project an exact human confirmation from gateway-verified write review.

The input review must be the output of ``auths-gateway review-submission``
against the installed recipe, lock and trust. This projection performs no
provider I/O or credential access. The gateway recomputes and compares the
same intent at task submission; a broker projection alone grants nothing.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urlsplit

from .contracts import commitment
from .operator_authority import OperatorDenied
from .task_write_proofs import task_commitment


_DIGEST = re.compile(r"[0-9a-f]{64}\Z")


@dataclass(frozen=True)
class ReviewedWrite:
    intent: dict
    arguments: dict
    method: str
    url: str
    content_type: str
    body: str


def project_exact_write(card: dict, review: dict, recipe: dict,
                        recipe_digest: str) -> ReviewedWrite:
    """Bind a reviewed native agent action to one approved task write scope."""
    if (type(card) is not dict or type(review) is not dict
            or type(recipe) is not dict or type(recipe_digest) is not str
            or _DIGEST.fullmatch(recipe_digest) is None
            or review.get("schema") != "auths.gateway-submission-review/1"
            or recipe.get("schema") != "auths.gateway-recipe-source/2"
            or type(recipe.get("task_binding")) is not dict
            or type(recipe.get("write")) is not dict
            or type(recipe.get("origin")) is not str):
        raise OperatorDenied("gateway write review is unavailable")
    actors = review.get("actors")
    arguments = review.get("arguments")
    request = review.get("request")
    binding = recipe["task_binding"]
    resource_field, verb = binding.get("resource_field"), binding.get("verb")
    if (type(actors) is not list or actors != [card.get("agent_principal")]
            or type(arguments) is not dict or type(request) is not dict
            or type(resource_field) is not str or verb not in ("edit", "create")
            or type(arguments.get(resource_field)) is not str
            or not arguments[resource_field]
            or type(card.get("write_scopes")) is not list
            or arguments.get("task_id") != card.get("task_id")
            or arguments.get("task_commitment") != task_commitment(card)
            or arguments.get("recipe_digest") != recipe_digest
            or arguments.get("operator_namespace") != recipe.get("operator_namespace")
            or type(arguments.get("operation_id")) is not str
            or not 1 <= len(arguments["operation_id"]) <= 128
            or type(review.get("action_commitment")) is not str
            or _DIGEST.fullmatch(review["action_commitment"]) is None):
        raise OperatorDenied("agent action is outside reviewed task scope")
    matching = [scope for scope in card["write_scopes"]
                if type(scope) is dict
                and scope.get("handle") == arguments[resource_field]
                and scope.get("recipe_digest") == recipe_digest
                and scope.get("verb") == verb
                and scope.get("connection_id") == card.get("connection_id")
                and scope.get("connection_generation") == card.get("connection_generation")
                and scope.get("connection_subject") == card.get("connection_subject")]
    if len(matching) != 1:
        raise OperatorDenied("agent action is outside reviewed task scope")
    method, url = request.get("method"), request.get("url")
    content_type, body = request.get("content_type"), request.get("body")
    headers = request.get("headers")
    if (type(method) is not str or type(url) is not str
            or not url.startswith("https://") or type(content_type) is not str
            or method != recipe.get("write", {}).get("method")
            or f"{urlsplit(url).scheme}://{urlsplit(url).netloc}"
            != recipe.get("origin")
            or type(body) is not str or len(body.encode("utf-8")) > 65_536
            or type(headers) is not list
            or any(type(pair) is not list or len(pair) != 2
                   or any(type(value) is not str for value in pair)
                   for pair in headers)):
        raise OperatorDenied("gateway closed request is malformed")
    request_commitment = commitment("auths.agent-write-request.v1", {
        "method": method, "url": url, "content_type": content_type,
        "headers": headers, "body_hex": body.encode("utf-8").hex(),
    })
    intent = {
        "task_id": card["task_id"],
        "task_commitment": task_commitment(card),
        "operation_id": arguments["operation_id"],
        "action_commitment": review["action_commitment"],
        "request_commitment": request_commitment,
        "recipe_digest": recipe_digest,
        "resource_handle": arguments[resource_field],
        "verb": verb,
        "connection_id": matching[0]["connection_id"],
        "connection_generation": matching[0]["connection_generation"],
        "connection_subject": matching[0]["connection_subject"],
    }
    return ReviewedWrite(intent, arguments, method, url, content_type, body)
