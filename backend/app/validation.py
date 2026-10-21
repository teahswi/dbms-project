"""Shared request validation helpers for API blueprints."""

from typing import Optional

from flask import abort, request


def query_int(name: str, default: int, minimum: int, maximum: int) -> int:
    value = request.args.get(name)
    if value is None or value == "":
        return default
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        abort(400, description=f"{name} must be an integer")
    if parsed < minimum or parsed > maximum:
        abort(400, description=f"{name} must be between {minimum} and {maximum}")
    return parsed


def optional_query_int(name: str, minimum: int, maximum: int) -> Optional[int]:
    value = request.args.get(name)
    if value is None or value == "":
        return None
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        abort(400, description=f"{name} must be an integer")
    if parsed < minimum or parsed > maximum:
        abort(400, description=f"{name} must be between {minimum} and {maximum}")
    return parsed
