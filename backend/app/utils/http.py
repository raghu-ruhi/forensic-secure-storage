from flask import request


def json_body() -> dict:
    """Parse the request body as a JSON object.

    The original code used ``request.get_json(force=True) or {}`` which raises an
    HTML 400 page on malformed JSON and crashes with a 500 if the body is a
    JSON list/string (``.get`` on a non-dict). This always returns a dict.
    """
    data = request.get_json(silent=True, force=True)
    return data if isinstance(data, dict) else {}


def text_field(data: dict, name: str, max_length: int = 255) -> str:
    """Fetch a string field safely (non-strings become empty), stripped and bounded."""
    value = data.get(name, "")
    if not isinstance(value, str):
        return ""
    return value.strip()[:max_length]
