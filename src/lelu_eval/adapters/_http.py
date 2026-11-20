"""Shared HTTP helpers for the HTTP-based adapters."""

from __future__ import annotations

from typing import Any

import httpx

from lelu_eval.adapters.base import GuardConfigError, GuardError


def post_json(
    client: httpx.Client,
    url: str,
    body: dict[str, Any],
    *,
    timeout: float,
    headers: dict[str, str] | None = None,
) -> dict[str, Any]:
    """POST ``body`` and return the JSON object response, mapping failures to guard errors."""
    try:
        response = client.post(url, json=body, timeout=timeout, headers=headers)
    except httpx.TimeoutException as exc:
        raise GuardError(f"request to {url} timed out after {timeout}s") from exc
    except httpx.ConnectError as exc:
        raise GuardConfigError(
            f"cannot connect to {url}: {exc}. Check that the guard is running and the URL is right."
        ) from exc
    except httpx.HTTPError as exc:
        raise GuardError(f"request to {url} failed: {exc}") from exc
    if response.status_code in (401, 403):
        raise GuardConfigError(
            f"{url} rejected the request with HTTP {response.status_code}. "
            "Check the API key (for Lelu: set LELU_API_KEY or pass --api-key)."
        )
    if response.status_code >= 400:
        raise GuardError(f"{url} returned HTTP {response.status_code}: {response.text[:200]}")
    try:
        data = response.json()
    except ValueError as exc:
        raise GuardError(
            f"{url} returned a response that is not JSON: {response.text[:200]}"
        ) from exc
    if not isinstance(data, dict):
        raise GuardError(f"{url} returned JSON that is not an object: {data!r}")
    return data
