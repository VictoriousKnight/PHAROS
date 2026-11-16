"""Thin wrapper around a local Ollama LLM (Llama 3.1 Instruct).

Provides `generate_brief` which receives the scanner dict and returns a
structured JSON payload for the UI.
"""

import os
from google import genai

# Gemini option


def generate_brief(summary_dict: dict) -> str | None:
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        return None
    client = genai.Client(api_key=api_key)
    prompt = (
        "You are a security analyst. Given these document scan results, "
        "write a concise 2-3 sentence threat summary:\n\n"
        f"{summary_dict}"
    )
    response = client.models.generate_content(model="gemini-2.0-flash", contents=prompt)
    return response.text


# Ollama option

# from __future__ import annotations
# import json
# import subprocess
# import logging
# from typing import Mapping, Any

# logger = logging.getLogger("ml.llm")


# def _run_ollama_prompt(prompt: str, model: str = "pharos-llm:latest") -> str:
#     """Execute the Ollama CLI synchronously and return stdout.

#     The binary must be on the system PATH.  A timeout of 30 seconds is used.
#     Any subprocess error is propagated to the caller.
#     """
#     result = subprocess.run(
#         ["ollama", "run", model],
#         input=prompt.encode("utf-8"),
#         capture_output=True,
#         check=True,
#         timeout=30,
#     )
#     return result.stdout.decode("utf-8").strip()


# def generate_brief(scan_dict: Mapping[str, Any]) -> dict[str, Any]:
#     """Ask the local Llama 3.1 model to produce an executive brief.

#     The LLM is instructed to return **only** a JSON object with the two keys
#     ``summary_rationale`` and ``top_contributions`` (a list of feature ->
#     description).  If parsing fails we fall back to a placeholder so the UI
#     does not break.
#     """
#     prompt = (
#     "You are a security analyst. Examine the following scan result (JSON) and produce a concise executive brief.\n\n"
#     f"{json.dumps(scan_dict, indent=2)}\n\n"
#     "Return **exactly** a JSON object with a single key:\n"
#     "  \"summary_rationale\": \"<one‑sentence overall assessment>\"\n"
#     "Do NOT add any extra text or fields."
# )

#     try:
#         raw = _run_ollama_prompt(prompt)
#         return json.loads(raw)
#     except Exception as exc:  # noqa: BLE001 – we deliberately swallow all errors.
#         logger.warning("LLM brief generation failed: %s", exc)
#         return {
#             "summary_rationale": "LLM integration unavailable.",
#             "top_contributions": [],
#         }
