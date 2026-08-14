"""Shared LLM provider factory.

OpenAI remains the default provider. Google/Gemini is available only when a
caller explicitly selects it, so existing AutoPlan-RT workflows keep the same
runtime behavior unless --llm-provider google is used.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Literal


LLMProvider = Literal["openai", "google"]
DEFAULT_LLM_PROVIDER: LLMProvider = "openai"
DEFAULT_OPENAI_MODEL = "gpt-4o-mini"
DEFAULT_GOOGLE_MODEL = "gemini-flash-lite-latest"


def normalize_llm_provider(provider: str | None = None) -> LLMProvider:
    value = (provider or os.getenv("LLM_PROVIDER") or DEFAULT_LLM_PROVIDER).strip().lower()
    aliases = {
        "openai": "openai",
        "gpt": "openai",
        "google": "google",
        "gemini": "google",
        "google-ai": "google",
        "google_genai": "google",
    }
    normalized = aliases.get(value)
    if normalized is None:
        raise ValueError(f"Unsupported LLM provider: {provider}")
    return normalized  # type: ignore[return-value]


def default_model_for_provider(provider: str | None = None) -> str:
    normalized = normalize_llm_provider(provider)
    if normalized == "google":
        return os.getenv("GOOGLE_MODEL") or os.getenv("GEMINI_MODEL") or DEFAULT_GOOGLE_MODEL
    return os.getenv("OPENAI_MODEL") or DEFAULT_OPENAI_MODEL


def resolve_llm_config(*, provider: str | None = None, model: str | None = None) -> tuple[LLMProvider, str]:
    normalized = normalize_llm_provider(provider)
    return normalized, model or default_model_for_provider(normalized)


def build_chat_client(
    *,
    provider: str | None = None,
    model: str | None = None,
    temperature: float = 0.0,
) -> Any:
    normalized, resolved_model = resolve_llm_config(provider=provider, model=model)
    _load_env_files()
    if normalized == "google":
        return _build_google_client(resolved_model, temperature)
    return _build_openai_client(resolved_model, temperature)


def response_content_to_text(response: Any) -> str:
    content = getattr(response, "content", response)
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        chunks: list[str] = []
        for item in content:
            if isinstance(item, dict):
                text = item.get("text")
                if isinstance(text, str):
                    chunks.append(text)
            elif isinstance(item, str):
                chunks.append(item)
        if chunks:
            return "\n".join(chunks)
    return str(content)


def _build_openai_client(model: str, temperature: float) -> Any:
    if not os.getenv("OPENAI_API_KEY"):
        raise RuntimeError("OPENAI_API_KEY is not set; OpenAI LLM provider cannot run")
    try:
        from langchain_openai import ChatOpenAI
    except ImportError as exc:
        raise RuntimeError("OpenAI LLM dependencies are missing") from exc
    return ChatOpenAI(model=model, temperature=temperature)


def _build_google_client(model: str, temperature: float) -> Any:
    api_key = os.getenv("GOOGLE_API_KEY") or os.getenv("GEMINI_API_KEY")
    if not api_key:
        raise RuntimeError("GOOGLE_API_KEY is not set; Google LLM provider cannot run")
    try:
        from langchain_google_genai import ChatGoogleGenerativeAI
    except ImportError as exc:
        raise RuntimeError("Google LLM dependencies are missing; install langchain-google-genai") from exc
    return ChatGoogleGenerativeAI(model=model, temperature=temperature, google_api_key=api_key)


def _load_env_files() -> None:
    try:
        from dotenv import load_dotenv
    except ImportError as exc:
        raise RuntimeError("python-dotenv is missing") from exc
    project_root = Path(__file__).resolve().parents[1]
    load_dotenv(project_root / ".env")
    load_dotenv(project_root / "cyberrange_lab" / ".env")
    load_dotenv()
