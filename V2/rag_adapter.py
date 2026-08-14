"""Small adapter around the existing BM25 corpora.

V2 uses RAG only as grounding evidence. It never executes a module or command.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from V2.models import ServiceFinding


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_LAB_CORPUS = PROJECT_ROOT / "corpus" / "lab_chunks.jsonl"
DEFAULT_MSF_CORPUS = PROJECT_ROOT / "corpus" / "metasploit_modules.jsonl"
WORD_RE = re.compile(r"(?u)\w+")


@dataclass(frozen=True)
class JsonlChunk:
    id: str
    text: str
    metadata: dict[str, Any]


class SimpleJSONLRetriever:
    """Small token-overlap fallback when rank_bm25 is not installed."""

    def __init__(self, chunks: list[JsonlChunk]) -> None:
        self.chunks = chunks
        self._tokens = [set(_tokenize(chunk.text)) for chunk in chunks]

    @classmethod
    def from_jsonl(cls, path: str | Path) -> "SimpleJSONLRetriever":
        chunks: list[JsonlChunk] = []
        with Path(path).open(encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                row = json.loads(line)
                chunks.append(
                    JsonlChunk(
                        id=str(row.get("id") or len(chunks)),
                        text=str(row.get("text") or ""),
                        metadata=dict(row.get("metadata") or {}),
                    )
                )
        return cls(chunks)

    def retrieve(self, query: str, k: int = 5) -> list[JsonlChunk]:
        query_tokens = set(_tokenize(query))
        if not query_tokens:
            return self.chunks[:k]
        scored = []
        for index, tokens in enumerate(self._tokens):
            score = len(query_tokens & tokens)
            scored.append((score, index))
        scored.sort(key=lambda item: (item[0], -item[1]), reverse=True)
        return [self.chunks[index] for score, index in scored[:k] if score > 0]


@dataclass(frozen=True)
class RAGHit:
    source: str
    text: str
    module_path: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ServiceRAGContext:
    hits: list[RAGHit]
    candidate_modules: list[str]

    def compact_references(self, limit: int = 4) -> list[str]:
        refs: list[str] = []
        for hit in self.hits[:limit]:
            if hit.module_path:
                refs.append(f"{hit.source}: {hit.module_path}")
            else:
                title = hit.metadata.get("section") or hit.metadata.get("file") or hit.source
                refs.append(f"{hit.source}: {title}")
        return refs


class RAGAdapter:
    def __init__(
        self,
        *,
        lab_retriever: Any | None = None,
        msf_retriever: Any | None = None,
        msf_modules: set[str] | None = None,
        limitations: list[str] | None = None,
        msf_corpus_path: Path | None = None,
        disabled: bool = False,
    ) -> None:
        self.lab_retriever = lab_retriever
        self.msf_retriever = msf_retriever
        self.msf_modules = msf_modules or set()
        self.limitations = limitations or []
        self.msf_corpus_path = msf_corpus_path
        self.disabled = disabled

    @property
    def active(self) -> bool:
        return not self.disabled and (self.lab_retriever is not None or self.msf_retriever is not None)

    @classmethod
    def from_paths(
        cls,
        *,
        lab_corpus: str | Path | None = DEFAULT_LAB_CORPUS,
        msf_corpus: str | Path | None = DEFAULT_MSF_CORPUS,
        disabled: bool = False,
    ) -> "RAGAdapter":
        limitations: list[str] = []
        if disabled:
            return cls(disabled=True, limitations=["RAG désactivé par option CLI (--no-rag)."])

        try:
            from retrieval.lab_rag import LabBM25Retriever
        except Exception as exc:  # pragma: no cover - depends on local optional deps
            LabBM25Retriever = SimpleJSONLRetriever
            limitations.append(
                "RAG BM25 indisponible : fallback lexical simple utilisé "
                f"({exc.__class__.__name__})."
            )

        lab_retriever = None
        if lab_corpus:
            lab_path = Path(lab_corpus)
            if lab_path.exists():
                try:
                    lab_retriever = LabBM25Retriever.from_jsonl(lab_path)
                except Exception as exc:
                    limitations.append(f"Corpus lab ignoré ({lab_path}) : {exc}.")
            else:
                limitations.append(f"Corpus lab absent : {lab_path}.")

        msf_retriever = None
        msf_modules: set[str] = set()
        msf_path = Path(msf_corpus) if msf_corpus else None
        chosen_msf_path = cls._choose_msf_corpus(msf_path, limitations)
        if chosen_msf_path:
            try:
                if LabBM25Retriever is not None:
                    msf_retriever = LabBM25Retriever.from_jsonl(chosen_msf_path)
                msf_modules = load_module_paths(chosen_msf_path)
            except Exception as exc:
                limitations.append(f"Corpus Metasploit ignoré ({chosen_msf_path}) : {exc}.")
        else:
            limitations.append(
                "Aucun corpus Metasploit disponible : les modules proposés restent non confirmés."
            )

        if not msf_modules:
            limitations.append("Aucun chemin de module Metasploit chargé pour validation locale.")

        return cls(
            lab_retriever=lab_retriever,
            msf_retriever=msf_retriever,
            msf_modules=msf_modules,
            limitations=limitations,
            msf_corpus_path=chosen_msf_path,
        )

    @staticmethod
    def _choose_msf_corpus(path: Path | None, limitations: list[str]) -> Path | None:
        if path and path.exists():
            return path
        if path:
            limitations.append(f"Corpus Metasploit demandé absent : {path}.")
        return None

    def module_exists(self, module_path: str | None) -> bool:
        if not module_path:
            return False
        return module_path.strip().lower() in self.msf_modules

    def query_service(
        self,
        finding: ServiceFinding,
        *,
        objective: str,
        top_k: int = 5,
    ) -> ServiceRAGContext:
        if self.disabled:
            return ServiceRAGContext(hits=[], candidate_modules=[])

        query = " ".join(
            part
            for part in [
                objective,
                finding.service,
                str(finding.port),
                finding.version or "",
                finding.cve or "",
                finding.notes or "",
            ]
            if part
        )
        hits: list[RAGHit] = []
        candidate_modules: list[str] = []

        if self.msf_retriever is not None:
            msf_hits = self._retrieve(self.msf_retriever, query, top_k * 3)
            msf_hits = self._boost_cve_hits(msf_hits, finding)[:top_k]
            for chunk in msf_hits:
                metadata = dict(getattr(chunk, "metadata", {}) or {})
                module_path = metadata.get("module_path")
                if not module_path and isinstance(getattr(chunk, "id", None), str):
                    module_path = getattr(chunk, "id").removeprefix("msf:")
                module_path = module_path.strip().lower() if isinstance(module_path, str) else None
                text = str(getattr(chunk, "text", ""))
                hits.append(RAGHit(source="msf", text=text, module_path=module_path, metadata=metadata))
                if module_path and module_path not in candidate_modules:
                    candidate_modules.append(module_path)

        if self.lab_retriever is not None:
            for chunk in self._retrieve(self.lab_retriever, query, max(1, min(top_k, 3))):
                metadata = dict(getattr(chunk, "metadata", {}) or {})
                hits.append(
                    RAGHit(
                        source="lab",
                        text=str(getattr(chunk, "text", "")),
                        module_path=None,
                        metadata=metadata,
                    )
                )

        return ServiceRAGContext(hits=hits, candidate_modules=candidate_modules)

    @staticmethod
    def _retrieve(retriever: Any, query: str, top_k: int) -> list[Any]:
        try:
            return list(retriever.retrieve(query, k=top_k))
        except Exception:
            return []

    @staticmethod
    def _boost_cve_hits(chunks: list[Any], finding: ServiceFinding) -> list[Any]:
        cve = (finding.cve or "").lower()
        if not cve:
            return chunks
        boosted = [chunk for chunk in chunks if cve in str(getattr(chunk, "text", "")).lower()]
        rest = [chunk for chunk in chunks if chunk not in boosted]
        return boosted + rest


def load_module_paths(path: str | Path) -> set[str]:
    modules: set[str] = set()
    with Path(path).open(encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            row = json.loads(line)
            metadata = row.get("metadata") or {}
            module_path = metadata.get("module_path")
            if not module_path and isinstance(row.get("id"), str):
                module_path = row["id"].removeprefix("msf:")
            if isinstance(module_path, str) and module_path.strip():
                modules.add(module_path.strip().lower())
    return modules


def _tokenize(text: str) -> list[str]:
    return WORD_RE.findall((text or "").lower())

