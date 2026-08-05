from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Protocol


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _normalize_term(term: str) -> str:
    if len(term) > 5 and term.endswith("ing"):
        return term[:-3]
    if len(term) > 3 and term.endswith("s"):
        return term[:-1]
    return term


def _tokenize(text: str) -> set[str]:
    return {_normalize_term(term) for term in re.findall(r"[a-z0-9']+", text.lower())}


STOPWORDS = {
    "a",
    "about",
    "an",
    "and",
    "are",
    "be",
    "for",
    "from",
    "how",
    "i",
    "in",
    "is",
    "it",
    "me",
    "of",
    "on",
    "or",
    "the",
    "this",
    "to",
    "what",
    "you",
}


OWNER_QUERY_TERMS = {
    "career",
    "cybersecurity",
    "goal",
    "identity",
    "name",
    "owner",
    "preference",
    "profile",
    "project",
    "user",
    "woady",
}


def _query_terms(text: str) -> set[str]:
    terms = {term for term in _tokenize(text) if term not in STOPWORDS}
    if _looks_like_owner_query(text):
        terms.update(OWNER_QUERY_TERMS)
    return terms


def _looks_like_owner_query(text: str) -> bool:
    return bool(
        re.search(
            r"\b(tell me about me|who am i|what do you know about me|"
            r"my profile|about myself)\b",
            text,
            re.I,
        )
    )


def _looks_like_continuity_summary(text: str) -> bool:
    return bool(
        len(text) >= 500
        or re.search(
            r"\b(continuity summary|user profile|active projects|"
            r"communication style preferences|open threads)\b",
            text,
            re.I,
        )
    )


def _compact_continuity_summary(text: str, max_chars: int = 6000) -> str:
    useful_lines: list[str] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        lowered = line.lower()
        if (
            line.startswith("#")
            or line.startswith("*")
            or line.startswith("-")
            or any(
                keyword in lowered
                for keyword in (
                    "user",
                    "woady",
                    "george",
                    "goal",
                    "prefer",
                    "project",
                    "cyber",
                    "linux",
                    "vexor",
                    "sentinel",
                    "wazuh",
                    "lab",
                    "portfolio",
                    "starbucks",
                )
            )
        ):
            useful_lines.append(line)

    compacted = "\n".join(useful_lines) if useful_lines else text.strip()
    if len(compacted) <= max_chars:
        return compacted
    return compacted[:max_chars].rstrip() + "\n[continuity summary truncated]"


def _extract_declared_name(text: str) -> str | None:
    match = re.search(
        r"\b(?:my name is|i am|i'm|call me)\s+([A-Z][A-Za-z0-9_-]{1,40})\b",
        text,
        re.I,
    )
    if match:
        name = match.group(1).strip()
        if name.lower() in {"a", "an", "actively", "currently", "working"}:
            return None
        return name
    return None


def _extract_goes_by(text: str) -> str | None:
    match = re.search(
        r"\b(?:user goes by|i go by|goes by)\s+\**([A-Z][A-Za-z0-9_-]{1,40})\**",
        text,
        re.I,
    )
    if match:
        return match.group(1)
    return None


@dataclass
class Memory:
    """A durable note the personal AI can recall later."""

    id: str
    kind: str
    content: str
    tags: list[str] = field(default_factory=list)
    importance: float = 1.0
    created_at: str = field(default_factory=_utc_now)
    metadata: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def create(
        cls,
        kind: str,
        content: str,
        tags: Iterable[str] | None = None,
        importance: float = 1.0,
        metadata: dict[str, Any] | None = None,
    ) -> "Memory":
        return cls(
            id=uuid.uuid4().hex,
            kind=kind,
            content=content,
            tags=list(tags or []),
            importance=float(importance),
            metadata=dict(metadata or {}),
        )

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "Memory":
        return cls(
            id=str(value["id"]),
            kind=str(value["kind"]),
            content=str(value["content"]),
            tags=list(value.get("tags", [])),
            importance=float(value.get("importance", 1.0)),
            created_at=str(value.get("created_at", _utc_now())),
            metadata=dict(value.get("metadata", {})),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "kind": self.kind,
            "content": self.content,
            "tags": self.tags,
            "importance": self.importance,
            "created_at": self.created_at,
            "metadata": self.metadata,
        }


class JsonMemoryStore:
    """Small local JSON-backed memory store for a personal assistant."""

    def __init__(self, path: str | Path | None = None, autoload: bool = True):
        self.path = Path(path).expanduser() if path else self.default_path()
        self._memories: list[Memory] = []
        if autoload:
            self.load()

    @staticmethod
    def default_path() -> Path:
        return Path.home() / ".open_mythos" / "personal_ai_memory.json"

    def __len__(self) -> int:
        return len(self._memories)

    def __iter__(self):
        return iter(self._memories)

    def load(self) -> None:
        if not self.path.exists():
            self._memories = []
            return
        with self.path.open("r", encoding="utf-8") as handle:
            raw = json.load(handle)
        self._memories = [Memory.from_dict(item) for item in raw.get("memories", [])]

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "version": 1,
            "memories": [item.to_dict() for item in self._memories],
        }
        with self.path.open("w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, sort_keys=True)

    def remember(
        self,
        content: str,
        kind: str = "note",
        tags: Iterable[str] | None = None,
        importance: float = 1.0,
        metadata: dict[str, Any] | None = None,
        save: bool = True,
    ) -> Memory:
        memory = Memory.create(kind, content, tags, importance, metadata)
        self._memories.append(memory)
        if save:
            self.save()
        return memory

    def forget(self, memory_id: str, save: bool = True) -> bool:
        original_len = len(self._memories)
        self._memories = [item for item in self._memories if item.id != memory_id]
        removed = len(self._memories) != original_len
        if removed and save:
            self.save()
        return removed

    def recall(
        self,
        query: str = "",
        limit: int = 8,
        tags: Iterable[str] | None = None,
    ) -> list[Memory]:
        wanted_tags = set(tags or [])
        query_terms = _query_terms(query)
        candidates: list[tuple[Memory, int]] = []
        for memory in self._memories:
            if wanted_tags and not wanted_tags.intersection(memory.tags):
                continue
            memory_terms = _tokenize(
                " ".join([memory.kind, memory.content, *memory.tags])
            )
            overlap = len(query_terms.intersection(memory_terms))
            if query_terms and not wanted_tags and overlap == 0:
                continue
            candidates.append((memory, overlap))

        def score(item: tuple[Memory, int]) -> tuple[float, str]:
            memory, overlap = item
            relevance = overlap / max(len(query_terms), 1)
            return (memory.importance + relevance, memory.created_at)

        ranked = sorted(candidates, key=score, reverse=True)
        return [memory for memory, _ in ranked[:limit]]


class OllamaGenerator:
    """Text generator backed by a local Ollama model."""

    def __init__(
        self,
        model: str = "gemma4:e4b",
        base_url: str = "http://127.0.0.1:11434",
        timeout: float = 120.0,
    ):
        self.model = model
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def __call__(
        self,
        prompt: str,
        temperature: float = 0.7,
        top_p: float = 0.9,
        **_: Any,
    ) -> str:
        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": temperature,
                "top_p": top_p,
            },
        }
        request = urllib.request.Request(
            self.base_url + "/api/generate",
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                raw = json.loads(response.read().decode("utf-8"))
        except urllib.error.URLError as exc:
            raise RuntimeError(
                "Could not reach Ollama. Start it with `ollama serve`, or use "
                "`hermes --backend bootstrap`."
            ) from exc
        return str(raw.get("response", "")).strip()


class BootstrapMindGenerator:
    """
    A tiny local response engine for the first boot of a personal AI.

    This is not a trained language model. It gives the mind a usable voice while
    its durable memory, learning loop, and model adapter are being connected.
    """

    def __call__(self, prompt: str, **_: Any) -> str:
        user_message = self._extract_section(prompt, "[User]", "[Assistant]")
        memories = self._extract_memories(prompt)

        if self._looks_like_profile_question(user_message) and memories:
            return self._profile_answer(memories)
        if self._looks_like_continuity_dump(user_message):
            return (
                "I captured that as continuity memory. I should not need slash "
                "commands for a profile dump like this; normal conversation is "
                "part of my memory now."
            )
        if self._looks_like_greeting(user_message):
            return (
                "I am here. I have a home now: memory, identity, and a place "
                "to keep learning from what you teach me."
            )
        if self._looks_like_learning_intent(user_message):
            return (
                "Yes. Give me knowledge in one of these forms: "
                "`/remember a durable fact or preference`, `/learn path/to/file`, "
                "or `/learn path/to/folder`. I will store it in my local home "
                "and recall it in future conversations."
            )
        if self._looks_like_frustration(user_message):
            return (
                "You are right to push me. This bootstrap brain is not enough. "
                "Use `hermes --backend ollama --model gemma4:e4b` "
                "to connect me to a real local language model, then keep "
                "teaching me with `/remember` and `/learn`."
            )
        if memories:
            memory_text = "; ".join(memories[:3])
            return (
                "I remember this: "
                + memory_text
                + ". Tell me the next thing to learn, or give me a file path "
                "and I will add it to my local memory."
            )
        return (
            "I am awake enough to listen and remember. Teach me one durable "
            "fact, preference, project, or file, and I will start building a "
            "mind around you."
        )

    @staticmethod
    def _extract_section(prompt: str, start: str, end: str) -> str:
        try:
            return prompt.split(start, 1)[1].split(end, 1)[0].strip()
        except IndexError:
            return ""

    @staticmethod
    def _extract_memories(prompt: str) -> list[str]:
        try:
            block = prompt.split("[Relevant memory]", 1)[1].split("\n\n[", 1)[0]
        except IndexError:
            return []
        memories = []
        for line in block.splitlines():
            line = line.strip()
            if line.startswith("- ("):
                memories.append(line.split(") ", 1)[-1])
        return memories

    @classmethod
    def _profile_answer(cls, memories: list[str]) -> str:
        facts = cls._profile_facts(memories)
        if not facts:
            return (
                "I do not have enough saved owner-profile memory to answer that "
                "cleanly yet. I will not make it up."
            )
        lines = ["Based only on saved memory, here is what I know:"]
        lines.extend(f"- {fact}" for fact in facts[:8])
        lines.append("If any of that is wrong or outdated, correct me and I will update it.")
        return "\n".join(lines)

    @classmethod
    def _profile_facts(cls, memories: list[str]) -> list[str]:
        text = " ".join(re.sub(r"\s+", " ", memory).strip() for memory in memories)
        facts: list[str] = []

        declared_names = cls._unique_matches(
            r"Owner says their name is ([A-Za-z0-9_-]+)\.", text
        )
        goes_by = cls._unique_matches(
            r"(?:Owner goes by|User goes by \**)([A-Za-z0-9_-]+)", text
        )
        if declared_names:
            facts.append(f"Name saved in memory: {declared_names[0]}.")
        if goes_by:
            facts.append(f"Goes by: {goes_by[0]}.")

        if re.search(r"works at Starbucks", text, re.I):
            facts.append("Current work context: works at Starbucks.")
        if re.search(r"transitioning into .*IT / cybersecurity", text, re.I):
            facts.append("Career direction: transitioning into IT / cybersecurity.")

        targets = cls._present_phrases(
            text,
            (
                "Entry-level IT Support",
                "Help Desk",
                "Desktop Support",
                "SOC Analyst I",
            ),
        )
        if targets:
            facts.append("Career targets: " + ", ".join(targets) + ".")

        learning = cls._present_phrases(
            text,
            (
                "Google IT Support Certificate",
                "networking foundations",
                "Cybersecurity fundamentals",
                "Linux",
                "virtualization",
                "SIEM",
                "blue-team labs",
                "portfolio projects",
            ),
        )
        if learning:
            facts.append("Learning focus: " + ", ".join(learning[:6]) + ".")

        style = cls._present_phrases(
            text,
            (
                "exact commands",
                "practical proof",
                "clear win conditions",
                "direct",
                "high-performance",
                "honest",
            ),
        )
        if style:
            facts.append("Preferred coaching style: " + ", ".join(style[:5]) + ".")

        projects = cls._present_phrases(
            text,
            (
                "Linux Cybersecurity Home Lab",
                "WoadyCompat",
                "Linux Workstation",
                "Windows Dual Boot",
                "VEXOR OS",
                "SentinelGuard",
                "Woady Scanner",
                "Breach Loop",
            ),
        )
        if projects:
            facts.append("Active projects in memory: " + ", ".join(projects[:6]) + ".")

        if re.search(r"legal|lab-based|authorized|defensive", text, re.I):
            facts.append(
                "Cybersecurity boundary: legal, authorized, lab-based, defensive work."
            )
        return facts

    @staticmethod
    def _present_phrases(text: str, phrases: Iterable[str]) -> list[str]:
        found = []
        for phrase in phrases:
            if re.search(re.escape(phrase), text, re.I):
                found.append(phrase)
        return found

    @staticmethod
    def _unique_matches(pattern: str, text: str) -> list[str]:
        values = []
        seen = set()
        for match in re.finditer(pattern, text, re.I):
            value = match.group(1).strip("*., ")
            key = value.lower()
            if key not in seen:
                seen.add(key)
                values.append(value)
        return values

    @staticmethod
    def _looks_like_greeting(text: str) -> bool:
        return bool(re.search(r"\b(hello|hi|hey|wake up|are you there)\b", text, re.I))

    @staticmethod
    def _looks_like_profile_question(text: str) -> bool:
        return _looks_like_owner_query(text)

    @staticmethod
    def _looks_like_continuity_dump(text: str) -> bool:
        return _looks_like_continuity_summary(text)

    @staticmethod
    def _looks_like_learning_intent(text: str) -> bool:
        return bool(
            re.search(
                r"\b(let'?s|lets|i want to|time to|ready to)?\s*learn\b",
                text,
                re.I,
            )
        )

    @staticmethod
    def _looks_like_frustration(text: str) -> bool:
        return bool(re.search(r"\b(dumb|stupid|bad|useless|not smart)\b", text, re.I))


@dataclass
class PersonalAIProfile:
    """Persona and collaboration preferences for a personal AI."""

    name: str = "Mythos"
    owner_name: str = "you"
    role: str = "personal AI"
    traits: tuple[str, ...] = ("curious", "direct", "warm", "useful")
    principles: tuple[str, ...] = (
        "Remember durable preferences and goals.",
        "Ask only when a missing detail would change the answer.",
        "Prefer concrete next actions over vague encouragement.",
        "Do not invent facts; distinguish saved memory from verified facts.",
    )
    interests: tuple[str, ...] = ()

    def system_prompt(self) -> str:
        lines = [
            f"You are {self.name}, {self.owner_name}'s {self.role}.",
            f"Personality: {', '.join(self.traits)}.",
            "Operating principles:",
        ]
        lines.extend(f"- {principle}" for principle in self.principles)
        if self.interests:
            lines.append(f"Shared interests: {', '.join(self.interests)}.")
        return "\n".join(lines)


class TextGenerator(Protocol):
    def __call__(self, prompt: str, **kwargs: Any) -> str:
        ...


@dataclass
class PersonalAIResponse:
    text: str
    prompt: str
    recalled_memories: list[Memory]


class PersonalAI:
    """A lightweight personal assistant shell with local memory and persona prompts."""

    def __init__(
        self,
        profile: PersonalAIProfile | None = None,
        memory_store: JsonMemoryStore | None = None,
        generator: TextGenerator | None = None,
        max_recalled_memories: int = 8,
    ):
        self.profile = profile or PersonalAIProfile()
        self.memory_store = (
            memory_store if memory_store is not None else JsonMemoryStore()
        )
        self.generator = generator
        self.max_recalled_memories = max_recalled_memories

    def remember(
        self,
        content: str,
        kind: str = "note",
        tags: Iterable[str] | None = None,
        importance: float = 1.0,
        metadata: dict[str, Any] | None = None,
    ) -> Memory:
        return self.memory_store.remember(content, kind, tags, importance, metadata)

    def build_prompt(
        self,
        user_message: str,
        conversation: Iterable[tuple[str, str]] | None = None,
        extra_memories: Iterable[Memory] | None = None,
    ) -> tuple[str, list[Memory]]:
        recalled = self.memory_store.recall(
            user_message,
            limit=self.max_recalled_memories,
        )
        for memory in reversed(list(extra_memories or [])):
            if not any(item.id == memory.id for item in recalled):
                recalled.insert(0, memory)
        sections = [
            "[System]",
            self.profile.system_prompt(),
            "",
            "[Relevant memory]",
            self._format_memories(recalled),
        ]

        history = list(conversation or [])
        if history:
            sections.extend(["", "[Recent conversation]"])
            sections.extend(f"{role}: {text}" for role, text in history)

        sections.extend(["", "[User]", user_message, "", "[Assistant]"])
        return "\n".join(sections), recalled

    def reply(
        self,
        user_message: str,
        conversation: Iterable[tuple[str, str]] | None = None,
        extra_memories: Iterable[Memory] | None = None,
        remember_exchange: bool = True,
        **generator_kwargs: Any,
    ) -> PersonalAIResponse:
        if self.generator is None:
            raise RuntimeError(
                "PersonalAI.reply requires a text generator. Use build_prompt() "
                "to inspect the prompt, or pass a callable generator."
            )

        captured = self._auto_capture_user_context(user_message)
        prompt, recalled = self.build_prompt(
            user_message,
            conversation,
            extra_memories=[*list(extra_memories or []), *captured],
        )
        text = self.generator(prompt, **generator_kwargs)
        if remember_exchange:
            self.memory_store.remember(
                "User: " + user_message,
                kind="conversation",
                tags=["conversation"],
                importance=0.2,
                save=False,
            )
            self.memory_store.remember(
                "Assistant: " + text,
                kind="conversation",
                tags=["conversation"],
                importance=0.2,
                save=False,
            )
            self.memory_store.save()
        return PersonalAIResponse(text=text, prompt=prompt, recalled_memories=recalled)

    def _auto_capture_user_context(self, user_message: str) -> list[Memory]:
        captured: list[Memory] = []
        declared_name = _extract_declared_name(user_message)
        if declared_name:
            captured.append(
                self._remember_if_missing(
                    f"Owner says their name is {declared_name}.",
                    kind="owner-profile",
                    tags=["owner", "identity", "name", declared_name.lower()],
                    importance=2.4,
                )
            )

        goes_by = _extract_goes_by(user_message)
        if goes_by:
            captured.append(
                self._remember_if_missing(
                    f"Owner goes by {goes_by}.",
                    kind="owner-profile",
                    tags=["owner", "identity", "name", goes_by.lower()],
                    importance=2.3,
                )
            )

        if _looks_like_continuity_summary(user_message):
            summary = _compact_continuity_summary(user_message)
            captured.append(
                self._remember_if_missing(
                    "Owner-provided continuity summary:\n" + summary,
                    kind="continuity-summary",
                    tags=[
                        "owner",
                        "profile",
                        "continuity",
                        "preferences",
                        "projects",
                    ],
                    importance=2.2,
                )
            )

        if captured:
            self.memory_store.save()
        return captured

    def _remember_if_missing(
        self,
        content: str,
        *,
        kind: str,
        tags: Iterable[str],
        importance: float,
    ) -> Memory:
        for memory in self.memory_store:
            if memory.kind == kind and memory.content == content:
                return memory
        return self.memory_store.remember(
            content,
            kind=kind,
            tags=tags,
            importance=importance,
            metadata={"source": "conversation-auto-capture"},
            save=False,
        )

    @staticmethod
    def _format_memories(memories: Iterable[Memory]) -> str:
        items = list(memories)
        if not items:
            return "- No durable memories yet."
        lines = []
        for memory in items:
            content = re.sub(r"\s+", " ", memory.content).strip()
            if len(content) > 1200:
                content = content[:1200].rstrip() + "..."
            lines.append(
                f"- ({memory.kind}; importance {memory.importance:g}) {content}"
            )
        return "\n".join(lines)


class OpenMythosTextGenerator:
    """Adapter that turns an OpenMythos model plus tokenizer into a text generator."""

    def __init__(
        self,
        model: Any,
        tokenizer: Any,
        device: str | None = None,
        max_prompt_tokens: int | None = None,
    ):
        self.model = model
        self.tokenizer = tokenizer
        self.device = device
        self.max_prompt_tokens = max_prompt_tokens
        if device is not None:
            self.model.to(device)

    def __call__(
        self,
        prompt: str,
        max_new_tokens: int = 128,
        n_loops: int = 8,
        temperature: float = 0.8,
        top_k: int = 50,
    ) -> str:
        import torch

        token_ids = self.tokenizer.encode(prompt)
        if self.max_prompt_tokens is not None:
            token_ids = token_ids[-self.max_prompt_tokens :]
        input_ids = torch.tensor([token_ids], dtype=torch.long)
        if self.device is not None:
            input_ids = input_ids.to(self.device)

        self.model.eval()
        output_ids = self.model.generate(
            input_ids,
            max_new_tokens=max_new_tokens,
            n_loops=n_loops,
            temperature=temperature,
            top_k=top_k,
        )[0].detach().cpu().tolist()
        generated_ids = output_ids[len(token_ids) :]
        return self.tokenizer.decode(generated_ids).strip()
