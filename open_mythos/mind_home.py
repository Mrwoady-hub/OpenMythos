from __future__ import annotations

import hashlib
import json
import math
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable

from open_mythos.personal_ai import (
    BootstrapMindGenerator,
    JsonMemoryStore,
    Memory,
    OllamaGenerator,
    PersonalAI,
    PersonalAIProfile,
    TextGenerator,
    _utc_now,
)
from open_mythos.seed_knowledge import CORE_KNOWLEDGE


DEFAULT_MIND_NAME = "Hermes"
LEGACY_DEFAULT_MIND_NAME = "Damon"
LEGACY_DEFAULT_MIND_NAMES = (LEGACY_DEFAULT_MIND_NAME, "Linus")

TEXT_SUFFIXES = {
    ".csv",
    ".json",
    ".log",
    ".md",
    ".py",
    ".rst",
    ".text",
    ".toml",
    ".txt",
    ".yaml",
    ".yml",
}
SKIPPED_LEARN_DIRS = {
    ".git",
    ".hg",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".tox",
    ".venv",
    "__pycache__",
    "build",
    "dist",
    "htmlcov",
    "node_modules",
}


@dataclass
class LearnedSource:
    path: str
    memories_added: int
    learned_at: str
    fingerprint: str = ""
    skipped: bool = False
    reason: str | None = None


@dataclass
class ConversationSummary:
    updated_at: str
    exchanges: int = 0
    recent_owner_messages: list[str] | None = None
    recent_assistant_messages: list[str] | None = None
    open_threads: list[str] | None = None

    @classmethod
    def create(cls) -> "ConversationSummary":
        return cls(
            updated_at=_utc_now(),
            recent_owner_messages=[],
            recent_assistant_messages=[],
            open_threads=[],
        )

    @classmethod
    def from_dict(cls, value: dict[str, object]) -> "ConversationSummary":
        return cls(
            updated_at=str(value.get("updated_at", _utc_now())),
            exchanges=int(value.get("exchanges", 0)),
            recent_owner_messages=list(value.get("recent_owner_messages", [])),
            recent_assistant_messages=list(value.get("recent_assistant_messages", [])),
            open_threads=list(value.get("open_threads", [])),
        )

    def to_text(self) -> str:
        owner = self.recent_owner_messages or []
        assistant = self.recent_assistant_messages or []
        threads = self.open_threads or []
        lines = [
            f"Conversation continuity updated {self.updated_at}.",
            f"Recorded exchanges: {self.exchanges}.",
            "Recent owner messages:",
        ]
        lines.extend(f"- {item}" for item in owner[-8:])
        lines.append("Recent assistant messages:")
        lines.extend(f"- {item}" for item in assistant[-5:])
        lines.append("Open threads:")
        lines.extend(f"- {item}" for item in threads[-8:])
        return "\n".join(lines)


@dataclass
class MindState:
    """Persistent growth state for a local personal AI."""

    level: int = 1
    experience: int = 0
    total_interactions: int = 0
    memories_created: int = 0
    sources_learned: int = 0
    trust_events: int = 0
    created_at: str = ""
    updated_at: str = ""
    last_level_up_at: str | None = None

    @classmethod
    def create(cls) -> "MindState":
        now = _utc_now()
        return cls(created_at=now, updated_at=now)

    @classmethod
    def from_dict(cls, value: dict[str, object]) -> "MindState":
        return cls(
            level=int(value.get("level", 1)),
            experience=int(value.get("experience", 0)),
            total_interactions=int(value.get("total_interactions", 0)),
            memories_created=int(value.get("memories_created", 0)),
            sources_learned=int(value.get("sources_learned", 0)),
            trust_events=int(value.get("trust_events", 0)),
            created_at=str(value.get("created_at", "")),
            updated_at=str(value.get("updated_at", "")),
            last_level_up_at=(
                str(value["last_level_up_at"])
                if value.get("last_level_up_at") is not None
                else None
            ),
        )


def experience_for_level(level: int) -> int:
    """Return total lifetime XP needed to reach a level."""

    if level <= 1:
        return 0
    return 100 * (level - 1) * (level - 1)


def level_from_experience(experience: int) -> int:
    return math.isqrt(max(0, experience) // 100) + 1


class MindHome:
    """A local filesystem home for a personal AI."""

    def __init__(self, root: str | Path | None = None):
        self.root = Path(root).expanduser() if root else self.default_root()
        self.memory_path = self.root / "memory.json"
        self.transcript_path = self.root / "hermes_memory.md"
        self.legacy_transcript_path = self.root / "damon_memory.md"
        self.legacy_transcript_paths = (
            self.root / "linus_memory.md",
            self.legacy_transcript_path,
        )
        self.profile_path = self.root / "profile.json"
        self.state_path = self.root / "state.json"
        self.growth_path = self.root / "growth.jsonl"
        self.journal_path = self.root / "journal.jsonl"
        self.continuity_path = self.root / "continuity.json"
        self.sources_path = self.root / "sources.jsonl"
        self.inbox_dir = self.root / "inbox"
        self.knowledge_dir = self.root / "knowledge"

    @staticmethod
    def default_root() -> Path:
        return Path.home() / ".open_mythos" / "mind"

    def initialize(
        self,
        name: str = DEFAULT_MIND_NAME,
        owner_name: str = "Woady",
        overwrite_profile: bool = False,
        rename_existing: bool = False,
    ) -> PersonalAI:
        self.root.mkdir(parents=True, exist_ok=True)
        self.inbox_dir.mkdir(parents=True, exist_ok=True)
        self.knowledge_dir.mkdir(parents=True, exist_ok=True)

        if overwrite_profile or not self.profile_path.exists():
            self.save_profile(
                PersonalAIProfile(
                    name=name,
                    owner_name=owner_name,
                    role="personal AI mind",
                    traits=("curious", "loyal", "direct", "ever-learning"),
                    principles=(
                        "Keep durable memory across conversations.",
                        "Learn from files and notes the owner explicitly provides.",
                        "Admit uncertainty instead of pretending to know everything.",
                        "Turn vague dreams into concrete next actions.",
                        "Do not invent facts; separate saved memory from verified facts.",
                    ),
                    interests=("knowledge", "creative work", "AI systems"),
                )
            )
        else:
            profile = self.load_profile()
            should_rename = rename_existing or (
                profile.name in LEGACY_DEFAULT_MIND_NAMES
                and name == DEFAULT_MIND_NAME
            )
            if should_rename and (
                profile.name != name or profile.owner_name != owner_name
            ):
                self.save_profile(
                    PersonalAIProfile(
                        name=name,
                        owner_name=owner_name,
                        role=profile.role,
                        traits=profile.traits,
                        principles=profile.principles,
                        interests=profile.interests,
                    )
                )
        self._ensure_transcript()
        state = self.load_state()
        self.save_state(state)

        memory = JsonMemoryStore(self.memory_path)
        profile = self.load_profile()
        if len(memory) == 0:
            memory.remember(
                f"{profile.name} was first given a home at {self.root}.",
                kind="origin",
                tags=["origin", "home"],
                importance=2.0,
            )
            self.award_experience(25, "first-home", memories_created=1)
        return self.open_ai()

    def open_ai(self, generator: TextGenerator | None = None) -> PersonalAI:
        profile = self.load_profile()
        progress = self.progress()
        profile = PersonalAIProfile(
            name=profile.name,
            owner_name=profile.owner_name,
            role=profile.role,
            traits=profile.traits,
            principles=(
                *profile.principles,
                "Current persistent growth state: "
                f"level {progress['level']} with {progress['experience']} XP.",
            ),
            interests=profile.interests,
        )
        return PersonalAI(
            profile=profile,
            memory_store=JsonMemoryStore(self.memory_path),
            generator=generator or BootstrapMindGenerator(),
        )

    def open_ollama_ai(
        self,
        model: str = "gemma4:e4b",
        base_url: str = "http://127.0.0.1:11434",
    ) -> PersonalAI:
        return self.open_ai(generator=OllamaGenerator(model=model, base_url=base_url))

    def load_profile(self) -> PersonalAIProfile:
        if not self.profile_path.exists():
            return PersonalAIProfile()
        with self.profile_path.open("r", encoding="utf-8") as handle:
            raw = json.load(handle)
        return PersonalAIProfile(
            name=raw.get("name", "Mythos"),
            owner_name=raw.get("owner_name", "you"),
            role=raw.get("role", "personal AI"),
            traits=tuple(raw.get("traits", [])),
            principles=tuple(raw.get("principles", [])),
            interests=tuple(raw.get("interests", [])),
        )

    def save_profile(self, profile: PersonalAIProfile) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        with self.profile_path.open("w", encoding="utf-8") as handle:
            json.dump(asdict(profile), handle, indent=2, sort_keys=True)

    def load_state(self) -> MindState:
        if not self.state_path.exists():
            return MindState.create()
        with self.state_path.open("r", encoding="utf-8") as handle:
            raw = json.load(handle)
        return MindState.from_dict(raw)

    def save_state(self, state: MindState) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        state.updated_at = _utc_now()
        state.level = level_from_experience(state.experience)
        with self.state_path.open("w", encoding="utf-8") as handle:
            json.dump(asdict(state), handle, indent=2, sort_keys=True)

    def progress(self) -> dict[str, object]:
        state = self.load_state()
        current_level_xp = experience_for_level(state.level)
        next_level_xp = experience_for_level(state.level + 1)
        return {
            **asdict(state),
            "current_level_xp": current_level_xp,
            "next_level_xp": next_level_xp,
            "xp_into_level": state.experience - current_level_xp,
            "xp_to_next_level": next_level_xp - state.experience,
        }

    def award_experience(
        self,
        amount: int,
        reason: str,
        *,
        interactions: int = 0,
        memories_created: int = 0,
        sources_learned: int = 0,
        trust_events: int = 0,
    ) -> MindState:
        state = self.load_state()
        previous_level = state.level
        state.experience += max(0, int(amount))
        state.total_interactions += max(0, int(interactions))
        state.memories_created += max(0, int(memories_created))
        state.sources_learned += max(0, int(sources_learned))
        state.trust_events += max(0, int(trust_events))
        state.level = level_from_experience(state.experience)
        if state.level > previous_level:
            state.last_level_up_at = _utc_now()
        self.save_state(state)
        self._record_growth_event(reason, amount, previous_level, state)
        return state

    def _record_growth_event(
        self,
        reason: str,
        experience: int,
        previous_level: int,
        state: MindState,
    ) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        event = {
            "at": _utc_now(),
            "reason": reason,
            "experience": experience,
            "previous_level": previous_level,
            "level": state.level,
            "total_experience": state.experience,
            "leveled_up": state.level > previous_level,
        }
        with self.growth_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(event, sort_keys=True) + "\n")

    def remember(
        self,
        content: str,
        kind: str = "note",
        tags: Iterable[str] | None = None,
        importance: float = 1.0,
    ) -> Memory:
        store = JsonMemoryStore(self.memory_path)
        memory = store.remember(content, kind, tags, importance)
        self.award_experience(8, f"remember:{kind}", memories_created=1)
        return memory

    def trust_lesson(
        self,
        content: str,
        kind: str = "trust-lesson",
        tags: Iterable[str] | None = None,
        importance: float = 2.2,
    ) -> Memory:
        memory = self.remember(
            content,
            kind=kind,
            tags=["trust", "owner-taught", *(tags or [])],
            importance=importance,
        )
        self.award_experience(18, "trust-lesson", trust_events=1)
        return memory

    def recall(self, query: str, limit: int = 8) -> list[Memory]:
        return JsonMemoryStore(self.memory_path).recall(query, limit=limit)

    def seed_core_knowledge(self) -> int:
        store = JsonMemoryStore(self.memory_path)
        existing = {memory.content for memory in store}
        added = 0
        for item in CORE_KNOWLEDGE:
            content = str(item["content"])
            if content in existing:
                continue
            store.remember(
                content,
                kind=str(item["kind"]),
                tags=list(item["tags"]),
                importance=float(item["importance"]),
                metadata={"source": "open_mythos_core_seed"},
                save=False,
            )
            existing.add(content)
            added += 1
        if added:
            store.save()
            self._record_source(
                LearnedSource(
                    path="open_mythos_core_seed",
                    memories_added=added,
                    learned_at=_utc_now(),
                )
            )
            self.award_experience(
                min(80, 10 + added * 3),
                "seed-core-knowledge",
                memories_created=added,
                sources_learned=1,
            )
        return added

    def journal(self, role: str, text: str) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        entry = {"at": _utc_now(), "role": role, "text": text}
        with self.journal_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(entry, sort_keys=True) + "\n")

    def remember_exchange(self, user_message: str, assistant_text: str) -> None:
        timestamp = _utc_now()
        self.journal_at(timestamp, "user", user_message)
        self.journal_at(timestamp, "assistant", assistant_text)
        self._append_transcript(timestamp, user_message, assistant_text)
        self.update_continuity(user_message, assistant_text)
        self.award_experience(3, "conversation", interactions=1)

    def journal_at(self, timestamp: str, role: str, text: str) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        entry = {"at": timestamp, "role": role, "text": text}
        with self.journal_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(entry, sort_keys=True) + "\n")

    def _read_journal_entries(self, max_entries: int) -> list[dict[str, object]]:
        if not self.journal_path.exists():
            return []
        lines = self.journal_path.read_text(encoding="utf-8").splitlines()
        entries = []
        for line in lines[-max_entries:]:
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return entries

    def memory_files(self) -> dict[str, Path]:
        return {
            "recall": self.memory_path,
            "transcript": self.transcript_path,
            "journal": self.journal_path,
            "continuity": self.continuity_path,
            "profile": self.profile_path,
            "state": self.state_path,
            "growth": self.growth_path,
        }

    def load_continuity(self) -> ConversationSummary:
        if not self.continuity_path.exists():
            summary = self._continuity_from_journal()
            self.save_continuity(summary)
            return summary
        with self.continuity_path.open("r", encoding="utf-8") as handle:
            raw = json.load(handle)
        summary = ConversationSummary.from_dict(raw)
        user_entries = [
            entry
            for entry in self._read_journal_entries(max_entries=10000)
            if entry.get("role") == "user"
        ]
        if len(user_entries) > summary.exchanges:
            summary = self._continuity_from_journal()
            self.save_continuity(summary)
        return summary

    def _load_continuity_for_append(self) -> ConversationSummary:
        if not self.continuity_path.exists():
            return ConversationSummary.create()
        with self.continuity_path.open("r", encoding="utf-8") as handle:
            raw = json.load(handle)
        return ConversationSummary.from_dict(raw)

    def save_continuity(self, summary: ConversationSummary) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        summary.updated_at = _utc_now()
        payload = asdict(summary)
        with self.continuity_path.open("w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, sort_keys=True)

    def update_continuity(self, user_message: str, assistant_text: str) -> None:
        summary = self._load_continuity_for_append()
        owner = list(summary.recent_owner_messages or [])
        assistant = list(summary.recent_assistant_messages or [])
        threads = list(summary.open_threads or [])

        owner.append(self._compact_continuity_item(user_message))
        assistant.append(self._compact_continuity_item(assistant_text))
        extracted_thread = self._thread_hint(user_message)
        if extracted_thread and extracted_thread.lower() not in {
            item.lower() for item in threads
        }:
            threads.append(extracted_thread)

        summary.exchanges += 1
        summary.recent_owner_messages = owner[-20:]
        summary.recent_assistant_messages = assistant[-12:]
        summary.open_threads = threads[-16:]
        self.save_continuity(summary)

    def continuity_memory(self) -> Memory:
        summary = self.load_continuity()
        return Memory.create(
            kind="conversation-continuity",
            content=summary.to_text(),
            tags=["conversation", "continuity", "resume"],
            importance=2.4,
            metadata={"source": str(self.continuity_path)},
        )

    def _continuity_from_journal(self, max_entries: int = 160) -> ConversationSummary:
        entries = self._read_journal_entries(max_entries=max_entries)
        summary = ConversationSummary.create()
        owner = []
        assistant = []
        threads = []
        for entry in entries:
            role = entry.get("role")
            text = str(entry.get("text", ""))
            if role == "user":
                compacted = self._compact_continuity_item(text)
                owner.append(compacted)
                thread = self._thread_hint(text)
                if thread and thread.lower() not in {
                    item.lower() for item in threads
                }:
                    threads.append(thread)
            elif role == "assistant":
                assistant.append(self._compact_continuity_item(text))

        summary.exchanges = len(owner)
        summary.recent_owner_messages = owner[-20:]
        summary.recent_assistant_messages = assistant[-12:]
        summary.open_threads = threads[-16:]
        return summary

    def recent_conversation(self, limit: int = 8) -> list[tuple[str, str]]:
        entries = self._read_journal_entries(max_entries=max(2, limit * 2))
        return [(str(item["role"]), str(item["text"])) for item in entries]

    def resume_briefing(self) -> str:
        profile = self.load_profile()
        summary = self.load_continuity()
        owner = summary.recent_owner_messages or []
        assistant = summary.recent_assistant_messages or []
        threads = summary.open_threads or []
        lines = [
            "Here is where we left off:",
            f"- Exchanges recorded in continuity: {summary.exchanges}.",
            f"- Last updated: {summary.updated_at}.",
            "",
            "Recent conversation:",
        ]
        if owner:
            lines.extend(f"- You: {item}" for item in owner[-5:])
        else:
            lines.append("- No recent owner messages recorded yet.")
        if assistant:
            lines.extend(f"- {profile.name}: {item}" for item in assistant[-3:])
        if threads:
            lines.extend(["", "Open threads:"])
            lines.extend(f"- {item}" for item in threads[-6:])
        lines.extend(
            [
                "",
                "Best next move:",
                "- Tell me which thread to resume, or say `continue` and I will pick up from the newest active thread.",
            ]
        )
        return "\n".join(lines)

    def learn_path(
        self,
        path: str | Path,
        tags: Iterable[str] | None = None,
        max_chars_per_memory: int = 1400,
    ) -> LearnedSource:
        source = Path(path).expanduser().resolve()
        if not source.exists():
            raise FileNotFoundError(source)

        fingerprint = self._source_fingerprint(source)
        if fingerprint and self._source_already_learned(source, fingerprint):
            learned = LearnedSource(
                path=str(source),
                memories_added=0,
                learned_at=_utc_now(),
                fingerprint=fingerprint,
                skipped=True,
                reason="unchanged-source-already-learned",
            )
            self._record_source(learned)
            return learned

        store = JsonMemoryStore(self.memory_path)
        base_tags = ["knowledge", *(tags or [])]
        before = len(store)
        for file_path in self._iter_text_files(source):
            text = file_path.read_text(encoding="utf-8", errors="ignore").strip()
            if not text:
                continue
            rel = file_path.name if file_path == source else str(file_path)
            for chunk in self._chunk_text(text, max_chars_per_memory):
                store.remember(
                    f"From {rel}: {chunk}",
                    kind="knowledge",
                    tags=base_tags,
                    importance=1.1,
                    metadata={"source_path": str(file_path)},
                    save=False,
                )
        store.save()
        learned = LearnedSource(
            path=str(source),
            memories_added=len(store) - before,
            learned_at=_utc_now(),
            fingerprint=fingerprint,
        )
        self._record_source(learned)
        if learned.memories_added:
            self.award_experience(
                min(120, 15 + learned.memories_added * 5),
                "learn-path",
                memories_created=learned.memories_added,
                sources_learned=1,
            )
        return learned

    def _record_source(self, source: LearnedSource) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        with self.sources_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(asdict(source), sort_keys=True) + "\n")

    def _source_already_learned(self, source: Path, fingerprint: str) -> bool:
        if not self.sources_path.exists():
            return False
        source_path = str(source)
        for line in self.sources_path.read_text(encoding="utf-8").splitlines():
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue
            if (
                entry.get("path") == source_path
                and entry.get("fingerprint") == fingerprint
            ):
                return True
        return False

    def _source_fingerprint(self, source: Path) -> str:
        digest = hashlib.sha256()
        files = list(self._iter_text_files(source))
        if not files:
            return ""
        for file_path in files:
            if file_path == source or not source.is_dir():
                relative = file_path.name
            else:
                relative = str(file_path.relative_to(source))
            digest.update(relative.encode("utf-8", errors="ignore"))
            digest.update(b"\0")
            digest.update(file_path.read_bytes())
            digest.update(b"\0")
        return digest.hexdigest()

    @staticmethod
    def _compact_continuity_item(text: str, max_chars: int = 220) -> str:
        compacted = " ".join(str(text).split())
        if len(compacted) <= max_chars:
            return compacted
        return compacted[: max_chars - 3].rstrip() + "..."

    @classmethod
    def _thread_hint(cls, text: str) -> str:
        compacted = cls._compact_continuity_item(text, max_chars=120)
        lowered = compacted.lower()
        if lowered in {"continue", "where were we?", "where were we"}:
            return ""
        if any(
            marker in lowered
            for marker in (
                "continue",
                "next",
                "fix",
                "improve",
                "memory",
                "gui",
                "hermes",
                "linus",
                "agent",
                "learn",
                "project",
            )
        ):
            return compacted
        return ""

    def _ensure_transcript(self) -> None:
        if self.transcript_path.exists():
            self._refresh_transcript_title()
            return
        for legacy_path in self.legacy_transcript_paths:
            if legacy_path.exists():
                legacy_path.replace(self.transcript_path)
                self._refresh_transcript_title()
                return
        profile = self.load_profile()
        self.root.mkdir(parents=True, exist_ok=True)
        self.transcript_path.write_text(
            f"# {profile.name} Memory\n\n"
            f"This file is {profile.name}'s readable conversation memory. "
            "Every normal chat exchange is appended here.\n",
            encoding="utf-8",
        )

    def _refresh_transcript_title(self) -> None:
        profile = self.load_profile()
        text = self.transcript_path.read_text(encoding="utf-8")
        lines = text.splitlines()
        if not lines:
            return
        expected = f"# {profile.name} Memory"
        if lines[0].startswith("# ") and lines[0].endswith(" Memory"):
            lines[0] = expected
            self.transcript_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    def _append_transcript(
        self,
        timestamp: str,
        user_message: str,
        assistant_text: str,
    ) -> None:
        self._ensure_transcript()
        profile = self.load_profile()
        with self.transcript_path.open("a", encoding="utf-8") as handle:
            handle.write(
                "\n"
                f"## {timestamp}\n\n"
                f"**{profile.owner_name}:** {user_message}\n\n"
                f"**{profile.name}:** {assistant_text}\n"
            )

    def _iter_text_files(self, path: Path) -> Iterable[Path]:
        if path.is_file():
            if self._is_text_file(path):
                yield path
            return

        for item in sorted(path.iterdir()):
            if item.is_dir():
                if item.name in SKIPPED_LEARN_DIRS:
                    continue
                yield from self._iter_text_files(item)
            elif item.is_file() and self._is_text_file(item):
                yield item

    @staticmethod
    def _is_text_file(path: Path) -> bool:
        return path.suffix.lower() in TEXT_SUFFIXES

    @staticmethod
    def _chunk_text(text: str, max_chars: int) -> Iterable[str]:
        paragraphs = [part.strip() for part in text.split("\n\n") if part.strip()]
        chunk = ""
        for paragraph in paragraphs:
            if len(paragraph) > max_chars:
                if chunk:
                    yield chunk
                    chunk = ""
                for start in range(0, len(paragraph), max_chars):
                    yield paragraph[start : start + max_chars]
                continue
            candidate = paragraph if not chunk else chunk + "\n\n" + paragraph
            if len(candidate) > max_chars:
                yield chunk
                chunk = paragraph
            else:
                chunk = candidate
        if chunk:
            yield chunk
