from __future__ import annotations

# ruff: noqa: E501

import argparse
import html
import json
import re
import threading
import time
import uuid
from dataclasses import asdict, dataclass, field
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from open_mythos.mind_home import (
    DEFAULT_MIND_NAME,
    MindHome,
    experience_for_level,
    level_from_experience,
)
from open_mythos.personal_ai import (
    BootstrapMindGenerator,
    JsonMemoryStore,
    OllamaGenerator,
    TextGenerator,
    _utc_now,
)
from open_mythos.research import ResearchEngine, looks_like_research_query


TASK_STATUSES = {"queued", "running", "done", "blocked", "error"}
TASK_KINDS = {
    "remember",
    "trust",
    "learn_path",
    "learn_allowed_roots",
    "learn_inbox",
    "seed",
    "reflect",
    "recall",
    "growth_plan",
    "briefing",
}


def requires_research_tools(message: str) -> bool:
    return looks_like_research_query(message)


def looks_like_self_growth_query(message: str) -> bool:
    return bool(
        re.search(
            r"\b(focusing on you|how much (do )?you know|what do you know|"
            r"what do you still need|need to learn|level up (your|you)|"
            r"grow older|grow up|your knowledge|your level|your xp|"
            r"how do you grow|how can you grow)\b",
            message,
            re.I,
        )
    )


def looks_like_briefing_query(message: str) -> bool:
    return bool(
        re.search(
            r"\b(brief me|briefing|status report|mission|what should we do next|"
            r"next move|learn and improve|not where (he|you) need|"
            r"need more out of (him|you)|daily plan)\b",
            message,
            re.I,
        )
    )


def looks_like_resume_query(message: str) -> bool:
    return bool(
        re.search(
            r"\b(where were we|what were we talking about|pick up|resume|"
            r"continue from|continue where|last conversation|our convo|"
            r"what did we talk about)\b",
            message,
            re.I,
        )
        or bool(re.fullmatch(r"\s*continue\s*", message, re.I))
    )


@dataclass
class PermissionPolicy:
    """Permission boundary for resident agent tools."""

    allowed_roots: list[str] = field(default_factory=list)
    allow_shell: bool = False

    @classmethod
    def for_home(
        cls,
        home: MindHome,
        extra_roots: list[str | Path] | None = None,
    ) -> "PermissionPolicy":
        roots = [str(home.root), *(str(Path(root)) for root in extra_roots or [])]
        return cls(allowed_roots=roots)

    def allows_path(self, path: str | Path) -> bool:
        target = Path(path).expanduser().resolve()
        for root in self.allowed_roots:
            allowed = Path(root).expanduser().resolve()
            if target == allowed or allowed in target.parents:
                return True
        return False

    def describe(self) -> dict[str, object]:
        return {"allowed_roots": self.allowed_roots, "allow_shell": self.allow_shell}


@dataclass
class AgentTask:
    id: str
    kind: str
    payload: dict[str, Any] = field(default_factory=dict)
    status: str = "queued"
    created_at: str = field(default_factory=_utc_now)
    updated_at: str = field(default_factory=_utc_now)
    result: dict[str, Any] | None = None
    error: str | None = None

    @classmethod
    def create(cls, kind: str, payload: dict[str, Any] | None = None) -> "AgentTask":
        if kind not in TASK_KINDS:
            raise ValueError(f"Unknown task kind: {kind}")
        return cls(id=uuid.uuid4().hex, kind=kind, payload=dict(payload or {}))

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "AgentTask":
        status = str(value.get("status", "queued"))
        if status not in TASK_STATUSES:
            status = "error"
        return cls(
            id=str(value["id"]),
            kind=str(value["kind"]),
            payload=dict(value.get("payload", {})),
            status=status,
            created_at=str(value.get("created_at", _utc_now())),
            updated_at=str(value.get("updated_at", _utc_now())),
            result=value.get("result"),
            error=value.get("error"),
        )


class ResidentAgent:
    """Local resident agent with a persistent task queue and web API."""

    def __init__(
        self,
        home: MindHome,
        policy: PermissionPolicy | None = None,
        generator: TextGenerator | None = None,
        backend: str = "bootstrap",
        model: str | None = None,
        research_tools: bool = False,
        research_engine: ResearchEngine | None = None,
        auto_reflect_every: int = 0,
    ):
        self.home = home
        self.home.initialize()
        self.policy = policy or PermissionPolicy.for_home(home)
        self.generator = generator
        self.backend = backend
        self.model = model
        self.research_tools = research_tools
        self.research_engine = research_engine
        self.auto_reflect_every = max(0, int(auto_reflect_every))
        self.tasks_path = self.home.root / "tasks.json"
        self._lock = threading.RLock()

    def status(self) -> dict[str, object]:
        profile = self.home.load_profile()
        return {
            "profile": asdict(profile),
            "progress": self.home.progress(),
            "memory_files": {
                key: str(path) for key, path in self.home.memory_files().items()
            },
            "permissions": self.policy.describe(),
            "brain": {
                "backend": self.backend,
                "model": self.model,
                "research_tools": self.research_tools,
                "auto_reflect_every": self.auto_reflect_every,
            },
            "growth_plan": self.growth_plan(),
            "tasks": [asdict(task) for task in self.list_tasks(limit=25)],
        }

    def submit_task(
        self,
        kind: str,
        payload: dict[str, Any] | None = None,
        run_now: bool = False,
    ) -> AgentTask:
        task = AgentTask.create(kind, payload)
        with self._lock:
            tasks = self._load_tasks()
            tasks.append(task)
            self._save_tasks(tasks)
        if run_now:
            self.run_pending(limit=1)
            task = self.get_task(task.id) or task
        return task

    def get_task(self, task_id: str) -> AgentTask | None:
        with self._lock:
            for task in self._load_tasks():
                if task.id == task_id:
                    return task
        return None

    def list_tasks(self, limit: int | None = None) -> list[AgentTask]:
        with self._lock:
            tasks = list(reversed(self._load_tasks()))
        return tasks if limit is None else tasks[:limit]

    def run_pending(self, limit: int | None = None) -> int:
        ran = 0
        while limit is None or ran < limit:
            task = self._claim_next_task()
            if task is None:
                return ran
            self._finish_task(self._execute_task(task))
            ran += 1
        return ran

    def chat(self, message: str) -> dict[str, object]:
        if looks_like_resume_query(message):
            text = self.home.resume_briefing()
            self.home.remember_exchange(message, text)
            self._queue_auto_reflection_if_due()
            return {
                "text": text,
                "recalled_memories": [self.home.continuity_memory().to_dict()],
                "progress": self.home.progress(),
            }
        if looks_like_briefing_query(message):
            text = self.briefing(include_pending_exchange=True)
            self.home.remember_exchange(message, text)
            self._queue_auto_reflection_if_due()
            return {
                "text": text,
                "recalled_memories": [],
                "progress": self.home.progress(),
            }
        if looks_like_self_growth_query(message):
            assessment = self.self_assessment(include_pending_exchange=True)
            self.home.remember_exchange(message, assessment)
            self._queue_auto_reflection_if_due()
            return {
                "text": assessment,
                "recalled_memories": [],
                "progress": self.home.progress(),
            }
        if requires_research_tools(message) and self.research_tools:
            engine = self.research_engine or ResearchEngine()
            researched = engine.answer(message)
            self.home.remember_exchange(message, researched.answer)
            self._queue_auto_reflection_if_due()
            return {
                "text": researched.answer,
                "research": researched.to_dict(),
                "recalled_memories": [],
                "progress": self.home.progress(),
            }
        if requires_research_tools(message):
            text = (
                "No BS: I do not have web, weather, news, pricing, or other "
                "live research tools connected in this resident build yet. "
                "I will not guess. I can answer from saved memory or general "
                "model knowledge, but anything current needs a verified "
                "research tool before I give you an answer."
            )
            self.home.remember_exchange(message, text)
            self._queue_auto_reflection_if_due()
            return {
                "text": text,
                "recalled_memories": [],
                "progress": self.home.progress(),
            }
        ai = self.home.open_ai(generator=self.generator)
        response = ai.reply(
            message,
            conversation=self.home.recent_conversation(limit=8),
            extra_memories=[self.home.continuity_memory()],
            remember_exchange=False,
        )
        self.home.remember_exchange(message, response.text)
        self._queue_auto_reflection_if_due()
        return {
            "text": response.text,
            "recalled_memories": [
                memory.to_dict() for memory in response.recalled_memories
            ],
            "progress": self.home.progress(),
        }

    def self_assessment(self, include_pending_exchange: bool = False) -> str:
        progress = self.home.progress()
        display_experience = int(progress["experience"])
        display_interactions = int(progress["total_interactions"])
        if include_pending_exchange:
            display_experience += 3
            display_interactions += 1
        display_level = level_from_experience(display_experience)
        next_level_xp = experience_for_level(display_level + 1)
        xp_to_next_level = next_level_xp - display_experience
        store = JsonMemoryStore(self.home.memory_path)
        memories = list(store)
        kind_counts: dict[str, int] = {}
        for memory in memories:
            kind_counts[memory.kind] = kind_counts.get(memory.kind, 0) + 1
        known_kinds = ", ".join(
            f"{kind}:{count}" for kind, count in sorted(kind_counts.items())
        )
        sources_count = self._jsonl_count(self.home.sources_path)
        task_count = len(self._load_tasks())
        brain = f"{self.backend}" + (f" ({self.model})" if self.model else "")
        research = "enabled" if self.research_tools else "disabled"

        lines = [
            "No BS self-check:",
            f"- Level: {display_level} ({display_experience} XP, "
            f"{xp_to_next_level} XP to next level).",
            f"- Brain backend: {brain}.",
            f"- Research tools: {research}.",
            f"- Durable memories: {len(memories)}"
            + (f" ({known_kinds})." if known_kinds else "."),
            f"- Learned sources: {sources_count}. Queued/recorded tasks: {task_count}.",
            f"- Conversations recorded: {display_interactions}. "
            f"Trust lessons: {progress['trust_events']}.",
            f"- Auto-reflection: every {self.auto_reflect_every} conversations."
            if self.auto_reflect_every
            else "- Auto-reflection: disabled.",
            "",
            "What I know right now:",
            "- I can use saved memory, journal, level state, task history, Ollama, "
            "and explicit research tools when enabled.",
            "- I know only what has been stored, learned from allowed files, "
            "or verified through connected tools.",
            "",
            "What I still need to grow:",
            "1. More owner-approved source folders and notes to learn from.",
            "2. Reflection jobs that compress conversation history into durable lessons.",
            "3. More trust/correction lessons so I learn your boundaries and standards.",
            "4. Stronger search providers for current facts beyond no-key lookup APIs.",
            "5. More tool permissions, added carefully, for real agent work.",
        ]
        return "\n".join(lines)

    def growth_plan(self) -> dict[str, object]:
        progress = self.home.progress()
        store = JsonMemoryStore(self.home.memory_path)
        memory_count = len(list(store))
        sources_count = self._jsonl_count(self.home.sources_path)
        missing = []
        next_actions = []

        if sources_count == 0:
            missing.append("No learned source folders/files yet.")
            next_actions.append("Queue `learn_allowed_roots` after adding allowed roots.")
        if int(progress["trust_events"]) == 0:
            missing.append("No trust/correction lessons stored yet.")
            next_actions.append("Add trust lessons for boundaries, tone, and mistakes.")
        if not self.auto_reflect_every:
            missing.append("Automatic reflection is disabled.")
            next_actions.append("Restart with `--auto-reflect-every 10`.")
        if not self.research_tools:
            missing.append("Research tools are disabled.")
            next_actions.append("Restart with `--enable-research`.")
        if memory_count < 20:
            missing.append("Durable memory is still shallow.")
            next_actions.append("Seed core knowledge and learn owner-approved notes.")

        return {
            "level": progress["level"],
            "experience": progress["experience"],
            "memory_count": memory_count,
            "learned_sources": sources_count,
            "trust_events": progress["trust_events"],
            "auto_reflect_every": self.auto_reflect_every,
            "research_tools": self.research_tools,
            "missing": missing,
            "next_actions": next_actions,
        }

    def briefing(self, include_pending_exchange: bool = False) -> str:
        progress = self.home.progress()
        display_experience = int(progress["experience"])
        display_interactions = int(progress["total_interactions"])
        if include_pending_exchange:
            display_experience += 3
            display_interactions += 1
        display_level = level_from_experience(display_experience)
        next_level_xp = experience_for_level(display_level + 1)
        xp_to_next_level = next_level_xp - display_experience
        growth = self.growth_plan()
        task_counts: dict[str, int] = {}
        for task in self._load_tasks():
            task_counts[task.status] = task_counts.get(task.status, 0) + 1
        task_summary = ", ".join(
            f"{status}:{count}" for status, count in sorted(task_counts.items())
        )
        recent_themes = self._recent_owner_themes(limit=5)
        next_actions = list(growth["next_actions"])
        if not next_actions:
            next_actions = [
                "Drop owner-approved notes into the inbox and queue `learn_inbox`.",
                "Use `reflect` after meaningful sessions to compress lessons.",
                "Add sharper trust lessons whenever the agent misses your standard.",
            ]

        research_status = (
            "enabled with verification boundaries."
            if self.research_tools
            else "disabled."
        )
        lines = [
            f"{self.home.load_profile().name} growth briefing:",
            f"- Level: {display_level} ({display_experience} XP, "
            f"{xp_to_next_level} XP to next level).",
            f"- Memory: {growth['memory_count']} durable memories, "
            f"{growth['learned_sources']} learned sources, "
            f"{growth['trust_events']} trust lessons.",
            f"- Brain: {self.backend}" + (f" ({self.model})." if self.model else "."),
            f"- Research: {research_status}",
            f"- Conversations recorded: {display_interactions}.",
            f"- Tasks: {task_summary or 'none recorded'}.",
            "",
            "Recent owner themes:",
        ]
        if recent_themes:
            lines.extend(f"- {theme}" for theme in recent_themes)
        else:
            lines.append("- No recent owner themes recorded yet.")

        lines.extend(["", "Weak spots:"])
        missing = list(growth["missing"])
        if missing:
            lines.extend(f"- {item}" for item in missing)
        else:
            lines.append(
                "- Core growth loop is connected; quality now depends on "
                "better inputs and corrections."
            )

        lines.extend(["", "Next moves:"])
        lines.extend(
            f"{index}. {action}" for index, action in enumerate(next_actions, 1)
        )
        return "\n".join(lines)

    def reflect_memory(self, max_entries: int = 40) -> dict[str, object]:
        entries = self._read_journal_entries(max_entries)
        if not entries:
            return {"reflected": False, "message": "No journal entries yet."}

        user_count = sum(1 for entry in entries if entry.get("role") == "user")
        recent = "; ".join(self._recent_owner_themes_from_entries(entries, limit=8))
        content = (
            "Memory reflection: recent conversations included "
            f"{user_count} owner messages. Recent owner themes: {recent}"
        )
        memory = self.home.remember(
            content,
            kind="reflection",
            tags=["reflection", "journal"],
            importance=1.6,
        )
        self.home.award_experience(20, "memory-reflection")
        return {"reflected": True, "memory": memory.to_dict()}

    def _execute_task(self, task: AgentTask) -> AgentTask:
        try:
            if task.kind == "remember":
                content = str(task.payload.get("content", "")).strip()
                if not content:
                    raise ValueError("remember task requires content")
                memory = self.home.remember(
                    content,
                    kind=str(task.payload.get("kind", "owner-note")),
                    tags=list(task.payload.get("tags", ["owner-taught"])),
                    importance=float(task.payload.get("importance", 1.4)),
                )
                task.result = {"memory": memory.to_dict()}
            elif task.kind == "trust":
                content = str(task.payload.get("content", "")).strip()
                if not content:
                    raise ValueError("trust task requires content")
                memory = self.home.trust_lesson(content)
                task.result = {"memory": memory.to_dict()}
            elif task.kind == "learn_path":
                path = Path(str(task.payload.get("path", ""))).expanduser()
                if not self.policy.allows_path(path):
                    task.status = "blocked"
                    task.error = f"Path is outside allowed roots: {path}"
                    return task
                learned = self.home.learn_path(path)
                task.result = asdict(learned)
            elif task.kind == "learn_allowed_roots":
                task.result = {
                    "learned": [
                        asdict(source)
                        for source in self.learn_allowed_roots(
                            include_home=bool(task.payload.get("include_home", False))
                        )
                    ]
                }
            elif task.kind == "learn_inbox":
                task.result = asdict(self.home.learn_path(self.home.inbox_dir))
            elif task.kind == "seed":
                task.result = {"memories_added": self.home.seed_core_knowledge()}
            elif task.kind == "reflect":
                task.result = self.reflect_memory(
                    max_entries=int(task.payload.get("max_entries", 40))
                )
            elif task.kind == "recall":
                query = str(task.payload.get("query", ""))
                memories = self.home.recall(
                    query,
                    limit=int(task.payload.get("limit", 8)),
                )
                task.result = {"memories": [memory.to_dict() for memory in memories]}
            elif task.kind == "growth_plan":
                task.result = self.growth_plan()
            elif task.kind == "briefing":
                task.result = {"briefing": self.briefing()}
            else:
                raise ValueError(f"Unsupported task kind: {task.kind}")
            task.status = "done"
        except Exception as exc:  # pragma: no cover - defensive queue boundary
            task.status = "error"
            task.error = str(exc)
        return task

    def _claim_next_task(self) -> AgentTask | None:
        with self._lock:
            tasks = self._load_tasks()
            for index, task in enumerate(tasks):
                if task.status == "queued":
                    task.status = "running"
                    task.updated_at = _utc_now()
                    tasks[index] = task
                    self._save_tasks(tasks)
                    return task
        return None

    def _finish_task(self, finished: AgentTask) -> None:
        finished.updated_at = _utc_now()
        with self._lock:
            tasks = self._load_tasks()
            for index, task in enumerate(tasks):
                if task.id == finished.id:
                    tasks[index] = finished
                    break
            self._save_tasks(tasks)

    def _load_tasks(self) -> list[AgentTask]:
        if not self.tasks_path.exists():
            return []
        with self.tasks_path.open("r", encoding="utf-8") as handle:
            try:
                raw = json.load(handle)
            except json.JSONDecodeError:
                return []
        return [AgentTask.from_dict(item) for item in raw.get("tasks", [])]

    def _save_tasks(self, tasks: list[AgentTask]) -> None:
        self.tasks_path.parent.mkdir(parents=True, exist_ok=True)
        payload = {"version": 1, "tasks": [asdict(task) for task in tasks]}
        tmp_path = self.tasks_path.with_suffix(".json.tmp")
        with tmp_path.open("w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, sort_keys=True)
        tmp_path.replace(self.tasks_path)

    def learn_allowed_roots(self, include_home: bool = False) -> list[Any]:
        learned = []
        home_root = self.home.root.expanduser().resolve()
        for root in self.policy.allowed_roots:
            path = Path(root).expanduser().resolve()
            if not include_home and path == home_root:
                continue
            if not path.exists():
                continue
            learned.append(self.home.learn_path(path, tags=["allowed-root"]))
        return learned

    def _queue_auto_reflection_if_due(self) -> None:
        if not self.auto_reflect_every:
            return
        interactions = int(self.home.progress()["total_interactions"])
        if interactions == 0 or interactions % self.auto_reflect_every != 0:
            return
        for task in self._load_tasks():
            if task.kind == "reflect" and task.status in {"queued", "running"}:
                return
        self.submit_task(
            "reflect",
            {"max_entries": min(100, self.auto_reflect_every * 4)},
            run_now=False,
        )

    def _read_journal_entries(self, max_entries: int) -> list[dict[str, Any]]:
        if not self.home.journal_path.exists():
            return []
        lines = self.home.journal_path.read_text(encoding="utf-8").splitlines()
        entries = []
        for line in lines[-max_entries:]:
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return entries

    def _recent_owner_themes(self, limit: int = 5) -> list[str]:
        entries = self._read_journal_entries(max(20, limit * 4))
        return self._recent_owner_themes_from_entries(entries, limit=limit)

    @staticmethod
    def _recent_owner_themes_from_entries(
        entries: list[dict[str, Any]],
        limit: int = 5,
    ) -> list[str]:
        themes = []
        seen = set()
        for entry in reversed(entries):
            if entry.get("role") != "user":
                continue
            raw_text = str(entry.get("text", "")).strip()
            text = ResidentAgent._compact_owner_theme(raw_text)
            if not text:
                continue
            key = text.lower()
            if key in seen:
                continue
            seen.add(key)
            themes.append(text)
            if len(themes) >= limit:
                break
        return list(reversed(themes))

    @staticmethod
    def _compact_owner_theme(text: str) -> str:
        if not text:
            return ""
        terminal_markers = (
            "PING ",
            "traceroute ",
            "ip a",
            "ip route",
            "systemctl ",
            "journalctl ",
        )
        if "\n" in text and (
            "$" in text[:200]
            or any(marker in text[:300] for marker in terminal_markers)
        ):
            first_line = next(
                (line.strip() for line in text.splitlines() if line.strip()),
                "terminal output",
            )
            command_match = re.search(r"[$#]\s*(.+)$", first_line)
            command = command_match.group(1).strip() if command_match else first_line
            command = re.sub(r"\s+", " ", command)
            if len(command) > 60:
                command = command[:57].rstrip() + "..."
            return f"Terminal output shared for analysis ({command})."

        compacted = re.sub(r"\s+", " ", text).strip()
        if len(compacted) > 120:
            compacted = compacted[:117].rstrip() + "..."
        return compacted

    @staticmethod
    def _jsonl_count(path: Path) -> int:
        if not path.exists():
            return 0
        return sum(1 for line in path.read_text(encoding="utf-8").splitlines() if line)


class ResidentAgentServer(ThreadingHTTPServer):
    def __init__(self, address: tuple[str, int], agent: ResidentAgent):
        super().__init__(address, ResidentAgentHandler)
        self.agent = agent
        self.worker_stop = threading.Event()
        self.worker_thread: threading.Thread | None = None

    def start_worker(self, interval: float = 0.5) -> None:
        def worker() -> None:
            while not self.worker_stop.is_set():
                self.agent.run_pending(limit=1)
                self.worker_stop.wait(interval)

        self.worker_thread = threading.Thread(target=worker, daemon=True)
        self.worker_thread.start()

    def shutdown(self) -> None:
        self.worker_stop.set()
        super().shutdown()


class ResidentAgentHandler(BaseHTTPRequestHandler):
    server: ResidentAgentServer

    def do_GET(self) -> None:
        path = urlparse(self.path).path
        if path == "/":
            self._send_html(render_app(self.server.agent.status()))
        elif path == "/api/status":
            self._send_json(self.server.agent.status())
        elif path == "/api/tasks":
            tasks = [asdict(task) for task in self.server.agent.list_tasks()]
            self._send_json({"tasks": tasks})
        else:
            self.send_error(HTTPStatus.NOT_FOUND)

    def do_POST(self) -> None:
        path = urlparse(self.path).path
        try:
            payload = self._read_json()
            if path == "/api/chat":
                message = str(payload.get("message", "")).strip()
                if not message:
                    raise ValueError("message is required")
                self._send_json(self.server.agent.chat(message))
            elif path == "/api/tasks":
                task = self.server.agent.submit_task(
                    str(payload.get("kind", "")),
                    dict(payload.get("payload", {})),
                    run_now=bool(payload.get("run_now", False)),
                )
                self._send_json(asdict(task), status=HTTPStatus.CREATED)
            elif path == "/api/run":
                ran = self.server.agent.run_pending(limit=int(payload.get("limit", 1)))
                self._send_json({"tasks_run": ran})
            else:
                self.send_error(HTTPStatus.NOT_FOUND)
        except (TypeError, ValueError) as exc:
            self._send_json({"error": str(exc)}, status=HTTPStatus.BAD_REQUEST)
        except RuntimeError as exc:
            self._send_json({"error": str(exc)}, status=HTTPStatus.BAD_GATEWAY)

    def log_message(self, format: str, *args: Any) -> None:
        return

    def _read_json(self) -> dict[str, Any]:
        length = int(self.headers.get("Content-Length", "0"))
        if length == 0:
            return {}
        raw = self.rfile.read(length).decode("utf-8")
        return json.loads(raw)

    def _send_json(
        self,
        payload: dict[str, Any],
        status: HTTPStatus = HTTPStatus.OK,
    ) -> None:
        body = json.dumps(payload, indent=2, sort_keys=True).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_html(self, body: str) -> None:
        encoded = body.encode("utf-8")
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)


def render_app(status: dict[str, object]) -> str:
    profile = status["profile"]
    progress = status["progress"]
    brain = status["brain"]
    growth = status["growth_plan"]
    name = html.escape(str(profile["name"]))
    level = html.escape(str(progress["level"]))
    xp = html.escape(str(progress["experience"]))
    to_next = html.escape(str(progress["xp_to_next_level"]))
    xp_into = int(progress["xp_into_level"])
    level_span = max(1, int(progress["next_level_xp"]) - int(progress["current_level_xp"]))
    xp_percent = min(100, max(0, round((xp_into / level_span) * 100)))
    backend = html.escape(str(brain["backend"]))
    model = html.escape(str(brain["model"] or "none"))
    research = "online" if brain["research_tools"] else "offline"
    auto_reflect = html.escape(str(brain["auto_reflect_every"]))
    roots = status["permissions"]["allowed_roots"]
    escaped_roots = "".join(f"<li>{html.escape(str(root))}</li>" for root in roots)
    escaped_missing = "".join(
        f"<li>{html.escape(str(item))}</li>" for item in growth["missing"]
    ) or "<li>Core growth systems are connected.</li>"
    escaped_actions = "".join(
        f"<li>{html.escape(str(item))}</li>" for item in growth["next_actions"]
    ) or "<li>Keep teaching, correcting, and assigning work.</li>"
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{name} Resident Agent</title>
  <style>
    :root {{
      color-scheme: dark;
      --bg: #090d12;
      --surface: #101820;
      --surface-2: #16232d;
      --panel: #0d141b;
      --line: #28404e;
      --ink: #eef6f8;
      --muted: #9fb0b8;
      --green: #35d08c;
      --cyan: #4cc9f0;
      --amber: #f6b54d;
      --rose: #f05d7a;
      --violet: #9b7cff;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      font: 15px/1.45 system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      color: var(--ink);
      background: var(--bg);
    }}
    header {{
      display: grid;
      grid-template-columns: minmax(0, 1fr) auto;
      gap: 16px;
      align-items: center;
      padding: 22px clamp(16px, 4vw, 42px);
      border-bottom: 1px solid var(--line);
      background: #101820;
    }}
    h1, h2 {{ margin: 0; line-height: 1.1; letter-spacing: 0; }}
    h1 {{ font-size: clamp(34px, 5vw, 56px); }}
    h2 {{ font-size: 16px; }}
    .subtitle {{ color: var(--muted); margin-top: 6px; }}
    .topline {{
      display: flex;
      flex-wrap: wrap;
      justify-content: flex-end;
      gap: 8px;
    }}
    .pill {{
      border: 1px solid var(--line);
      border-radius: 999px;
      padding: 7px 10px;
      color: var(--ink);
      background: var(--panel);
      font-size: 13px;
      white-space: nowrap;
    }}
    .pill strong {{ color: var(--green); }}
    main {{
      display: grid;
      grid-template-columns: minmax(0, 1.35fr) minmax(300px, .65fr);
      gap: 16px;
      padding: 18px clamp(16px, 4vw, 42px) 36px;
    }}
    section {{
      border: 1px solid var(--line);
      border-radius: 8px;
      background: var(--surface);
      overflow: hidden;
    }}
    .section-head {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 12px;
      padding: 14px 16px;
      border-bottom: 1px solid var(--line);
      background: var(--surface-2);
    }}
    .body {{ padding: 16px; }}
    .controls {{
      display: grid;
      grid-template-columns: repeat(5, minmax(0, 1fr));
      gap: 8px;
      margin-bottom: 14px;
    }}
    .stats {{
      display: grid;
      grid-template-columns: repeat(5, minmax(110px, 1fr));
      gap: 10px;
      margin-bottom: 18px;
    }}
    .stat {{
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 12px;
      background: var(--panel);
      min-height: 78px;
    }}
    .label {{ color: var(--muted); font-size: 12px; text-transform: uppercase; }}
    .value {{ font-size: 24px; font-weight: 700; margin-top: 4px; }}
    .meter {{
      height: 10px;
      overflow: hidden;
      border: 1px solid var(--line);
      border-radius: 999px;
      background: #071017;
      margin-bottom: 16px;
    }}
    .meter span {{
      display: block;
      height: 100%;
      width: {xp_percent}%;
      background: var(--green);
    }}
    textarea, input, select {{
      width: 100%;
      border: 1px solid var(--line);
      border-radius: 6px;
      padding: 10px 12px;
      font: inherit;
      color: var(--ink);
      background: #091119;
    }}
    textarea {{ min-height: 112px; resize: vertical; }}
    button {{
      border: 1px solid transparent;
      border-radius: 6px;
      padding: 10px 14px;
      background: var(--green);
      color: #05100b;
      font-weight: 800;
      cursor: pointer;
    }}
    button.secondary {{ background: var(--cyan); color: #061018; }}
    button.warning {{ background: var(--amber); color: #161006; }}
    button.ghost {{
      border-color: var(--line);
      background: #0b121a;
      color: white;
    }}
    button:hover {{ filter: brightness(1.08); }}
    .row {{ display: grid; grid-template-columns: 1fr auto; gap: 10px; }}
    .stack {{ display: grid; gap: 12px; }}
    .log {{
      min-height: 220px;
      max-height: 420px;
      overflow: auto;
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 12px;
      background: #070d13;
      white-space: pre-wrap;
      color: #dce8ea;
    }}
    .msg {{
      border-left: 3px solid var(--line);
      margin: 0 0 12px;
      padding: 8px 10px;
    }}
    .msg .speaker {{
      display: block;
      font-size: 12px;
      font-weight: 800;
      letter-spacing: .04em;
      text-transform: uppercase;
      margin-bottom: 4px;
    }}
    .msg.user {{
      border-color: var(--amber);
      color: var(--amber);
      background: rgba(246, 181, 77, .08);
    }}
    .msg.agent {{
      border-color: var(--green);
      color: var(--green);
      background: rgba(53, 208, 140, .08);
    }}
    .msg.system {{
      border-color: var(--cyan);
      color: var(--cyan);
      background: rgba(76, 201, 240, .08);
    }}
    ul {{ margin: 8px 0 0; padding-left: 20px; color: #c2d0d5; }}
    code {{ overflow-wrap: anywhere; }}
    @media (max-width: 860px) {{
      header, main {{ grid-template-columns: 1fr; }}
      .stats {{ grid-template-columns: repeat(2, minmax(0, 1fr)); }}
      .controls {{ grid-template-columns: repeat(2, minmax(0, 1fr)); }}
      .row {{ grid-template-columns: 1fr; }}
    }}
  </style>
</head>
<body>
  <header>
    <div>
      <h1>{name}</h1>
      <div class="subtitle">Resident local agent · learn and improve loop</div>
    </div>
    <div class="topline">
      <span class="pill"><strong>Level {level}</strong></span>
      <span class="pill">{xp} XP · {to_next} XP next</span>
      <span class="pill">{backend}: {model}</span>
      <span class="pill">research {research}</span>
      <span class="pill">reflect/{auto_reflect}</span>
    </div>
  </header>
  <main>
    <section>
      <div class="section-head"><h2>Command Console</h2><button class="ghost" id="refresh">Refresh</button></div>
      <div class="body stack">
        <div class="controls">
          <button data-quick="briefing">Brief</button>
          <button class="secondary" data-quick="learn_inbox">Learn Inbox</button>
          <button class="warning" data-quick="reflect">Reflect</button>
          <button class="ghost" data-quick="growth_plan">Growth Plan</button>
          <button class="ghost" id="run-top">Run Queue</button>
        </div>
        <div class="stats">
          <div class="stat"><div class="label">Level</div><div class="value" id="level">{level}</div></div>
          <div class="stat"><div class="label">XP</div><div class="value" id="xp">{xp}</div></div>
          <div class="stat"><div class="label">Memories</div><div class="value" id="memories">{progress["memories_created"]}</div></div>
          <div class="stat"><div class="label">Trust</div><div class="value" id="trust">{progress["trust_events"]}</div></div>
          <div class="stat"><div class="label">Brain</div><div class="value" id="brain">{backend}</div></div>
        </div>
        <div class="meter" aria-label="Level progress"><span id="xp-meter"></span></div>
        <div id="chat" class="log"></div>
        <div class="row">
          <textarea id="message" placeholder="Talk to the resident mind"></textarea>
          <button id="send">Send</button>
        </div>
      </div>
    </section>
    <aside class="stack">
      <section>
        <div class="section-head"><h2>Task Queue</h2><button class="secondary" id="run">Run</button></div>
        <div class="body stack">
          <select id="task-kind">
            <option value="remember">Remember</option>
            <option value="trust">Trust lesson</option>
            <option value="learn_path">Learn path</option>
            <option value="learn_allowed_roots">Learn approved roots</option>
            <option value="learn_inbox">Learn inbox</option>
            <option value="seed">Seed</option>
            <option value="reflect">Reflect</option>
            <option value="recall">Recall</option>
            <option value="growth_plan">Growth plan</option>
            <option value="briefing">Briefing</option>
          </select>
          <input id="task-value" placeholder="Content, path, or query">
          <button id="queue">Queue task</button>
          <div id="tasks" class="log"></div>
        </div>
      </section>
      <section>
        <div class="section-head"><h2>Permissions</h2></div>
        <div class="body">
          <div class="label">Allowed roots</div>
          <ul>{escaped_roots}</ul>
        </div>
      </section>
      <section>
        <div class="section-head"><h2>Growth</h2></div>
        <div class="body">
          <div class="label">Missing</div>
          <ul>{escaped_missing}</ul>
          <div class="label" style="margin-top:12px;">Next actions</div>
          <ul>{escaped_actions}</ul>
        </div>
      </section>
    </aside>
  </main>
  <script>
    const chat = document.querySelector('#chat');
    const tasks = document.querySelector('#tasks');
    const message = document.querySelector('#message');
    const kind = document.querySelector('#task-kind');
    const value = document.querySelector('#task-value');

    async function post(url, body) {{
      const res = await fetch(url, {{
        method: 'POST',
        headers: {{'Content-Type': 'application/json'}},
        body: JSON.stringify(body)
      }});
      return await res.json();
    }}
    function appendMessage(role, speaker, text) {{
      const entry = document.createElement('div');
      entry.className = `msg ${{role}}`;
      const label = document.createElement('span');
      label.className = 'speaker';
      label.textContent = speaker;
      const body = document.createElement('div');
      body.textContent = text;
      entry.append(label, body);
      chat.append(entry);
      chat.scrollTop = chat.scrollHeight;
    }}
    async function refresh() {{
      const res = await fetch('/api/status');
      const data = await res.json();
      document.querySelector('#level').textContent = data.progress.level;
      document.querySelector('#xp').textContent = data.progress.experience;
      document.querySelector('#memories').textContent = data.progress.memories_created;
      document.querySelector('#trust').textContent = data.progress.trust_events;
      document.querySelector('#brain').textContent = data.brain.backend;
      const span = Math.max(1, data.progress.next_level_xp - data.progress.current_level_xp);
      const pct = Math.max(0, Math.min(100, Math.round((data.progress.xp_into_level / span) * 100)));
      document.querySelector('#xp-meter').style.width = `${{pct}}%`;
      tasks.textContent = data.tasks.map(t => {{
        const result = t.result ? ` ${{JSON.stringify(t.result).slice(0, 180)}}` : '';
        return `${{t.status}} ${{t.kind}} ${{t.error || ''}}${{result}}`;
      }}).join('\\n');
    }}
    document.querySelector('#send').onclick = async () => {{
      const text = message.value.trim();
      if (!text) return;
      appendMessage('user', 'you', text);
      message.value = '';
      const data = await post('/api/chat', {{message: text}});
      appendMessage('agent', '{name}', data.text || data.error);
      await refresh();
    }};
    document.querySelector('#queue').onclick = async () => {{
      const selected = kind.value;
      const raw = value.value.trim();
      let payload = {{}};
      if (selected === 'learn_path') payload.path = raw;
      else if (selected === 'recall') payload.query = raw;
      else if (!['seed', 'reflect', 'learn_allowed_roots', 'learn_inbox', 'growth_plan', 'briefing'].includes(selected)) payload.content = raw;
      await post('/api/tasks', {{kind: selected, payload}});
      value.value = '';
      await refresh();
    }};
    document.querySelector('#run').onclick = async () => {{
      await post('/api/run', {{limit: 1}});
      await refresh();
    }};
    document.querySelector('#run-top').onclick = async () => {{
      await post('/api/run', {{limit: 1}});
      await refresh();
    }};
    document.querySelectorAll('[data-quick]').forEach(button => {{
      button.onclick = async () => {{
        const created = await post('/api/tasks', {{kind: button.dataset.quick, run_now: true}});
        appendMessage('system', 'task', `${{created.kind}} ${{created.status}}`);
        if (created.result?.briefing) appendMessage('agent', '{name}', created.result.briefing);
        else if (created.error) appendMessage('system', 'task error', created.error);
        await refresh();
      }};
    }});
    document.querySelector('#refresh').onclick = refresh;
    refresh();
  </script>
</body>
</html>"""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run the OpenMythos resident agent.")
    parser.add_argument("--home", type=Path, default=None)
    parser.add_argument("--name", default=DEFAULT_MIND_NAME)
    parser.add_argument("--owner", default="Woady")
    parser.add_argument(
        "--rename-existing-profile",
        action="store_true",
        help="Update an existing home profile to --name/--owner on startup.",
    )
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument(
        "--backend",
        choices=("ollama", "bootstrap"),
        default="ollama",
        help="Brain backend. Ollama uses a local model; bootstrap is a tiny fallback.",
    )
    parser.add_argument(
        "--model",
        default="gemma4:e4b",
        help="Ollama model to use when --backend ollama.",
    )
    parser.add_argument(
        "--ollama-url",
        default="http://127.0.0.1:11434",
        help="Base URL for Ollama.",
    )
    parser.add_argument(
        "--enable-research",
        action="store_true",
        help="Enable live web/weather research tools with cited answers.",
    )
    parser.add_argument(
        "--weather-location",
        default=None,
        help="Default weather location, e.g. 'Miami, FL'.",
    )
    parser.add_argument(
        "--auto-reflect-every",
        type=int,
        default=0,
        help="Queue a reflection task after this many chat exchanges. 0 disables.",
    )
    parser.add_argument(
        "--allow-root",
        type=Path,
        action="append",
        default=[],
        help="Allow the agent to learn from this file or directory root.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    home = MindHome(args.home)
    home.initialize(
        name=args.name,
        owner_name=args.owner,
        rename_existing=args.rename_existing_profile,
    )
    policy = PermissionPolicy.for_home(home, args.allow_root)
    if args.backend == "ollama":
        generator = OllamaGenerator(model=args.model, base_url=args.ollama_url)
        model = args.model
    else:
        generator = BootstrapMindGenerator()
        model = None
    research_engine = (
        ResearchEngine(default_location=args.weather_location)
        if args.enable_research
        else None
    )
    agent = ResidentAgent(
        home,
        policy=policy,
        generator=generator,
        backend=args.backend,
        model=model,
        research_tools=args.enable_research,
        research_engine=research_engine,
        auto_reflect_every=args.auto_reflect_every,
    )
    server = ResidentAgentServer((args.host, args.port), agent)
    server.start_worker()
    url = f"http://{args.host}:{server.server_port}"
    print(f"{home.load_profile().name} resident agent: {url}")
    print(f"Brain backend: {args.backend}" + (f" ({args.model})" if model else ""))
    print("Research tools: " + ("enabled" if args.enable_research else "disabled"))
    if args.auto_reflect_every:
        print(f"Auto-reflection: every {args.auto_reflect_every} exchanges")
    print(f"Home: {home.root}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print()
    finally:
        server.worker_stop.set()
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
