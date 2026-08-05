import json
import urllib.request

from open_mythos.mind_home import MindHome
from open_mythos.research import ResearchAnswer, ResearchSource
from open_mythos.resident_agent import (
    PermissionPolicy,
    ResidentAgent,
    ResidentAgentServer,
    looks_like_briefing_query,
    looks_like_resume_query,
    looks_like_self_growth_query,
    requires_research_tools,
)


def test_resident_agent_runs_remember_task(tmp_path):
    home = MindHome(tmp_path / "mind")
    agent = ResidentAgent(home)

    task = agent.submit_task(
        "remember",
        {"content": "The resident agent should live in my computer."},
        run_now=True,
    )
    recalled = home.recall("resident agent computer", limit=4)

    assert task.status == "done"
    assert any(
        memory.content == "The resident agent should live in my computer."
        for memory in recalled
    )
    assert home.progress()["memories_created"] >= 2


def test_resident_agent_blocks_learning_outside_allowed_roots(tmp_path):
    home = MindHome(tmp_path / "mind")
    secret = tmp_path / "private.txt"
    secret.write_text("do not learn this", encoding="utf-8")
    agent = ResidentAgent(
        home,
        policy=PermissionPolicy.for_home(home, extra_roots=[]),
    )

    task = agent.submit_task("learn_path", {"path": str(secret)}, run_now=True)

    assert task.status == "blocked"
    assert "outside allowed roots" in str(task.error)


def test_resident_agent_learns_inside_allowed_root(tmp_path):
    home = MindHome(tmp_path / "mind")
    source = tmp_path / "notes"
    source.mkdir()
    note = source / "agent.md"
    note.write_text("The local agent needs a task queue.", encoding="utf-8")
    agent = ResidentAgent(
        home,
        policy=PermissionPolicy.for_home(home, extra_roots=[source]),
    )

    task = agent.submit_task("learn_path", {"path": str(note)}, run_now=True)
    recalled = home.recall("task queue", limit=1)

    assert task.status == "done"
    assert task.result["memories_added"] == 1
    assert "task queue" in recalled[0].content


def test_resident_agent_reflects_journal_into_memory(tmp_path):
    home = MindHome(tmp_path / "mind")
    home.initialize()
    home.remember_exchange("I need you to remember everything.", "I will.")
    agent = ResidentAgent(home)

    task = agent.submit_task("reflect", run_now=True)
    recalled = home.recall("recent owner themes remember everything", limit=2)

    assert task.status == "done"
    assert task.result["reflected"] is True
    assert any(memory.kind == "reflection" for memory in recalled)


def test_resident_agent_reflection_keeps_themes_compact(tmp_path):
    home = MindHome(tmp_path / "mind")
    home.initialize()
    long_terminal_output = "ip a\n" + "\n".join(
        f"{index}: synthetic interface output with lots of noisy detail"
        for index in range(30)
    )
    home.remember_exchange(long_terminal_output, "I will analyze it.")
    agent = ResidentAgent(home)

    task = agent.submit_task("reflect", {"max_entries": 10}, run_now=True)
    content = task.result["memory"]["content"]

    assert task.status == "done"
    assert len(content) < 350
    assert "Terminal output shared for analysis" in content
    assert "synthetic interface output" not in content


def test_resident_agent_chat_uses_generator_and_grows(tmp_path):
    home = MindHome(tmp_path / "mind")

    def generator(prompt: str, **kwargs):
        assert "Level" not in prompt
        assert "persistent growth state" in prompt
        return "I am resident now."

    agent = ResidentAgent(home, generator=generator)
    response = agent.chat("Are you here?")

    assert response["text"] == "I am resident now."
    assert home.progress()["total_interactions"] == 1


def test_resident_agent_chat_includes_recent_conversation_and_continuity(tmp_path):
    home = MindHome(tmp_path / "mind")
    home.initialize()
    home.remember_exchange(
        "We were improving Hermes memory.",
        "I will keep continuity.",
    )

    def generator(prompt: str, **kwargs):
        assert "[Recent conversation]" in prompt
        assert "We were improving Hermes memory." in prompt
        assert "Conversation continuity updated" in prompt
        return "I can resume from that context."

    agent = ResidentAgent(home, generator=generator)
    response = agent.chat("tell me more")

    assert response["text"] == "I can resume from that context."
    assert any(
        memory["kind"] == "conversation-continuity"
        for memory in response["recalled_memories"]
    )


def test_resident_agent_resume_query_returns_grounded_continuity(tmp_path):
    home = MindHome(tmp_path / "mind")
    home.initialize()
    home.remember_exchange(
        "We were changing the GUI colors.",
        "You wanted orange for you and green for Hermes.",
    )

    def generator(prompt: str, **kwargs):
        raise AssertionError("resume query must use local continuity")

    agent = ResidentAgent(home, generator=generator)
    response = agent.chat("where were we?")

    assert looks_like_resume_query("where were we?")
    assert looks_like_resume_query("continue")
    assert "Here is where we left off" in response["text"]
    assert "GUI colors" in response["text"]
    assert "orange for you and green for Hermes" in response["text"]


def test_resident_agent_http_status_and_task_api(tmp_path):
    home = MindHome(tmp_path / "mind")
    agent = ResidentAgent(home)
    server = ResidentAgentServer(("127.0.0.1", 0), agent)
    thread = None

    try:
        import threading

        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        base = f"http://127.0.0.1:{server.server_port}"

        status = json.loads(urllib.request.urlopen(base + "/api/status").read())
        assert status["progress"]["level"] == 1

        body = json.dumps(
            {
                "kind": "trust",
                "payload": {"content": "Ask before taking risky actions."},
                "run_now": True,
            }
        ).encode("utf-8")
        request = urllib.request.Request(
            base + "/api/tasks",
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        created = json.loads(urllib.request.urlopen(request).read())

        assert created["status"] == "done"
        assert home.progress()["trust_events"] == 1
    finally:
        server.shutdown()
        server.server_close()
        if thread is not None:
            thread.join(timeout=2)


def test_resident_agent_status_reports_brain_backend(tmp_path):
    home = MindHome(tmp_path / "mind")
    agent = ResidentAgent(
        home,
        generator=lambda prompt, **kwargs: "ok",
        backend="ollama",
        model="test-model",
    )

    status = agent.status()

    assert status["brain"]["backend"] == "ollama"
    assert status["brain"]["model"] == "test-model"


def test_resident_agent_refuses_current_questions_without_research_tools(tmp_path):
    home = MindHome(tmp_path / "mind")

    def generator(prompt: str, **kwargs):
        raise AssertionError("current questions must not call the model")

    agent = ResidentAgent(
        home,
        generator=generator,
        backend="ollama",
        model="test-model",
        research_tools=False,
    )

    response = agent.chat("who is the president")

    assert requires_research_tools("what is the weather today")
    assert "I will not guess" in response["text"]
    assert home.progress()["total_interactions"] == 1


class FakeResearchEngine:
    def answer(self, message):
        return ResearchAnswer(
            answer="Verified weather for Miami: 82°F, partly cloudy.\nSources:\n- Open-Meteo Forecast API: https://open-meteo.com/en/docs",
            verified=True,
            sources=[
                ResearchSource(
                    "Open-Meteo Forecast API",
                    "https://open-meteo.com/en/docs",
                    "Current weather.",
                )
            ],
        )


def test_resident_agent_uses_research_engine_for_current_questions(tmp_path):
    home = MindHome(tmp_path / "mind")

    def generator(prompt: str, **kwargs):
        raise AssertionError("research questions must use tools before the model")

    agent = ResidentAgent(
        home,
        generator=generator,
        backend="ollama",
        model="test-model",
        research_tools=True,
        research_engine=FakeResearchEngine(),
    )

    response = agent.chat("whats the weather in Miami")

    assert response["research"]["verified"] is True
    assert response["research"]["sources"][0]["url"] == "https://open-meteo.com/en/docs"
    assert "Verified weather for Miami" in response["text"]


def test_resident_agent_answers_self_growth_from_local_state(tmp_path):
    home = MindHome(tmp_path / "mind")
    home.initialize()
    home.remember("Hermes should become a stronger resident agent.", kind="goal")

    def generator(prompt: str, **kwargs):
        raise AssertionError("self-growth questions must not call the model")

    agent = ResidentAgent(
        home,
        generator=generator,
        backend="ollama",
        model="test-model",
        research_tools=True,
        research_engine=FakeResearchEngine(),
    )

    message = (
        "we are focusing on you. how much you know and how much you still "
        "need to learn to grow older and level up your knowledge"
    )
    response = agent.chat(message)

    assert looks_like_self_growth_query(message)
    assert not requires_research_tools(message)
    assert "No BS self-check" in response["text"]
    assert f"{response['progress']['experience']} XP" in response["text"]
    assert "Brain backend: ollama (test-model)." in response["text"]
    assert "Durable memories:" in response["text"]
    assert "What I still need to grow:" in response["text"]


def test_resident_agent_learns_all_allowed_roots(tmp_path):
    home = MindHome(tmp_path / "mind")
    source = tmp_path / "approved-notes"
    source.mkdir()
    (source / "growth.md").write_text(
        "Hermes needs owner-approved source folders to grow.",
        encoding="utf-8",
    )
    agent = ResidentAgent(
        home,
        policy=PermissionPolicy.for_home(home, extra_roots=[source]),
    )

    task = agent.submit_task("learn_allowed_roots", run_now=True)
    recalled = home.recall("owner-approved source folders", limit=2)

    assert task.status == "done"
    assert task.result["learned"][0]["memories_added"] == 1
    assert any("source folders" in memory.content for memory in recalled)


def test_resident_agent_learns_inbox(tmp_path):
    home = MindHome(tmp_path / "mind")
    home.initialize()
    (home.inbox_dir / "owner-note.md").write_text(
        "The motto is continue to learn and improve.",
        encoding="utf-8",
    )
    agent = ResidentAgent(home)

    task = agent.submit_task("learn_inbox", run_now=True)
    recalled = home.recall("learn and improve motto", limit=2)

    assert task.status == "done"
    assert task.result["memories_added"] == 1
    assert any("learn and improve" in memory.content for memory in recalled)


def test_resident_agent_queues_auto_reflection_on_interval(tmp_path):
    home = MindHome(tmp_path / "mind")
    agent = ResidentAgent(
        home,
        generator=lambda prompt, **kwargs: "noted",
        auto_reflect_every=2,
    )

    first = agent.chat("first exchange")
    second = agent.chat("second exchange")
    tasks = agent.list_tasks()

    assert first["progress"]["total_interactions"] == 1
    assert second["progress"]["total_interactions"] == 2
    assert any(task.kind == "reflect" and task.status == "queued" for task in tasks)


def test_resident_agent_queues_auto_reflection_for_self_growth_chat(tmp_path):
    home = MindHome(tmp_path / "mind")
    agent = ResidentAgent(home, auto_reflect_every=1)

    response = agent.chat("how much do you know and what do you still need to learn")
    tasks = agent.list_tasks()

    assert "No BS self-check" in response["text"]
    assert any(task.kind == "reflect" and task.status == "queued" for task in tasks)


def test_resident_agent_growth_plan_reports_missing_capabilities(tmp_path):
    home = MindHome(tmp_path / "mind")
    agent = ResidentAgent(home)

    plan = agent.submit_task("growth_plan", run_now=True)

    assert plan.status == "done"
    assert "No learned source folders/files yet." in plan.result["missing"]
    assert "Durable memory is still shallow." in plan.result["missing"]


def test_resident_agent_briefing_is_grounded_and_actionable(tmp_path):
    home = MindHome(tmp_path / "mind")
    home.initialize()
    home.remember_exchange("Hermes needs to improve.", "I will track the gap.")

    def generator(prompt: str, **kwargs):
        raise AssertionError("briefings must come from local state")

    agent = ResidentAgent(home, generator=generator)
    message = "lets continue to learn and improve"
    response = agent.chat(message)
    task = agent.submit_task("briefing", run_now=True)

    assert looks_like_briefing_query(message)
    assert "Hermes growth briefing" in response["text"]
    assert "Weak spots:" in response["text"]
    assert "Next moves:" in response["text"]
    assert "Hermes needs to improve." in response["text"]
    assert task.status == "done"
    assert "Hermes growth briefing" in task.result["briefing"]
