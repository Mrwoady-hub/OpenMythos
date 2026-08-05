from open_mythos.mind_home import (
    MindHome,
    experience_for_level,
    level_from_experience,
)
from open_mythos.personal_ai import (
    BootstrapMindGenerator,
    JsonMemoryStore,
    OllamaGenerator,
    PersonalAI,
    PersonalAIProfile,
)


def test_memory_store_persists_and_recalls_relevant_memory(tmp_path):
    path = tmp_path / "memory.json"
    store = JsonMemoryStore(path)
    store.remember(
        "The user prefers concise engineering updates.",
        kind="preference",
        tags=["work-style"],
        importance=1.5,
    )
    store.remember(
        "The user enjoys sketching fantasy maps.",
        kind="interest",
        tags=["creative"],
        importance=1.0,
    )

    reloaded = JsonMemoryStore(path)
    recalled = reloaded.recall("How should you update me while coding?", limit=1)

    assert len(reloaded) == 2
    assert recalled[0].kind == "preference"
    assert "concise engineering updates" in recalled[0].content


def test_memory_recall_can_filter_by_tag(tmp_path):
    store = JsonMemoryStore(tmp_path / "memory.json")
    store.remember("Use a calm tone.", kind="preference", tags=["voice"])
    store.remember("Ship a personal AI module.", kind="goal", tags=["project"])

    recalled = store.recall(tags=["project"])

    assert len(recalled) == 1
    assert recalled[0].kind == "goal"


def test_memory_recall_ignores_unrelated_query(tmp_path):
    store = JsonMemoryStore(tmp_path / "memory.json")
    store.remember(
        "OpenMythos uses recurrent depth transformers.",
        kind="knowledge",
        tags=["open-mythos"],
        importance=2.0,
    )

    assert store.recall("you are dumb") == []


def test_personal_ai_prompt_includes_profile_and_memory(tmp_path):
    store = JsonMemoryStore(tmp_path / "memory.json")
    store.remember(
        "The active project is OpenMythos.",
        kind="project",
        tags=["open-mythos"],
    )
    ai = PersonalAI(
        profile=PersonalAIProfile(name="Hermes", owner_name="Woady"),
        memory_store=store,
    )

    prompt, recalled = ai.build_prompt("What should we work on in OpenMythos?")

    assert "You are Hermes, Woady's personal AI." in prompt
    assert "The active project is OpenMythos." in prompt
    assert "Do not invent facts" in prompt
    assert "[Assistant]" in prompt
    assert recalled[0].kind == "project"


def test_reply_uses_generator_and_stores_exchange(tmp_path):
    store = JsonMemoryStore(tmp_path / "memory.json")

    def generator(prompt: str, **kwargs):
        assert "Hello" in prompt
        assert kwargs["temperature"] == 0.2
        return "Hello back."

    ai = PersonalAI(memory_store=store, generator=generator)
    response = ai.reply("Hello", temperature=0.2)

    assert response.text == "Hello back."
    assert len(store.recall(tags=["conversation"])) == 2


def test_bootstrap_mind_generator_can_answer_without_model_weights():
    generator = BootstrapMindGenerator()
    text = generator("[User]\nhello\n\n[Assistant]")

    assert "home" in text.lower()
    assert "memory" in text.lower()


def test_bootstrap_mind_generator_explains_learning_commands():
    generator = BootstrapMindGenerator()
    text = generator("[User]\nlets learn\n\n[Assistant]")

    assert "/remember" in text
    assert "/learn" in text


def test_bootstrap_mind_generator_handles_frustration():
    generator = BootstrapMindGenerator()
    text = generator("[User]\nyou are dumb\n\n[Assistant]")

    assert "bootstrap brain" in text
    assert "ollama" in text


def test_reply_auto_captures_declared_name_and_continuity_summary(tmp_path):
    store = JsonMemoryStore(tmp_path / "memory.json")

    def generator(prompt: str, **kwargs):
        assert "Owner says their name is George." in prompt
        assert "Owner goes by Woady." in prompt
        assert "transitioning into **IT / cybersecurity**" in prompt
        return "I captured that."

    ai = PersonalAI(memory_store=store, generator=generator)
    response = ai.reply(
        "My name is George.\n\n"
        "# Continuity Summary for Woady\n\n"
        "## User Profile & Preferences\n\n"
        "* User goes by **Woady**.\n"
        "* Currently works at Starbucks and is actively transitioning into "
        "**IT / cybersecurity**.\n"
        "* User values practical proof over theory.\n"
    )

    recalled = store.recall("tell me about me", limit=5)

    assert response.text == "I captured that."
    assert any("Owner says their name is George." in item.content for item in recalled)
    assert any("Owner goes by Woady." in item.content for item in recalled)
    assert any(item.kind == "continuity-summary" for item in recalled)


def test_bootstrap_answers_profile_question_from_recalled_memory(tmp_path):
    store = JsonMemoryStore(tmp_path / "memory.json")
    store.remember(
        "Owner goes by Woady and is transitioning into IT / cybersecurity.",
        kind="owner-profile",
        tags=["owner", "profile", "career"],
        importance=2.0,
    )
    ai = PersonalAI(memory_store=store, generator=BootstrapMindGenerator())

    response = ai.reply("tell me about me")

    assert "Based only on saved memory" in response.text
    assert "transitioning into IT / cybersecurity" in response.text


def test_bootstrap_profile_answer_is_grounded_and_structured(tmp_path):
    store = JsonMemoryStore(tmp_path / "memory.json")
    store.remember(
        "Owner-provided continuity summary: # Continuity Summary for Woady "
        "* User goes by **Woady**. * Currently works at Starbucks and is "
        "actively transitioning into **IT / cybersecurity**. "
        "* Main career targets: Entry-level IT Support / Help Desk / Desktop "
        "Support. Longer-term SOC Analyst I / cybersecurity role. "
        "* Likes exact commands, practical proof, and clear win conditions. "
        "## Active Projects ## 1. Linux Cybersecurity Home Lab ## 2. WoadyCompat "
        "## 3. Linux Workstation / Main PC Build. Cybersecurity work must remain "
        "legal, lab-based, authorized, and defensive.",
        kind="continuity-summary",
        tags=["owner", "profile", "continuity"],
        importance=2.2,
    )
    store.remember(
        "Owner says their name is George.",
        kind="owner-profile",
        tags=["owner", "identity", "name"],
        importance=2.4,
    )
    ai = PersonalAI(memory_store=store, generator=BootstrapMindGenerator())

    response = ai.reply("now tell me about me")

    assert response.text.startswith("Based only on saved memory")
    assert "- Name saved in memory: George." in response.text
    assert "- Goes by: Woady." in response.text
    assert "- Current work context: works at Starbucks." in response.text
    assert "Career targets:" in response.text
    assert "Linux Cybersecurity Home Lab" in response.text
    assert "Owner-provided continuity summary" not in response.text
    assert "step-b..." not in response.text


def test_ollama_generator_posts_prompt(monkeypatch):
    class FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, *_):
            return False

        def read(self):
            return b'{"response": "local mind online"}'

    seen = {}

    def fake_urlopen(request, timeout):
        seen["url"] = request.full_url
        seen["body"] = request.data.decode("utf-8")
        seen["timeout"] = timeout
        return FakeResponse()

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)

    generator = OllamaGenerator(model="test-model", timeout=3)
    text = generator("hello")

    assert text == "local mind online"
    assert seen["url"].endswith("/api/generate")
    assert '"model": "test-model"' in seen["body"]
    assert seen["timeout"] == 3


def test_mind_home_initializes_profile_and_memory(tmp_path):
    home = MindHome(tmp_path / "mind")
    ai = home.initialize(name="Hermes", owner_name="Woady")

    assert home.profile_path.exists()
    assert home.memory_path.exists()
    assert home.state_path.exists()
    assert home.transcript_path.exists()
    assert ai.profile.name == "Hermes"
    assert home.recall("home origin", limit=1)[0].kind == "origin"
    assert home.progress()["level"] == 1


def test_mind_home_renames_legacy_damon_profile_to_hermes(tmp_path):
    home = MindHome(tmp_path / "mind")
    home.initialize(name="Damon", owner_name="Woady")

    reopened = MindHome(tmp_path / "mind")
    ai = reopened.initialize()

    assert ai.profile.name == "Hermes"
    assert reopened.load_profile().name == "Hermes"


def test_mind_home_renames_legacy_linus_profile_to_hermes(tmp_path):
    home = MindHome(tmp_path / "mind")
    home.initialize(name="Linus", owner_name="Woady")

    reopened = MindHome(tmp_path / "mind")
    ai = reopened.initialize()

    assert ai.profile.name == "Hermes"
    assert reopened.load_profile().name == "Hermes"


def test_mind_home_migrates_legacy_linus_transcript(tmp_path):
    root = tmp_path / "mind"
    root.mkdir()
    legacy = root / "linus_memory.md"
    legacy.write_text("# Linus Memory\n\nlegacy transcript", encoding="utf-8")

    reopened = MindHome(root)
    reopened.initialize()

    assert reopened.transcript_path.exists()
    assert "# Hermes Memory" in reopened.transcript_path.read_text(encoding="utf-8")
    assert not legacy.exists()


def test_mind_home_learns_text_file(tmp_path):
    home = MindHome(tmp_path / "mind")
    home.initialize()
    source = tmp_path / "notes.md"
    source.write_text(
        "OpenMythos should become a local personal AI mind.\n\n"
        "It should keep learning from owner-provided notes.",
        encoding="utf-8",
    )

    learned = home.learn_path(source, tags=["test-source"])
    recalled = home.recall("owner-provided notes", limit=2)

    assert learned.memories_added >= 1
    assert any("owner-provided notes" in memory.content for memory in recalled)


def test_mind_home_does_not_relearn_unchanged_source(tmp_path):
    home = MindHome(tmp_path / "mind")
    home.initialize()
    source = tmp_path / "notes.md"
    source.write_text("Hermes should grow from clean memory.", encoding="utf-8")

    first = home.learn_path(source, tags=["test-source"])
    second = home.learn_path(source, tags=["test-source"])

    assert first.memories_added == 1
    assert first.fingerprint
    assert second.memories_added == 0
    assert second.skipped is True
    assert second.reason == "unchanged-source-already-learned"


def test_mind_home_skips_dependency_and_repo_cache_dirs_when_learning(tmp_path):
    home = MindHome(tmp_path / "mind")
    home.initialize()
    source = tmp_path / "source"
    source.mkdir()
    (source / "notes.md").write_text(
        "Hermes should learn approved notes.",
        encoding="utf-8",
    )
    venv = source / ".venv"
    git = source / ".git"
    venv.mkdir()
    git.mkdir()
    (venv / "noise.py").write_text(
        "This dependency cache should stay ignored.",
        encoding="utf-8",
    )
    (git / "config").write_text(
        "This repo metadata should stay ignored.",
        encoding="utf-8",
    )

    learned = home.learn_path(source, tags=["test-source"])
    recalled = home.recall("dependency cache repo metadata ignored", limit=5)

    assert learned.memories_added == 1
    assert not any("dependency cache" in memory.content for memory in recalled)
    assert not any("repo metadata" in memory.content for memory in recalled)


def test_mind_home_seeds_core_knowledge_once(tmp_path):
    home = MindHome(tmp_path / "mind")
    home.initialize()

    first = home.seed_core_knowledge()
    second = home.seed_core_knowledge()
    recalled = home.recall("growth path stronger local language model", limit=3)

    assert first > 0
    assert second == 0
    assert any(memory.kind == "growth-plan" for memory in recalled)


def test_mind_home_remember_exchange_appends_readable_transcript(tmp_path):
    home = MindHome(tmp_path / "mind")
    home.initialize(name="Hermes", owner_name="Woady")

    home.remember_exchange("Remember everything.", "I will keep a transcript.")
    text = home.transcript_path.read_text(encoding="utf-8")

    assert "# Hermes Memory" in text
    assert "**Woady:** Remember everything." in text
    assert "**Hermes:** I will keep a transcript." in text
    assert home.journal_path.exists()


def test_mind_home_updates_continuity_and_recent_conversation(tmp_path):
    home = MindHome(tmp_path / "mind")
    home.initialize(name="Hermes", owner_name="Woady")

    home.remember_exchange(
        "We need memory to pick up a convo from anywhere.",
        "I will build continuity.",
    )

    summary = home.load_continuity()
    recent = home.recent_conversation(limit=2)
    memory = home.continuity_memory()
    briefing = home.resume_briefing()

    assert summary.exchanges == 1
    assert "pick up a convo" in summary.recent_owner_messages[-1]
    assert recent[-2][0] == "user"
    assert recent[-1][0] == "assistant"
    assert memory.kind == "conversation-continuity"
    assert "Conversation continuity" in memory.content
    assert "Here is where we left off" in briefing
    assert "pick up a convo" in briefing


def test_mind_home_backfills_continuity_from_existing_journal(tmp_path):
    home = MindHome(tmp_path / "mind")
    home.initialize(name="Hermes", owner_name="Woady")
    home.remember_exchange(
        "We were building stronger continuity memory.",
        "I will backfill from the journal.",
    )
    home.continuity_path.unlink()

    reopened = MindHome(tmp_path / "mind")
    summary = reopened.load_continuity()
    briefing = reopened.resume_briefing()

    assert summary.exchanges == 1
    assert "stronger continuity memory" in summary.recent_owner_messages[-1]
    assert "stronger continuity memory" in briefing


def test_mind_home_transcript_uses_profile_names(tmp_path):
    home = MindHome(tmp_path / "mind")
    home.initialize(name="Echo", owner_name="Ada")

    home.remember_exchange("Use my name.", "I will.")
    text = home.transcript_path.read_text(encoding="utf-8")

    assert "# Echo Memory" in text
    assert "**Ada:** Use my name." in text
    assert "**Echo:** I will." in text


def test_level_progression_is_persistent(tmp_path):
    home = MindHome(tmp_path / "mind")
    home.initialize()

    home.award_experience(75, "test-training")
    progress = home.progress()
    reopened = MindHome(tmp_path / "mind")

    assert experience_for_level(2) == 100
    assert level_from_experience(100) == 2
    assert progress["level"] == 2
    assert progress["xp_to_next_level"] == 300
    assert reopened.progress()["level"] == 2


def test_mind_home_records_trust_lessons_as_high_priority_memory(tmp_path):
    home = MindHome(tmp_path / "mind")
    home.initialize()

    memory = home.trust_lesson("Never delete owner files without explicit approval.")
    progress = home.progress()
    recalled = home.recall("delete owner files approval", limit=1)

    assert memory.kind == "trust-lesson"
    assert "trust" in memory.tags
    assert progress["trust_events"] == 1
    assert recalled[0].id == memory.id


def test_conversation_exchange_increments_persistent_interactions(tmp_path):
    home = MindHome(tmp_path / "mind")
    home.initialize()

    home.remember_exchange("Keep growing.", "I will remember and level from this.")
    progress = home.progress()

    assert progress["total_interactions"] == 1
    assert progress["experience"] >= 28
