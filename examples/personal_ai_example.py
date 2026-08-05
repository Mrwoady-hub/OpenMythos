from pathlib import Path

from open_mythos.personal_ai import JsonMemoryStore, PersonalAI, PersonalAIProfile


def tiny_demo_generator(prompt: str, **_: object) -> str:
    """A deterministic stand-in so the example runs without model weights."""
    return (
        "I have the context. The next useful step is to turn one preference, "
        "one goal, and one active project into durable memory."
    )


profile = PersonalAIProfile(
    name="Hermes",
    owner_name="Woady",
    traits=("warm", "precise", "playful", "engineering-minded"),
    interests=("AI systems", "creative tools", "long-horizon projects"),
)

memory = JsonMemoryStore(Path("personal_ai_memory.json"))
ai = PersonalAI(profile=profile, memory_store=memory, generator=tiny_demo_generator)

ai.remember(
    "Woady prefers direct implementation with concise status updates.",
    kind="preference",
    tags=["work-style"],
    importance=1.4,
)
ai.remember(
    "OpenMythos is the active local AI architecture project.",
    kind="project",
    tags=["open-mythos"],
    importance=1.2,
)

response = ai.reply("Help me shape this repo into my own personal AI.")

print("Prompt sent to generator:\n")
print(response.prompt)
print("\nAssistant response:\n")
print(response.text)
