from __future__ import annotations

import argparse
import sys
from pathlib import Path

from open_mythos.mind_home import DEFAULT_MIND_NAME, MindHome


HELP = """
Commands:
  /help                 Show this help.
  /home                 Show the mind's local home.
  /memory               Show the mind's memory files.
  /level                Show persistent level and growth progress.
  /remember TEXT        Store a durable memory.
  /trust TEXT           Store a high-priority trust/correction lesson.
  /learn PATH           Learn from a text file or folder.
  /seed                 Add the built-in starter knowledge pack.
  /recall QUERY         Show related memories.
  /quit                 Leave the chat.

Say normal things without a slash when you just want to talk.
""".strip()


def format_progress(progress: dict[str, object]) -> str:
    return (
        f"Level {progress['level']} | XP {progress['experience']} | "
        f"{progress['xp_to_next_level']} XP to level "
        f"{int(progress['level']) + 1}\n"
        f"Interactions: {progress['total_interactions']} | "
        f"Memories: {progress['memories_created']} | "
        f"Sources: {progress['sources_learned']} | "
        f"Trust lessons: {progress['trust_events']}"
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Talk to your OpenMythos mind.")
    parser.add_argument(
        "--home",
        type=Path,
        default=None,
        help="Mind home directory. Defaults to ~/.open_mythos/mind.",
    )
    parser.add_argument(
        "--name",
        default=DEFAULT_MIND_NAME,
        help="Name for first boot.",
    )
    parser.add_argument("--owner", default="Woady", help="Owner name for first boot.")
    parser.add_argument(
        "--backend",
        choices=("ollama", "bootstrap"),
        default="ollama",
        help="Brain backend. Ollama uses a real local model; bootstrap is tiny.",
    )
    parser.add_argument(
        "--model",
        default="gemma4:e4b",
        help="Ollama model to use when --backend ollama.",
    )
    parser.add_argument(
        "--learn",
        type=Path,
        action="append",
        default=[],
        help="Learn from a file or directory before opening chat.",
    )
    parser.add_argument(
        "--seed",
        action="store_true",
        help="Seed the mind with built-in starter knowledge before chat.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    home = MindHome(args.home)
    home.initialize(name=args.name, owner_name=args.owner)
    if args.backend == "ollama":
        ai = home.open_ollama_ai(model=args.model)
    else:
        ai = home.open_ai()

    for path in args.learn:
        learned = home.learn_path(path)
        print(f"Learned {learned.memories_added} memories from {learned.path}")
    if args.seed:
        added = home.seed_core_knowledge()
        print(f"Seeded {added} core memories.")

    print(f"{ai.profile.name} is home: {home.root}")
    model_suffix = f" ({args.model})" if args.backend == "ollama" else ""
    print(f"Brain backend: {args.backend}{model_suffix}")
    print(format_progress(home.progress()))
    print("Type /help for commands, /quit to leave.")

    conversation: list[tuple[str, str]] = []
    while True:
        try:
            user_message = input("\nyou> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return 0

        if not user_message:
            continue
        if user_message == "/quit":
            return 0
        if user_message == "/help":
            print(HELP)
            continue
        if user_message == "/home":
            print(home.root)
            continue
        if user_message == "/memory":
            for label, path in home.memory_files().items():
                print(f"{label}: {path}")
            continue
        if user_message == "/level":
            print(format_progress(home.progress()))
            continue
        if user_message.startswith("/remember "):
            memory = home.remember(
                user_message.removeprefix("/remember ").strip(),
                kind="owner-note",
                tags=["owner-taught"],
                importance=1.4,
            )
            print(f"remembered: {memory.id}")
            print(format_progress(home.progress()))
            continue
        if user_message.startswith("/trust "):
            memory = home.trust_lesson(user_message.removeprefix("/trust ").strip())
            print(f"trust lesson stored: {memory.id}")
            print(format_progress(home.progress()))
            continue
        if user_message.startswith("/learn "):
            path = user_message.removeprefix("/learn ").strip()
            try:
                learned = home.learn_path(path)
            except OSError as exc:
                print(f"could not learn: {exc}")
                continue
            print(f"learned {learned.memories_added} memories from {learned.path}")
            print(format_progress(home.progress()))
            continue
        if user_message == "/seed":
            added = home.seed_core_knowledge()
            if added:
                print(f"seeded {added} core memories")
            else:
                print("core seed is already loaded")
            print(format_progress(home.progress()))
            continue
        if user_message.startswith("/recall "):
            query = user_message.removeprefix("/recall ").strip()
            memories = home.recall(query)
            if not memories:
                print("nothing recalled yet")
                continue
            for memory in memories:
                print(f"- {memory.content}")
            continue
        if user_message.startswith("/"):
            print("unknown command. Type /help to see what I understand.")
            continue

        previous_level = int(home.progress()["level"])
        try:
            response = ai.reply(user_message, conversation=conversation[-8:])
        except RuntimeError as exc:
            print(str(exc))
            continue
        home.remember_exchange(user_message, response.text)
        conversation.append(("user", user_message))
        conversation.append(("assistant", response.text))
        print(f"{ai.profile.name}> {response.text}")
        progress = home.progress()
        if int(progress["level"]) > previous_level:
            print(f"{ai.profile.name} reached level {progress['level']}.")

    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
