from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
GATE01_BUILD_ROOT = (REPO_ROOT / "build" / "gate01").resolve()


def relative_to_repo(path: Path) -> Path:
    resolved = path.resolve()
    try:
        return resolved.relative_to(REPO_ROOT)
    except ValueError as exc:
        raise ValueError(f"path is outside repository: {resolved}") from exc


def require_gate01_output(path: Path) -> Path:
    resolved = path.resolve()
    try:
        resolved.relative_to(GATE01_BUILD_ROOT)
    except ValueError as exc:
        raise ValueError(
            f"path is outside Gate 01 build root: {resolved}"
        ) from exc
    if resolved == GATE01_BUILD_ROOT:
        raise ValueError("refusing Gate 01 build root itself as an output target")
    return resolved
