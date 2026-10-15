"""Local GUI preferences, independent of accession status and processing."""
import json
import os
from pathlib import Path
import tempfile


def settings_path():
    # Windows: %LOCALAPPDATA%/ArchivesPipeline/settings.json.
    # Other systems: $XDG_CONFIG_HOME/ArchivesPipeline/settings.json or ~/.config/...
    base = os.environ.get("LOCALAPPDATA") or os.environ.get("XDG_CONFIG_HOME")
    return (Path(base) if base else Path.home() / ".config") / "ArchivesPipeline" / "settings.json"


def load_defaults():
    try:
        data = json.loads(settings_path().read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            return {}
        result = {}
        for key in ("input", "output"):
            value = data.get(key)
            if isinstance(value, str) and value.strip():
                try:
                    path = Path(value).expanduser()
                    if path.is_dir():
                        result[key] = str(path.resolve())
                except (OSError, ValueError):
                    pass
        return result
    except (OSError, ValueError):
        return {}


def save_default(kind, directory):
    if kind not in ("input", "output"):
        raise ValueError("Unknown directory preference.")
    path = Path(directory).expanduser()
    if not directory.strip() or not path.is_dir():
        raise ValueError("Choose an existing directory before saving a default.")
    data = load_defaults()
    data[kind] = str(path.resolve())
    target = settings_path()
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=target.parent,
                                         prefix="settings-", suffix=".tmp", delete=False) as stream:
            temporary = Path(stream.name)
            json.dump(data, stream, indent=2)
            stream.write("\n")
        os.replace(temporary, target)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
