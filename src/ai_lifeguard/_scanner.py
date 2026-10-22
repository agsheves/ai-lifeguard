import re
from fnmatch import fnmatch
from pathlib import Path

SOURCE_EXTENSIONS = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".rb",
    ".go", ".rs", ".java", ".sh", ".bash", ".zsh",
}

CONFIG_EXTENSIONS = {".yaml", ".yml", ".json", ".toml", ".ini"}

SKIP_DIRS = {"node_modules", ".git", "__pycache__", ".venv", "venv", ".tox", "dist", "build"}


def walk_files(directory, extensions=None):
    exts = extensions or SOURCE_EXTENSIONS
    for path in Path(directory).rglob("*"):
        if not path.is_file() or path.suffix not in exts:
            continue
        if SKIP_DIRS & set(path.parts):
            continue
        yield path


def walk_named_files(directory, patterns):
    for path in Path(directory).rglob("*"):
        if not path.is_file() or SKIP_DIRS & set(path.parts):
            continue
        if any(fnmatch(path.name, pat) for pat in patterns):
            yield path


def extract_matches(filepath, pattern):
    try:
        text = filepath.read_text(errors="ignore")
    except (OSError, PermissionError):
        return []
    return [(m.group(), m.start()) for m in pattern.finditer(text)]


def find_strings_in_file(filepath):
    try:
        text = filepath.read_text(errors="ignore")
    except (OSError, PermissionError):
        return []

    strings = []
    for m in re.finditer(r'"""(.*?)"""|\'\'\'(.*?)\'\'\'', text, re.DOTALL):
        strings.append(m.group(1) or m.group(2))
    for m in re.finditer(r'"([^"\\]*(?:\\.[^"\\]*)*)"', text):
        val = m.group(1)
        if len(val) > 40:
            strings.append(val)
    for m in re.finditer(r"'([^'\\]*(?:\\.[^'\\]*)*)'", text):
        val = m.group(1)
        if len(val) > 40:
            strings.append(val)
    return strings
