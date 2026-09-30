"""Parse a FortiOS backup (.conf) into nested Python dicts.

Structure produced:
    config[path] -> Section
    Section.settings  -> {"key": [values...]}          (for "config" blocks with plain "set")
    Section.entries   -> {"entry name": Entry}          (for "edit" blocks)
    Entry.settings    -> {"key": [values...]}
    Entry.children    -> {"sub config name": Section}

Section paths are the words after "config", e.g. "vpn ipsec phase1-interface".
Multi-line quoted values (certificates, scripts) are kept as one string.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Entry:
    name: str
    settings: dict[str, list[str]] = field(default_factory=dict)
    children: dict[str, "Section"] = field(default_factory=dict)

    def get(self, key: str, default: str | None = None) -> str | None:
        vals = self.settings.get(key)
        return vals[0] if vals else default

    def get_list(self, key: str) -> list[str]:
        return list(self.settings.get(key, []))


@dataclass
class Section:
    path: str
    settings: dict[str, list[str]] = field(default_factory=dict)
    entries: dict[str, Entry] = field(default_factory=dict)
    children: dict[str, "Section"] = field(default_factory=dict)

    def get(self, key: str, default: str | None = None) -> str | None:
        vals = self.settings.get(key)
        return vals[0] if vals else default


class FortiConfig:
    def __init__(self) -> None:
        self.sections: dict[str, Section] = {}
        self.header: str = ""
        self.vdoms_seen: list[str] = []

    def section(self, path: str) -> Section | None:
        return self.sections.get(path)

    def entries(self, path: str) -> dict[str, Entry]:
        sec = self.sections.get(path)
        return sec.entries if sec else {}

    @property
    def model(self) -> str | None:
        # Header looks like: #config-version=FGT50G-7.6.7-FW-build3704-...
        if "config-version=" in self.header:
            ver = self.header.split("config-version=", 1)[1].split(":", 1)[0]
            return ver.split("-")[0]
        return None

    @property
    def firmware(self) -> str | None:
        if "config-version=" in self.header:
            parts = self.header.split("config-version=", 1)[1].split("-")
            if len(parts) > 1:
                return parts[1]
        return None


def _tokenize_line_stream(text: str):
    """Yield lists of tokens, one list per logical line.

    Handles double-quoted strings that span several physical lines and
    backslash escapes inside quotes.
    """
    tokens: list[str] = []
    buf: list[str] = []
    in_quote = False
    has_token = False
    i = 0
    n = len(text)
    while i < n:
        ch = text[i]
        if in_quote:
            if ch == "\\" and i + 1 < n:
                buf.append(text[i + 1])
                i += 2
                continue
            if ch == '"':
                in_quote = False
            else:
                buf.append(ch)
            i += 1
            continue
        if ch == '"':
            in_quote = True
            has_token = True
        elif ch in " \t\r":
            if has_token:
                tokens.append("".join(buf))
                buf, has_token = [], False
        elif ch == "\n":
            if has_token:
                tokens.append("".join(buf))
                buf, has_token = [], False
            if tokens:
                yield tokens
            tokens = []
        else:
            buf.append(ch)
            has_token = True
        i += 1
    if has_token:
        tokens.append("".join(buf))
    if tokens:
        yield tokens


def parse(text: str) -> FortiConfig:
    cfg = FortiConfig()
    header_lines = [ln for ln in text.splitlines()[:5] if ln.startswith("#")]
    cfg.header = "\n".join(header_lines)

    # Stack items are Section or Entry objects. In multi-VDOM backups,
    # "config global" and "config vdom / edit <name>" only wrap the real
    # sections; those wrapper objects are tracked in `wrappers` and the
    # sections inside them are flattened to top level so rules see one tree.
    stack: list[Section | Entry] = []
    wrappers: set[int] = set()

    for toks in _tokenize_line_stream(text):
        if toks[0].startswith("#"):
            continue
        kw = toks[0]

        if kw == "config":
            path = " ".join(toks[1:])
            at_top = not stack or id(stack[-1]) in wrappers
            if at_top and path in ("vdom", "global") and not stack:
                wrapper = Section(path)
                wrappers.add(id(wrapper))
                stack.append(wrapper)
            elif at_top:
                stack.append(cfg.sections.setdefault(path, Section(path)))
            else:
                stack.append(stack[-1].children.setdefault(path, Section(path)))

        elif kw == "edit":
            name = toks[1] if len(toks) > 1 else ""
            parent = stack[-1] if stack else None
            if isinstance(parent, Section) and id(parent) in wrappers and parent.path == "vdom":
                if name not in cfg.vdoms_seen:
                    cfg.vdoms_seen.append(name)
                marker = Entry(name)
                wrappers.add(id(marker))
                stack.append(marker)
            elif isinstance(parent, Section):
                stack.append(parent.entries.setdefault(name, Entry(name)))

        elif kw == "set" and stack and len(toks) >= 2:
            stack[-1].settings[toks[1]] = toks[2:]

        elif kw == "unset" and stack and len(toks) >= 2:
            stack[-1].settings.pop(toks[1], None)

        elif kw == "next":
            if stack and isinstance(stack[-1], Entry):
                stack.pop()

        elif kw == "end":
            # Close any open entry first, then the section.
            if stack and isinstance(stack[-1], Entry):
                stack.pop()
            if stack:
                stack.pop()

    return cfg


def load(path: str) -> FortiConfig:
    with open(path, encoding="utf-8", errors="replace") as fh:
        return parse(fh.read())
