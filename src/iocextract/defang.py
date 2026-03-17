"""Defang / refang helpers.

Defanging rewrites an indicator so it cannot be accidentally clicked or
resolved when pasted into a ticket, chat, or report -- e.g.::

    http://evil.com/x  ->  hxxp://evil[.]com/x
    1.2.3.4            ->  1[.]2[.]3[.]4
    user@evil.com      ->  user[@]evil[.]com

Refanging is the inverse and is deliberately liberal: analysts defang in many
house styles (``[.]``, ``(.)``, ``{.}``, ``[dot]``, ``[at]``,
``hxxp``/``hXXp``) and we want to normalise all of them back before extraction.
"""

from __future__ import annotations

import re

_DEFANG_SCHEME = re.compile(r"http(s?)://", re.IGNORECASE)


def defang(text: str) -> str:
    """Return a safe-to-share, non-clickable version of ``text``."""
    out = _DEFANG_SCHEME.sub(lambda m: f"hxxp{m.group(1)}://", text)
    out = out.replace(".", "[.]")
    out = out.replace("@", "[@]")
    return out


# ``hxxp`` / ``hXXp`` / ``h**p`` -> ``http`` (only when followed by a scheme sep)
_REFANG_SCHEME = re.compile(r"h[x*]{2}p(s?)(?=\[?:?//)", re.IGNORECASE)
# ``[.]`` ``(.)`` ``{.}`` ``[dot]`` -> ``.``
_DOT_BRACKET = re.compile(r"[\[({<]\s*(?:\.|dot)\s*[\])}>]", re.IGNORECASE)
# ``[@]`` ``(at)`` ``[at]`` -> ``@``
_AT_BRACKET = re.compile(r"[\[({<]\s*(?:@|at)\s*[\])}>]", re.IGNORECASE)


def refang(text: str) -> str:
    """Undo common defang styles, normalising ``text`` for extraction."""
    out = _REFANG_SCHEME.sub(lambda m: f"http{m.group(1)}", text)
    out = out.replace("[://]", "://")
    out = _DOT_BRACKET.sub(".", out)
    out = _AT_BRACKET.sub("@", out)
    return out
