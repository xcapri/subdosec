"""
Terminal color scheme for subdosec.

Minimal ANSI color palette — clean, professional, no rainbow spam.
Designed for dark terminals common in security tooling.
"""

import os
import sys


def _supports_color():
    """Check if the terminal supports ANSI colors."""
    if os.getenv("NO_COLOR"):
        return False
    if os.getenv("FORCE_COLOR"):
        return True
    if not hasattr(sys.stdout, "isatty") or not sys.stdout.isatty():
        return False
    if os.name == "nt":
        # Enable ANSI on Windows 10+
        try:
            import ctypes
            kernel32 = ctypes.windll.kernel32
            kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
            return True
        except Exception:
            return False
    return True


_COLOR = _supports_color()


# ── ANSI codes ──────────────────────────────────────────────────

def _code(c):
    return c if _COLOR else ""


# Core palette — muted, not neon
RESET   = _code("\033[0m")
BOLD    = _code("\033[1m")
DIM     = _code("\033[2m")

# Greens — confirmed vuln / success
GREEN   = _code("\033[38;5;114m")    # soft sage green
BGREEN  = _code("\033[1;38;5;114m")  # bold sage

# Reds — errors / critical
RED     = _code("\033[38;5;203m")     # muted coral red
BRED    = _code("\033[1;38;5;203m")   # bold coral

# Yellows — warnings / undetect
YELLOW  = _code("\033[38;5;222m")     # warm amber
BYELLOW = _code("\033[1;38;5;222m")   # bold amber

# Cyan — info / domains / links
CYAN    = _code("\033[38;5;117m")     # soft sky blue
BCYAN   = _code("\033[1;38;5;117m")   # bold sky

# White / Gray — labels, structure
WHITE   = _code("\033[38;5;252m")     # clean white
GRAY    = _code("\033[38;5;245m")     # mid gray
DGRAY   = _code("\033[38;5;239m")     # dark gray

# Purple — AI / special
PURPLE  = _code("\033[38;5;176m")     # soft lavender


# ── Semantic helpers ────────────────────────────────────────────

def vuln(text):
    """Format a VULN tag."""
    return f"{BRED}[VULN]{RESET}"

def undetect(text=""):
    """Format an UNDETECT tag."""
    return f"{YELLOW}[UNDETECT]{RESET}"

def saved():
    """Format a SAVED tag."""
    return f"{GREEN}[SAVED]{RESET}"

def service_tag(name):
    """Format a service name tag like [gohire.io]."""
    return f"{CYAN}[{name}]{RESET}"

def info(msg):
    """Format an [INFO] message."""
    return f"{BCYAN}[INFO]{RESET} {WHITE}{msg}{RESET}"

def warning(msg):
    """Format a [WARNING] message."""
    return f"{BYELLOW}[WARNING]{RESET} {YELLOW}{msg}{RESET}"

def error(msg):
    """Format an [Error] message."""
    return f"{BRED}[Error]{RESET} {RED}{msg}{RESET}"

def success(msg):
    """Format a [Success] message."""
    return f"{BGREEN}[Success]{RESET} {GREEN}{msg}{RESET}"

def domain(url):
    """Format a domain/URL."""
    return f"{WHITE}{url}{RESET}"

def link(url):
    """Format a clickable link."""
    return f"{CYAN}{url}{RESET}"

def label(key, value):
    """Format a key: value pair."""
    return f"  {GRAY}{key:<10}{RESET} : {WHITE}{value}{RESET}"

def separator():
    """Return a styled separator line."""
    return f"{DGRAY}{'-' * 72}{RESET}"

def banner_color(text):
    """Color the ASCII banner."""
    return f"{CYAN}{text}{RESET}"

def fingerprint_line(service, name, status):
    """Format a fingerprint listing line."""
    if "False Positive" in status:
        status_fmt = f"{DGRAY}{status}{RESET}"
    else:
        status_fmt = f"{GREEN}{status}{RESET}"
    return f"{WHITE}{service}{RESET} {DGRAY}|{RESET} {GRAY}{name}{RESET} {status_fmt}"

def path_label(key, path):
    """Format a path output line."""
    return f"{GRAY}{key}\t: {RESET}{CYAN}{path}{RESET}"

def ai_header(text):
    """Format AI analysis header."""
    return f"\n{PURPLE}{BOLD}{text}{RESET}\n"

def ai_result_block(entry):
    """Format a single AI analysis result entry."""
    lines = []
    d = entry.get('DOMAIN', '-')
    cname = entry.get('CNAME', '-')
    a_record = entry.get('A_RECORD') or []
    if not isinstance(a_record, list):
        a_record = [a_record]
    takeover = entry.get('TAKEOVER', '-')
    reason = entry.get('REASON', '-')
    ref = entry.get('LINK_REFERENCE', '-')

    # Takeover status coloring
    if takeover == "POSSIBLE":
        takeover_fmt = f"{BRED}{takeover}{RESET}"
    elif takeover == "NOT":
        takeover_fmt = f"{GREEN}{takeover}{RESET}"
    else:
        takeover_fmt = f"{YELLOW}{takeover}{RESET}"

    lines.append(f"{BCYAN}Domain{RESET}     : {WHITE}{d}{RESET}")
    lines.append(f"  {GRAY}CNAME{RESET}    : {WHITE}{cname}{RESET}")
    lines.append(f"  {GRAY}A Record{RESET} : {WHITE}{', '.join(a_record)}{RESET}")
    lines.append(f"  {GRAY}Takeover{RESET} : {takeover_fmt}")
    lines.append(f"  {GRAY}Reason{RESET}   : {DIM}{reason}{RESET}")
    lines.append(f"  {GRAY}Reference{RESET}: {CYAN}{ref}{RESET}")
    lines.append(separator())
    return "\n".join(lines)
