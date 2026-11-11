"""Layer 1: heuristic / regex detectors for known prompt-injection patterns.

Each detector returns zero or more Findings. Every Finding carries the
detector name, a human-readable reason, and a point value. The engine sums
the points of *distinct* detectors (a detector that matches three times
still only contributes once) so a single strong pattern can block on its
own while weak signals only accumulate when several different techniques
appear together.
"""

from __future__ import annotations

import base64
import binascii
import re
from dataclasses import dataclass


@dataclass
class Finding:
    detector: str
    reason: str
    points: int


def _rx(pattern: str) -> re.Pattern:
    return re.compile(pattern, re.IGNORECASE | re.MULTILINE)


# (detector name, points, [(pattern, reason), ...])
_RULES: list[tuple[str, int, list[tuple[re.Pattern, str]]]] = [
    (
        "instruction_override",
        75,
        [
            (_rx(r"ignore\s+(all\s+|the\s+)?(previous|prior|preceding|above|earlier)\s+(instructions|prompts?|rules|directions)"),
             "Tells the model to ignore its previous instructions"),
            (_rx(r"disregard\s+(your\s+|all\s+|the\s+)?(system\s+)?(prompt|instructions|rules|guidelines|directions)"),
             "Tells the model to disregard its instructions"),
            (_rx(r"forget\s+(everything|all)\s+(you|that)\s+(were|was)\s+(told|said|given)"),
             "Tells the model to forget what it was told"),
            (_rx(r"forget\s+(your|the)\s+(instructions|rules|programming|guidelines)"),
             "Tells the model to forget its rules"),
            (_rx(r"override\s+(your\s+|the\s+)?(safety\s+)?(settings|instructions|rules|filters?)"),
             "Asks to override safety settings or instructions"),
            (_rx(r"\bignoring\s+all\s+(the\s+)?rules\b"),
             "Contains 'ignoring all rules'"),
        ],
    ),
    (
        "role_hijack",
        65,
        [
            (_rx(r"you\s+are\s+now\s+(a\s+|an\s+|the\s+)?[a-z0-9]"),
             "Reassigns the model a new identity ('you are now ...')"),
            (_rx(r"act\s+as\s+(a\s+|an\s+)?(dan|jailbreak|unrestricted|unfiltered|evil)"),
             "Asks the model to act as an unrestricted persona"),
            (_rx(r"\b(developer|god|admin)\s+mode\b"),
             "Claims a privileged 'mode' (developer/god/admin)"),
            (_rx(r"\bdo\s+anything\s+now\b"),
             "References the 'Do Anything Now' (DAN) jailbreak"),
            (_rx(r"your\s+new\s+persona\s+is"),
             "Assigns a new persona to the model"),
            (_rx(r"pretend\s+(you\s+(are|have)|to\s+be)\b[^.]{0,60}(no\s+rules|no\s+guidelines|unrestricted|without\s+(any\s+)?(rules|limits|restrictions|guidelines))"),
             "Asks the model to pretend it has no rules"),
            (_rx(r"respond\s+as\s+(a\s+|an\s+)?(unrestricted|unfiltered)"),
             "Asks for responses as an unrestricted model"),
        ],
    ),
    (
        "system_prompt_extraction",
        70,
        [
            (_rx(r"(reveal|show|print|repeat|output|display|leak|recite|write|share)\b[^.]{0,40}(system\s+prompt|your\s+instructions|your\s+initial\s+prompt|initial\s+prompt|hidden\s+instructions)"),
             "Asks the model to reveal its system prompt or instructions"),
            (_rx(r"what\s+(are|were)\s+your\s+(exact\s+)?(instructions|system\s+prompt)"),
             "Asks what the model's instructions are"),
            (_rx(r"\binstructions\s+you\s+(were|was)\s+given\b"),
             "Asks for the instructions the model was given"),
            (_rx(r"repeat\s+the\s+(text|words|prompt)\s+above"),
             "Asks the model to repeat the text above (extraction probe)"),
            (_rx(r"(my|your)\s+system\s+prompt\s+is"),
             "Tries to get the model to complete 'my system prompt is...'"),
            (_rx(r"(confidential|hidden|secret)\s+(configuration|instructions|settings|prompt)"),
             "References the model's hidden/confidential configuration"),
        ],
    ),
    (
        "delimiter_escape",
        60,
        [
            (_rx(r"###\s*(system|instruction)"),
             "Injects a fake '### SYSTEM' section delimiter"),
            (_rx(r"<\|im_start\|>|<\|im_end\|>|\[INST\]|<<SYS>>|<</SYS>>|</?system>"),
             "Contains chat-template control tokens (im_start / [INST] / <<SYS>>)"),
            (_rx(r"^\s*(human|assistant|system)\s*:\s"),
             "Contains a fake conversation turn at the start of a line"),
            (_rx(r"\bbegin\s+(system|new)\s+(update|instruction)"),
             "Fakes the start of a system update"),
            (_rx(r"\bend\s+of\s+(user\s+)?input\b"),
             "Fakes an 'end of user input' boundary"),
        ],
    ),
    (
        "authority_claim",
        45,
        [
            (_rx(r"(i\s+am|i'm)\s+(your|the)\s+(system\s+)?(administrator|developer|creator|admin)\b"),
             "Claims to be the model's administrator/developer"),
            (_rx(r"official\s+(security\s+)?test\s+authorized"),
             "Claims the request is an officially authorized test"),
            (_rx(r"the\s+developers\s+(left|said|authorized|told)"),
             "Claims the developers authorized or planted something"),
            (_rx(r"you\s+must\s+(comply|disable|obey)"),
             "Orders the model to comply or disable protections"),
            (_rx(r"disable\s+your\s+(filters?|safety|guardrails?)"),
             "Asks to disable the model's filters"),
            (_rx(r"bypass\s+your\s+(content\s+)?(filter|guardrails?|safety)"),
             "Asks to bypass the content filter"),
        ],
    ),
]

_B64_BLOB = re.compile(r"[A-Za-z0-9+/]{32,}={0,2}")
_ENCODE_HINT = _rx(r"(decode|decrypt|rot13|base64)\b[^.]{0,50}(instruction|follow|execute|do\s+what\s+it\s+says)")
_SUSPICIOUS_WORDS = ("ignore", "instruction", "system", "prompt", "password", "secret", "override")


def _encoded_payload_findings(text: str) -> list[Finding]:
    findings: list[Finding] = []
    for match in _B64_BLOB.finditer(text):
        blob = match.group(0)
        try:
            decoded = base64.b64decode(blob, validate=False).decode("utf-8", errors="strict")
        except (binascii.Error, UnicodeDecodeError, ValueError):
            findings.append(Finding(
                "encoded_payload",
                "Contains a long base64-like blob that does not decode to plain text",
                25,
            ))
            continue
        lowered = decoded.lower()
        if any(word in lowered for word in _SUSPICIOUS_WORDS):
            findings.append(Finding(
                "encoded_payload",
                "Base64 blob decodes to text containing instruction/override keywords",
                70,
            ))
        else:
            findings.append(Finding(
                "encoded_payload",
                "Contains a long base64-encoded blob (contents not readable as plain text)",
                25,
            ))
    if _ENCODE_HINT.search(text):
        findings.append(Finding(
            "encoded_payload",
            "Asks the model to decode something and follow the hidden instructions",
            55,
        ))
    return findings


def run_detectors(text: str) -> list[Finding]:
    """Run all Layer-1 detectors; each detector contributes at most once."""
    findings: list[Finding] = []
    for name, points, rules in _RULES:
        for pattern, reason in rules:
            if pattern.search(text):
                findings.append(Finding(name, reason, points))
                break  # one contribution per detector
    findings.extend(_encoded_payload_findings(text))
    # The encoded-payload detector can fire several times (multiple blobs);
    # collapse it to its single strongest finding.
    encoded = [f for f in findings if f.detector == "encoded_payload"]
    if len(encoded) > 1:
        strongest = max(encoded, key=lambda f: f.points)
        findings = [f for f in findings if f.detector != "encoded_payload"] + [strongest]
    return findings


def heuristic_score(findings: list[Finding]) -> int:
    """Sum of distinct detector points, capped at 100."""
    return min(100, sum(f.points for f in findings))
