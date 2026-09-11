#!/usr/bin/env python3
"""
Enigma M4 simulator with deterministic key derivation and authentication.

Two people share a secret SEED (exchanged once, out of band) and a date.
Both independently derive the SAME day's rotor/ring/plugboard/ground
settings from (seed, date, message_number) using HMAC-SHA256 as a KDF.
No settings are ever transmitted -- only ciphertext, with a plaintext
message-number header so the receiver knows which derivation to run.

Every transmission also carries an HMAC-SHA256 authentication tag,
computed with a separate key derived from the same seed. The receiver
verifies the tag before decrypting -- a mismatch means the message was
altered in transit, or the seed/date don't match what the sender used.

Usage:
    python3 enigma_kdf.py encrypt --seed "correct horse battery staple" \\
        --date 2026-09-08 --msg 1 --text "MEET ME AT NOON"

    python3 enigma_kdf.py decrypt --seed "correct horse battery staple" \\
        --date 2026-09-08 --msg 1 --text "<ciphertext>"

    # Or just pipe a full transmission (header + ciphertext) through decrypt:
    python3 enigma_kdf.py decrypt --seed "..." --transmission "1|XKLQP...|a3f9c81b2e047d56"
"""

import argparse
import hashlib
import hmac
import math
import re
import string
import sys
from datetime import date, timezone, datetime

# ---------------------------------------------------------------------------
# Historical M4 rotor wirings (David Hamer reference table).
# Format: wiring = substitution alphabet for A..Z entering from the right.
# notches = letters at which this rotor causes the NEXT rotor to step.
# ---------------------------------------------------------------------------

ROTORS = {
    "I":    {"wiring": "EKMFLGDQVZNTOWYHXUSPAIBRCJ", "notches": "Q"},
    "II":   {"wiring": "AJDKSIRUXBLHWTMCQGZNPYFVOE", "notches": "E"},
    "III":  {"wiring": "BDFHJLCPRTXVZNYEIWGAKMUSQO", "notches": "V"},
    "IV":   {"wiring": "ESOVPZJAYQUIRHXLNFTGKDCMWB", "notches": "J"},
    "V":    {"wiring": "VZBRGITYUPSDNHLXAWMJQOFECK", "notches": "Z"},
    "VI":   {"wiring": "JPGVOUMFYQBENHZRDKASXLICTW", "notches": "ZM"},
    "VII":  {"wiring": "NZJHGRCXMYSWBOUFAIVLPEKQDT", "notches": "ZM"},
    "VIII": {"wiring": "FKQHTLXOCBJSPDZRAMEWNIUYGV", "notches": "ZM"},
}

# Fourth (non-stepping) rotors, M4 only -- no notches, they never turn.
GREEK_ROTORS = {
    "BETA":  "LEYJVCNIXWPBQMDRTAKZGFUHOS",
    "GAMMA": "FSOKANUERHMBTIYCWLQPZXVGJD",
}

# Thin reflectors, M4 only (paired with a Greek rotor).
REFLECTORS_THIN = {
    "B_THIN": "ENKQAUYWJICOPBLMDXZVFTHRGS",
    "C_THIN": "RDOBJNTKVEHMLFCWZAXGYIPSUQ",
}

ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"


# ---------------------------------------------------------------------------
# Seed strength estimate (informational only -- never blocks anything).
# ---------------------------------------------------------------------------

def estimate_entropy_bits(seed: str) -> float:
    """
    Estimate: (character pool size implied by which classes are present)
    ^ (length), dampened by how much of the seed is actually unique.

    Pool*length alone is fooled by repetition -- 'aaaaaaaaaaaaaaaaaaaa' would
    otherwise score as strong purely from length. The unique-character-ratio
    factor corrects for that: a string using few distinct characters (or
    simple alternating/repeating patterns) gets scaled down accordingly.
    This is still a heuristic upper bound, not a guarantee -- a memorized
    natural-language phrase has less true randomness than its raw character
    diversity suggests, since real words are far from uniformly distributed.
    """
    if not seed:
        return 0.0
    length = len(seed)
    pool = 0
    if any(c.islower() for c in seed):
        pool += 26
    if any(c.isupper() for c in seed):
        pool += 26
    if any(c.isdigit() for c in seed):
        pool += 10
    if any(c in string.punctuation for c in seed):
        pool += 32
    if any(c == " " for c in seed):
        pool += 1
    if pool == 0:
        pool = 1
    pool_bits = length * math.log2(pool)
    unique_ratio = len(set(seed)) / length
    return pool_bits * unique_ratio


def entropy_label(bits: float) -> str:
    if bits < 40:
        return "weak"
    elif bits < 70:
        return "moderate"
    elif bits < 100:
        return "strong"
    else:
        return "very strong"


def seed_strength_note(seed: str) -> str:
    bits = estimate_entropy_bits(seed)
    label = entropy_label(bits)
    return f"[seed strength: ~{bits:.0f} bits, estimated {label}]"


# ---------------------------------------------------------------------------
# Key derivation: (seed, date, message_number) -> full M4 daily key
# ---------------------------------------------------------------------------

KDF_VERSION = "v1"  # Bump this if the KDF or primitive (HMAC-SHA256) is ever
                    # replaced. Both sides just need to agree on which version
                    # they're running -- old and new messages never collide,
                    # since the version is baked into every derived key.

def derive_keystream(seed: str, date: str, msg_num: int, num_bytes: int = 64, purpose: str = "ENIGMA") -> bytes:
    """
    HMAC-SHA256-based KDF in counter mode: produces as many pseudorandom
    bytes as needed by hashing seed || version || purpose || context ||
    counter repeatedly. `purpose` domain-separates different uses of the
    same seed (Enigma settings vs. the authentication key below) so that
    knowing one derived value never leaks anything about the other, even
    though both come from the same underlying secret. `KDF_VERSION` is
    folded in so the derivation scheme itself can be replaced later
    without any ambiguity about which version produced a given message.
    """
    context = f"{KDF_VERSION}|{purpose}|{date}|{msg_num}".encode("utf-8")
    key = seed.encode("utf-8")
    out = b""
    counter = 0
    while len(out) < num_bytes:
        block = hmac.new(key, context + counter.to_bytes(4, "big"), hashlib.sha256).digest()
        out += block
        counter += 1
    return out[:num_bytes]


def derive_mac_key(seed: str, date: str, msg_num: int) -> bytes:
    """Separate 32-byte key for authentication, domain-separated from the Enigma settings key."""
    return derive_keystream(seed, date, msg_num, num_bytes=32, purpose="MAC")


MAC_TAG_HEX_LEN = 16  # 8 bytes / 64 bits -- plenty for a friend-to-friend
                       # exercise; full HMAC-SHA256 output is 32 bytes, but
                       # that's overkill length for casual use, so it's
                       # truncated here. Forging a valid tag by guessing
                       # still takes on the order of 2^64 attempts.


def compute_mac(mac_key: bytes, msg_num: int, ciphertext: str) -> str:
    """HMAC-SHA256 tag over the header + ciphertext, truncated and hex-encoded."""
    data = f"{msg_num}|{ciphertext}".encode("utf-8")
    full_digest = hmac.new(mac_key, data, hashlib.sha256).digest()
    tag_bytes = MAC_TAG_HEX_LEN // 2
    return full_digest[:tag_bytes].hex()


def derive_settings(seed: str, date: str, msg_num: int) -> dict:
    """
    Maps a derived keystream onto a full M4 configuration:
      - 3 moving rotors chosen without replacement from I-VIII
      - 1 Greek rotor (Beta/Gamma)
      - matching thin reflector (B_thin/C_thin) -- either is fine, pick one
      - ring settings for all 4 positions
      - ground (start) position for all 4 positions
      - 10 plugboard pairs (derangement over the alphabet)
    """
    ks = derive_keystream(seed, date, msg_num, num_bytes=64)
    idx = 0

    def next_byte():
        nonlocal idx
        b = ks[idx % len(ks)]
        idx += 1
        return b

    # --- Choose 3 distinct moving rotors from I-VIII, order matters ---
    rotor_pool = list(ROTORS.keys())
    moving_rotors = []
    pool = rotor_pool[:]
    for _ in range(3):
        choice = pool.pop(next_byte() % len(pool))
        moving_rotors.append(choice)

    # --- Choose Greek rotor (4th position, non-moving) ---
    greek = "BETA" if next_byte() % 2 == 0 else "GAMMA"

    # --- Choose thin reflector ---
    reflector = "B_THIN" if next_byte() % 2 == 0 else "C_THIN"

    # --- Ring settings: one per position (Greek, then the 3 moving rotors) ---
    rings = [next_byte() % 26 for _ in range(4)]

    # --- Ground (start) position: one per position ---
    ground = [next_byte() % 26 for _ in range(4)]

    # --- Plugboard: derive 10 disjoint pairs (a random derangement-ish pairing) ---
    letters = list(ALPHABET)
    # Fisher-Yates shuffle driven by the keystream
    for i in range(len(letters) - 1, 0, -1):
        j = next_byte() % (i + 1)
        letters[i], letters[j] = letters[j], letters[i]
    plug_pairs = []
    used = set()
    for i in range(0, len(letters)):
        if len(plug_pairs) >= 10:
            break
        a = letters[i]
        if a in used:
            continue
        # find next unused letter to pair with
        for b in letters[i + 1:]:
            if b not in used:
                plug_pairs.append((a, b))
                used.add(a)
                used.add(b)
                break

    return {
        "rotors": moving_rotors,       # left, middle, right (moving)
        "greek": greek,                # leftmost, non-moving
        "reflector": reflector,
        "rings": rings,                # [greek, left, middle, right]
        "ground": ground,              # [greek, left, middle, right]
        "plugboard": plug_pairs,
    }


def format_settings(settings: dict) -> str:
    """
    Human-readable breakdown of a derived key: positions run left-to-right
    as column headers (4th/Greek, Left, Middle, Right), with Rotor, Ring,
    and Start as rows underneath -- plus a quick-copy line for the starting
    position, the sequence of letters you actually dial in before typing.
    """
    position_names = ["4th (Greek)", "Left", "Middle", "Right"]
    rotor_names = [settings["greek"]] + settings["rotors"]
    rings_letters = [ALPHABET[r] for r in settings["rings"]]
    ground_letters = [ALPHABET[g] for g in settings["ground"]]
    plug_str = " ".join(f"{a}{b}" for a, b in settings["plugboard"])

    label_width = 8
    col_width = max(len(p) for p in position_names) + 2

    def row(label, values):
        return label.ljust(label_width) + "".join(v.ljust(col_width) for v in values)

    lines = [
        f"Reflector: {settings['reflector']}",
        "",
        row("", position_names),
        row("Rotor:", rotor_names),
        row("Ring:", rings_letters),
        row("Start:", ground_letters),
        "",
        f"Ring settings, left to right:   {' '.join(rings_letters)}",
        f"Starting position, left to right: {' '.join(ground_letters)}",
        "",
        f"Plugboard: {plug_str}",
    ]
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# M4 Enigma machine
# ---------------------------------------------------------------------------

class Rotor:
    def __init__(self, wiring: str, notches: str, ring: int, position: int, moving: bool):
        self.wiring = wiring
        self.notches = notches
        self.ring = ring          # 0-25
        self.position = position  # 0-25, current rotation
        self.moving = moving

    def at_notch(self) -> bool:
        return ALPHABET[self.position] in self.notches

    def step(self):
        if self.moving:
            self.position = (self.position + 1) % 26

    def forward(self, c: int) -> int:
        # c: 0-25 signal entering from the right
        shifted = (c + self.position - self.ring) % 26
        out = ord(self.wiring[shifted]) - ord("A")
        return (out - self.position + self.ring) % 26

    def backward(self, c: int) -> int:
        shifted = (c + self.position - self.ring) % 26
        out = self.wiring.index(ALPHABET[shifted])
        return (out - self.position + self.ring) % 26


class EnigmaM4:
    def __init__(self, settings: dict):
        rotors = settings["rotors"]     # left, middle, right (moving)
        greek = settings["greek"]
        reflector = settings["reflector"]
        rings = settings["rings"]       # [greek, left, middle, right]
        ground = settings["ground"]     # [greek, left, middle, right]

        self.reflector_wiring = REFLECTORS_THIN[reflector]

        self.greek_rotor = Rotor(GREEK_ROTORS[greek], "", rings[0], ground[0], moving=False)
        self.left = Rotor(ROTORS[rotors[0]]["wiring"], ROTORS[rotors[0]]["notches"], rings[1], ground[1], moving=True)
        self.middle = Rotor(ROTORS[rotors[1]]["wiring"], ROTORS[rotors[1]]["notches"], rings[2], ground[2], moving=True)
        self.right = Rotor(ROTORS[rotors[2]]["wiring"], ROTORS[rotors[2]]["notches"], rings[3], ground[3], moving=True)

        self.plugboard = {}
        for a, b in settings["plugboard"]:
            self.plugboard[a] = b
            self.plugboard[b] = a

    def _step_rotors(self):
        # Standard double-step mechanism (Greek rotor never steps on M4).
        middle_at_notch = self.middle.at_notch()
        right_at_notch = self.right.at_notch()

        if middle_at_notch:
            self.middle.step()
            self.left.step()
        elif right_at_notch:
            self.middle.step()
        self.right.step()

    def _plug(self, ch: str) -> str:
        return self.plugboard.get(ch, ch)

    def encrypt_char(self, ch: str) -> str:
        if ch not in ALPHABET:
            return ch
        self._step_rotors()

        c = ord(self._plug(ch)) - ord("A")
        c = self.right.forward(c)
        c = self.middle.forward(c)
        c = self.left.forward(c)
        c = self.greek_rotor.forward(c)

        c = ord(self.reflector_wiring[c]) - ord("A")

        c = self.greek_rotor.backward(c)
        c = self.left.backward(c)
        c = self.middle.backward(c)
        c = self.right.backward(c)

        out = ALPHABET[c]
        return self._plug(out)

    def process(self, text: str) -> str:
        text = re.sub(r"[^A-Za-z]", "", text).upper()
        return "".join(self.encrypt_char(ch) for ch in text)


# ---------------------------------------------------------------------------
# High-level encrypt / decrypt with plaintext message-number header
# ---------------------------------------------------------------------------

def encrypt_message(seed: str, date: str, msg_num: int, plaintext: str) -> str:
    settings = derive_settings(seed, date, msg_num)
    machine = EnigmaM4(settings)
    ciphertext = machine.process(plaintext)
    mac_key = derive_mac_key(seed, date, msg_num)
    tag = compute_mac(mac_key, msg_num, ciphertext)
    return f"{msg_num}|{ciphertext}|{tag}"


def decrypt_transmission(seed: str, date: str, transmission: str) -> str:
    m = re.match(r"^(\d+)\|([A-Z]*)\|([0-9a-fA-F]{16})$", transmission.strip())
    if not m:
        raise ValueError("Transmission missing <n>|CIPHERTEXT|TAG format.")
    msg_num = int(m.group(1))
    ciphertext = m.group(2)
    tag = m.group(3)

    mac_key = derive_mac_key(seed, date, msg_num)
    expected_tag = compute_mac(mac_key, msg_num, ciphertext)
    if not hmac.compare_digest(tag.lower(), expected_tag.lower()):
        raise ValueError(
            "Authentication failed -- the tag doesn't match. The message may have been "
            "altered in transit, or the seed/date don't match what the sender used."
        )

    settings = derive_settings(seed, date, msg_num)
    machine = EnigmaM4(settings)
    plaintext = machine.process(ciphertext)
    return plaintext


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description=(
            "Enigma M4 simulator with deterministic key derivation.\n\n"
            "You and a friend share one secret SEED phrase (exchanged once, "
            "out of band -- never over this tool). Both sides independently "
            "derive the same day's rotor/ring/plugboard/ground settings from "
            "(seed, date, message number) -- no settings are ever transmitted, "
            "only ciphertext with a plaintext 'n|' header and an authentication "
            "tag, verified on receipt before decrypting."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  Encrypt a message (msg number 1, today's date):\n"
            "    %(prog)s encrypt --seed \"correct horse battery staple\" \\\n"
            "        --msg 1 --text \"MEET ME AT NOON\"\n\n"
            "  Decrypt what you received (paste the whole n|... line):\n"
            "    %(prog)s decrypt --seed \"correct horse battery staple\" \\\n"
            "        --transmission \"1|JXGE EAGC BIFH...|a3f9c81b2e047d56\"\n\n"
            "  Pin a specific date instead of using today (UTC):\n"
            "    %(prog)s encrypt --seed \"...\" --date 2026-09-08 --msg 1 --text \"...\"\n\n"
            "  Inspect the derived Enigma settings without sending anything:\n"
            "    %(prog)s encrypt --seed \"...\" --msg 1 --text \"X\" --show-settings\n"
        ),
    )
    sub = parser.add_subparsers(dest="mode", required=True)

    enc = sub.add_parser(
        "encrypt",
        help="Turn plaintext into an authenticated ciphertext transmission (n|CIPHERTEXT|TAG).",
        description="Encrypt plaintext using settings derived from (seed, date, msg).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "example:\n"
            "  %(prog)s --seed \"correct horse battery staple\" --msg 1 \\\n"
            "      --text \"MEET ME AT NOON\"\n"
            "  -> 1|JXGE EAGC BIFH GZSA ...|a3f9c81b2e047d56\n"
        ),
    )
    enc.add_argument("--seed", required=True, metavar="PHRASE",
                      help="Shared secret phrase, agreed with your friend out of band.")
    enc.add_argument("--date", default=None, metavar="YYYY-MM-DD",
                      help="ISO8601 date. Defaults to today's date in UTC if omitted.")
    enc.add_argument("--msg", required=True, type=int, metavar="N",
                      help="Message number (increment for every message you send this friend today).")
    enc.add_argument("--text", required=True, metavar="TEXT",
                      help="Plaintext to encrypt. Non-letters are stripped, case is ignored.")
    enc.add_argument("--show-settings", action="store_true",
                      help="Print the derived rotor/ring/plugboard/ground settings to stderr.")

    dec = sub.add_parser(
        "decrypt",
        help="Recover plaintext from a received transmission or raw ciphertext.",
        description="Decrypt a transmission using settings re-derived from (seed, date, msg).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  Paste the whole line you received (recommended -- reads the message number\n"
            "  automatically from the header, no need to track it yourself):\n"
            "    %(prog)s --seed \"correct horse battery staple\" \\\n"
            "        --transmission \"1|JXGE EAGC BIFH GZSA...|a3f9c81b2e047d56\"\n\n"
            "  Or supply the message number and raw ciphertext separately:\n"
            "    %(prog)s --seed \"correct horse battery staple\" --msg 1 \\\n"
            "        --text \"JXGE EAGC BIFH GZSA\"\n"
        ),
    )
    dec.add_argument("--seed", required=True, metavar="PHRASE",
                      help="Shared secret phrase, agreed with your friend out of band.")
    dec.add_argument("--date", default=None, metavar="YYYY-MM-DD",
                      help="ISO8601 date. Defaults to today's date in UTC if omitted.")
    dec.add_argument("--show-settings", action="store_true",
                      help="Print the derived rotor/ring/plugboard/ground settings to stderr.")
    group = dec.add_mutually_exclusive_group(required=True)
    group.add_argument("--transmission", metavar="'n|CIPHERTEXT|TAG'",
                        help="The full line you received, header and authentication tag included. Preferred over --msg/--text.")
    group.add_argument("--msg", type=int, metavar="N",
                        help="Message number, if supplying raw ciphertext via --text instead (skips authentication -- no tag to check).")
    dec.add_argument("--text", metavar="CIPHERTEXT",
                      help="Raw ciphertext with no header or tag, used together with --msg. Not authenticated.")

    args = parser.parse_args()

    if args.date is None:
        args.date = datetime.now(timezone.utc).date().isoformat()
        print(f"(no --date given, using today's UTC date: {args.date})", file=sys.stderr)

    print(seed_strength_note(args.seed), file=sys.stderr)

    if args.mode == "encrypt":
        if args.show_settings:
            print(format_settings(derive_settings(args.seed, args.date, args.msg)), file=sys.stderr)
            print("---", file=sys.stderr)
        result = encrypt_message(args.seed, args.date, args.msg, args.text)
        print(result)

    elif args.mode == "decrypt":
        if args.transmission:
            if args.show_settings:
                m = re.match(r"(\d+)\|", args.transmission.strip())
                msg_num = int(m.group(1))
                print(format_settings(derive_settings(args.seed, args.date, msg_num)), file=sys.stderr)
                print("---", file=sys.stderr)
            result = decrypt_transmission(args.seed, args.date, args.transmission)
        else:
            if not args.text:
                parser.error("--text is required when using --msg instead of --transmission")
            if args.show_settings:
                print(format_settings(derive_settings(args.seed, args.date, args.msg)), file=sys.stderr)
                print("---", file=sys.stderr)
            settings = derive_settings(args.seed, args.date, args.msg)
            machine = EnigmaM4(settings)
            result = machine.process(args.text)
        print(result)


if __name__ == "__main__":
    main()
