# Enigma KDF

> **Before anything else:** this is a recreational cryptography exercise, not a vetted security tool. It fixes how Enigma's keys were historically generated and shared. It does not change Enigma's own cipher-level math: the keyspace is still small by modern standards, and no letter ever enciphers to itself. Do not use this for anything that actually needs to stay secret. See [Security summary](enigma-kdf-security-summary.md) for the full accounting of what's fixed and what isn't.

Enigma M4, with the key management modernized. Instead of daily key sheets and transmitted indicators, both sides derive identical rotor and plugboard settings from one shared seed, fresh for every date and message.

Historical Enigma was broken mainly through key management failures: reused settings, predictable operator choices, transmitted indicators, not through a flaw in the cipher itself. This project keeps an authentic M4 simulator (real historical rotor wirings, the real double-step mechanism) and replaces everything around it with a modern key derivation function and a real authentication tag.

## What's here

| File | What it is |
|---|---|
| `enigma_kdf.py` | Command-line tool. Encrypt and decrypt from a terminal. |
| `enigma_kdf.html` | Same tool, as a single offline HTML file. No install, no dependencies, runs in any browser. Byte-compatible with the CLI: a message encrypted in one decrypts correctly in the other. |
| `enigma-kdf-slides.html` | The security summary as a short slide deck. |
| `enigma-kdf-security-summary.md` | What this system fixes from historical Enigma, what's still vulnerable, and what was deliberately left unfixed. |
| `operator-hygiene-guidelines.md` | Human discipline the system depends on but can't enforce: seed handling, message numbering, content hygiene. Read this before actually using the tool with someone. |

## Quick start

Encrypt a message:

```
python3 enigma_kdf.py encrypt --seed "your shared phrase" --msg 1 --text "MEET ME AT NOON"
```

Decrypt what you received:

```
python3 enigma_kdf.py decrypt --seed "your shared phrase" --transmission "1|JXGEEAGCBIFHGZSA...|a3f9c81b2e047d56"
```

`--date` defaults to today's date in UTC if omitted. Run `python3 enigma_kdf.py -h` for the full option list and more examples. The HTML tool exposes the same functionality through a form instead of flags.

## How it works

Two people share one secret (the seed), exchanged once, out of band. For every message, both sides independently compute:

```
HMAC-SHA256(seed, "v1|ENIGMA|date|message_number") → rotor order, ring settings, plugboard, starting position
HMAC-SHA256(seed, "v1|MAC|date|message_number")     → a separate key used to authenticate the message
```

No settings are ever transmitted. Only ciphertext and a public message number cross the wire, along with a short authentication tag that's verified before anything gets decrypted. Every message gets independent settings, so two messages never share a key the way historical Enigma traffic often did.

Full details, including the exact rotor wirings and the KDF-to-parameter mapping, are in the source.

## What this actually fixes, and what it doesn't

Fixed: operators inventing weak keys under pressure (cillies), the shared daily settings that enabled Banburismus, physical key material that exposed weeks of traffic if captured, indicators transmitted in the clear, and the complete absence of message authentication in the original machine.

Not fixed, because it can't be without changing what this is: Enigma's own bounded keyspace, the fact that no letter can encipher to itself, and the lack of forward secrecy, since every key is always re-derivable from the same seed. The shared seed is now the single point of failure. If it leaks, every past and future message for that pair is exposed at once.

Full writeup in [enigma-kdf-security-summary.md](enigma-kdf-security-summary.md).

## Before you use this with someone

The math doesn't protect you from a weak seed, a reused message number, or a compromised device. Read [operator-hygiene-guidelines.md](operator-hygiene-guidelines.md) first.

## Credits

Rotor wirings and stepping mechanism are historical public record (the Dr. David Hamer reference table). The ciphertext-only cryptanalysis discussion in the security summary draws on the real 2006 M4 Project, which broke genuine unsolved 1942 U-boat traffic using the same hill-climbing approach described there.

## License

MIT. See [LICENSE.md](LICENSE.md).
