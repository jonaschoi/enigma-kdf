# Operator Hygiene Guidelines

These cover human discipline around the system, not how to run the tool. None of this is enforced by the math. It's on you and whoever you're communicating with.

## Seed management

- Never reuse a seed across relationships. One seed per pair. Reusing a seed with more than two people collapses the isolation the system depends on: anyone holding it can read traffic meant for someone else.
- Exchange the seed out of band, once. In person or over a call, the same way you'd trust someone with a physical key. Never send it through the same channel you send ciphertext through.
- Don't let the seed sync anywhere unintended. Typing it into a notes app or password manager that syncs to the cloud reintroduces the transmission risk the system was built to avoid.
- Aim for real entropy, not just length. A seed should be genuinely random, or a long unpredictable multi-word phrase. Not a memorable phrase you'd also use elsewhere.
- If you suspect the seed leaked, stop using it. Agree on a replacement out of band the same way you agreed on the original. There's no safe way to rotate a compromised seed through the same channel it may have leaked from.

## Message discipline

- Never reuse a message number for the same pair on the same day. Reusing (seed, date, message number) produces the identical key twice, the same depth weakness that historically enabled Banburismus. Increment for every message you send that person that day.
- Reject a message number you've already seen from that pair. The authentication tag proves a message wasn't altered. It doesn't prove it wasn't captured and resent later. Treating a repeated number as suspicious is the replay defense the tag alone can't provide.
- Agree on date format and timezone in advance. A mismatch won't leak anything, but it will silently produce undecryptable messages.

## Content discipline

- Avoid formulaic or stereotyped openings and closings. Predictable structure is what historical crib attacks were built on. Varied phrasing gives an attacker nothing to anchor a known-plaintext guess against.
- Keep messages short and irregular in length where practical. Longer, more uniform messages give ciphertext-only statistical attacks more signal to work with.
- Don't insert a marker character, like the historical "X", for spaces or punctuation. Running words together removes a predictable structural pattern a statistical attack could use as an extra signal. It's less pleasant to read, but it's the more defensible default.
- An unusual shared language raises the bar slightly. It isn't a real barrier and shouldn't be treated as the main defense.

## Operational hygiene

- Watch the endpoints, not just the cipher. A keylogger, a shared or unlocked device, or a compromised copy of the tool defeats everything upstream of it. The cryptography can't protect a seed typed on a compromised machine.
- Verify you're running an unmodified copy of the tool, especially if it's been copied around or handed off. A silently altered copy could leak the seed or weaken the derivation with no visible sign in the output.
- Don't discuss message content or seed details in the same channel used to send ciphertext, if that channel isn't itself trusted. Treat the ciphertext channel as public.

## What none of this fixes

Even with perfect discipline, this only protects key management: how the key is generated, shared, and used. It doesn't change Enigma's own mathematical limits, the small effective keyspace by modern standards, and the fact that no letter ever enciphers to itself. Good discipline makes those limits harder to reach in practice. It doesn't remove them.
