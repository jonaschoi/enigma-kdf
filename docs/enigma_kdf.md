**What the historical system got wrong, and what this fixes:**

| Historical vulnerability | This system's fix |
|---|---|
| Cillies — operators inventing "random" keys under pressure, defaulting to initials, keyboard runs, memorable words | Settings are derived algorithmically from HMAC-SHA256; no human ever picks a key by hand, so there's nothing for a human bias to leak into |
| Doubled message-key encipherment (the original 1930s flaw Rejewski broke mathematically) | Doesn't exist in this design — there's no message key transmitted or doubled at all |
| Shared Grundstellung across a whole day's naval traffic, enabling depth and Banburismus | Message number is part of the KDF input, so every message — even same day, same pair — gets independently derived settings. No two messages ever share a key, so there's no depth to exploit |
| Bigram tables and the Kenngruppenbuch — physical documents that, if captured (Narvik pinch), exposed the whole indicator system | Nothing physical exists to capture. No codebooks, no bigram tables, no printed key sheets — settings are computed on demand, in memory, from a secret only two people hold |
| The indicator itself, transmitted in the clear (even if bigram-encoded), giving cryptanalysts a structured target | Nothing about the settings is ever transmitted — only ciphertext and a public message number. The receiver re-derives everything independently |
| Reused physical key sheets valid for a whole month, meaning one leak exposed weeks of past/future traffic | Nothing is pre-generated or stored in bulk — each day/message's settings exist only transiently, computed at the moment they're needed |

**What this doesn't fix — still real, and worth remembering:**

- **Enigma's own structural math is untouched.** No letter ever enciphers to itself, the substitution is involutory, and the effective keyspace (~84-bit equivalent for M4) is small by modern standards. A single long, intercepted message is still theoretically breakable via ciphertext-only statistical attacks (the M4 Project's hill-climbing approach), same as any Enigma traffic — the KDF protects how the key is generated and distributed, not the cipher itself.
- **Content discipline is still on you.** Stereotyped openings, repeated phrasing, predictable structure — the cillie-era crib problem — aren't solved by better key management. That's operational hygiene, same advice as several messages back: vary structure, keep messages short and irregular.
- **The seed is now the single point of failure.** All the security that used to depend on codebook secrecy, physical courier security, and operator discipline now depends entirely on one shared secret staying secret. If it leaks, every day and every message number for that pair is retroactively and prospectively exposed — a different failure mode than the historical system, but not a smaller one if it happens.

The overall shift: WWII Enigma failed primarily at *key management* — generating, distributing, and protecting the key material — while the cipher's own math held up reasonably well against anything but dedicated cryptanalysis. This system fixes exactly that layer (generation and distribution) using a modern KDF, while leaving the underlying Enigma mechanism, warts and all, unchanged.