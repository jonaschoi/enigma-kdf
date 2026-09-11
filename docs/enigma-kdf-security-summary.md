# Enigma KDF: What's Fixed, What Isn't

## What this system fixes

Historical Enigma's failures were almost entirely in key management: how keys were generated, shared, and reused, not in the cipher's own math. This system replaces that layer.

| Historical vulnerability | How it's fixed here |
|---|---|
| Cillies: operators inventing "random" keys under pressure, defaulting to initials, keyboard runs, memorable words | Settings are derived algorithmically via HMAC-SHA256. No human picks a key by hand, so there's no human bias to exploit. |
| Doubled message-key encipherment, the 1930s flaw Rejewski broke mathematically | Doesn't exist in this design. No message key is ever encrypted and transmitted. It's derived independently by both sides. |
| Shared Grundstellung across a day's traffic, which enabled depth and Banburismus | Message number is part of the KDF input. Every message gets an independently derived key. No two messages share settings, so there's no depth to find. |
| Physical key material: Kenngruppenbuch, bigram tables, captured once and exposing weeks of traffic (the Narvik pinch) | Nothing physical exists. No codebooks, no printed sheets. Settings are computed on demand, in memory, from a secret only two people hold. |
| Indicator transmitted in the clear, even bigram-encoded, giving cryptanalysts a structured daily target | Nothing about the settings is ever transmitted. Only ciphertext and a public message number cross the wire. The receiver re-derives everything. |
| Monthly key sheets, where one leak exposed weeks of past and future traffic | Nothing is pre-generated or stored in bulk. Each message's settings exist only transiently, computed when needed. |
| No integrity or authentication protection: a tampered ciphertext just decrypted to different but plausible garbage | Every transmission carries an HMAC-SHA256 tag, computed with a key derived separately from the same seed. The receiver verifies the tag before decrypting. A mismatch means the message was altered or the seed/date don't match. |

## What's still vulnerable

### Enigma's own cryptographic limits
The KDF protects how the key is generated and distributed. It does nothing to change the cipher itself. Enigma's structural weaknesses are untouched:
- No letter can ever encipher to itself.
- The substitution is involutory: encryption and decryption are the same operation.
- The effective keyspace is roughly equivalent to an 84-bit key, small by modern standards though not casually brute-forceable.

### Ciphertext-only statistical cryptanalysis
With no crib and no depth available, an attacker's real remaining option is the modern hill-climbing/genetic-algorithm approach, the method behind the M4 Project's real 2006 breaks of 1942 traffic: brute-force the rotor order, ring settings, and starting position, then recover the plugboard by iteratively improving a candidate's fit against language statistics.

This is expensive but real. It's how every actually-unsolved WWII Enigma message that's since been broken was broken.

Message length matters a lot. Published successful attacks on plugboard-equipped Enigma have generally needed messages in the 200-450+ character range; earlier techniques needed as many as 647. A short message, under roughly 150 characters, sits below where these techniques reliably converge. That's a real advantage of keeping messages brief, not just a theoretical one.

Success only costs one message. A fully successful break of a single intercepted message reveals nothing about any other message, day, or pair, since each one is derived independently. There's no cascading exposure the way there was historically.

### The seed is the single point of failure
Every protection above assumes the seed stays secret. If it leaks, all past and future messages for that pair become instantly and permanently readable. There's no way to rotate away from a compromised seed except agreeing on an entirely new one out of band.

This design also has no forward secrecy. Unlike systems with ratcheting, such as Signal, every day's key is always re-derivable from the same seed, forever. Compromise isn't limited to messages already sent; it exposes the whole timeline, past and future, until the seed is replaced.

### Authentication is real but has two limits
The HMAC tag proves the sender held the correct seed and that the ciphertext wasn't altered in transit. Two things it doesn't give you:

It can't distinguish the two of you. Since the scheme is symmetric and only two people ever hold the seed, a valid tag proves someone with this seed sent the message, not specifically which of the two of you sent it. That's inherent to any symmetric-key scheme, not a gap in this implementation. Distinguishing the two parties would require asymmetric signatures, a meaningfully bigger addition.

It doesn't stop replay. A valid tag doesn't prove a message wasn't simply captured and resent later. That's handled operationally: reject any message number you've already seen from that pair, the same discipline already required to avoid key reuse.

The tag itself is truncated to 16 hex characters (64 bits) rather than the full 32-byte HMAC-SHA256 output, for readability. Forging a valid truncated tag by guessing still takes on the order of 2^64 attempts, comfortably out of reach for a casual exercise, even though it's a real reduction from full-strength 256-bit output.

### No metadata protection
The date and message number travel in the clear, on purpose, since that removes the need to transmit key material. But it also means an observer always knows when messages were sent and roughly how many a pair has exchanged on a given day, even without breaking anything. This system hides content. It doesn't hide the existence or pattern of communication.

### Dependence on the underlying primitives
Security assumes HMAC-SHA256 remains sound. Quantum computing's known impact here, Grover's algorithm, only halves the effective bit-strength through a brute-force speedup: erosion, not a break. Every derived key includes a version marker (v1) in its KDF context, but that marker isn't transmitted. Both sides still need to agree in advance which version they're running, the same way they agree on date format. If that ever falls out of sync, the result is a clean authentication failure instead of silent garbage: a louder failure mode, not automatic version detection.

## Solvable, but deliberately left as-is

Two issues have straightforward fixes that were considered and intentionally not implemented, since this system is for a casual exercise rather than anything that needs to withstand serious pressure.

Plaintext length is leaked exactly. Enigma is a 1:1 letter substitution, so ciphertext length always reveals exact message length. Padding to a fixed block size, with the receiver stripping filler via a length marker derived from the same seed, would close this. Not implemented, by choice.

Message-number reuse and replay are operator discipline, not system-enforced. The tool has no memory between runs, so nothing stops reusing a message number or replaying a captured message. A local ledger of used message numbers per seed could make the tool refuse both automatically. Not implemented, by choice; see the operator hygiene guidelines for the manual version of this discipline instead.

### Everything operator-dependent
Seed secrecy, seed strength, message-number discipline, endpoint security, and content hygiene are all necessary conditions this system relies on but cannot enforce. See the separate operator hygiene guidelines for that half of the picture.

## Bottom line

This is a genuine fix for the specific way historical Enigma failed: key management, built with a real KDF and a real MAC rather than an ad hoc scheme. It is not a cryptographically hardened system by contemporary standards. The underlying cipher is a 1940s substitution machine with a bounded keyspace and no forward secrecy, and the authentication can't tell the two parties apart or stop replay. It's a well-understood exercise, not a substitute for a vetted modern encryption tool for anything that actually needs to stay secret.
