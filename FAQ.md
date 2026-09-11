# FAQ

## Why does this exist?

Historical Enigma wasn't broken because the cipher's math was weak for its time. It was broken because of how the keys were generated, shared, and reused: operators picking predictable keys under pressure, a shared daily setting that let cryptanalysts compare messages against each other, physical codebooks that exposed weeks of traffic if captured, and a message key that got transmitted (if disguised) rather than derived independently by both sides.

This project keeps an authentic M4 simulator and replaces everything around it with a modern key derivation function and a real authentication tag. The goal was to see how much of Enigma's historical weakness could be closed using only what both sides already know (a shared secret, the date, a message number) without changing the machine itself. It's a learning exercise built around a specific question, not an attempt to build something you should actually rely on.

## Is this actually secure?

For what it's for: reasonably, against a casual reader who stumbles onto the ciphertext. Against anyone who sits down and actually works on it: no. Enigma's own cipher-level limits are untouched. The keyspace is small by modern standards, no letter can ever encipher to itself, and the whole system's security rests on one shared secret staying secret. See [enigma-kdf-security-summary.md](enigma-kdf-security-summary.md) for the full accounting. Don't use this for anything that actually needs to stay secret.

## Why is the output split into three parts with pipes?

`message_number|ciphertext|tag`. The number tells the receiver which derivation to run, since settings are different for every message. The tag is an authentication code, checked before anything decrypts, so a tampered or forged message gets rejected instead of silently decrypting into garbage. Neither part is encrypted; both are meant to be public.

## Why can't I reuse a message number?

Because the settings for a message are derived from the seed, the date, and that number together. Reusing a number on the same day recreates the exact same key twice, which is the same weakness that let historical cryptanalysts compare overlapping messages against each other. Increment it for every message you send that person that day.

## What happens if my friend and I disagree on the date?

Decryption fails. Nothing leaks, it just won't produce readable text, since both sides need to derive the same key from the same date string. Agree on a format and a timezone (UTC is the tool's default) once, up front, so this never comes up mid-conversation.

## Can I use this with more than one person?

Yes, but each pair needs its own separate shared seed. Reusing one seed across more than two people means anyone holding it can read everyone's traffic, not just their own conversation.

## Why can't I type numbers?

The real Enigma keyboard only had 26 keys, the letters A through Z. There's no number row and never was. German operators spelled numbers out as words, or substituted a stand-in letter sequence. This tool follows the machine faithfully: numerals get stripped from anything you type before encryption, the same way the real device simply couldn't represent them.

## Why don't spaces show up in the decrypted message?

Same root cause. There's no space bar on an Enigma. Historically, most operators just ran words together and let the receiver work out the boundaries from context; some used the letter X as a stand-in for a space when it mattered. This tool strips spaces rather than substituting a marker, since a marker character turns out to leak more structure to an attacker than it's worth. If you want boundaries preserved, agree on a convention with whoever you're messaging and add it to your own message before encrypting.

## What about punctuation, like periods and commas?

Not supported, for the same reason. Historically, punctuation got the same treatment as spaces: substitute letters standing in for a period, a comma, quotation marks. This tool doesn't implement any of those conventions automatically. Anything that isn't A through Z gets stripped before encryption.

## Why did my message come out wrong when I used accented characters?

Enigma only ever had the 26 unaccented Latin letters. Characters like é, ö, or ñ aren't stripped and replaced, they're just dropped entirely, since the machine has no equivalent for them. "café" becomes "CAF". If you're writing in a language that normally uses accents, transliterate first (é to E, ö to OE, and so on), the same workaround German telegraphy used for umlauts.

## Why is everything in uppercase?

Enigma has no concept of case. There's one alphabet, not an upper and lower one. Anything you type gets uppercased before it touches the machine, and the decrypted output comes back the same way.
