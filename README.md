# Papotage

Vencord plugin that encrypts Discord messages and hides the ciphertext in invisible text.
Without the plugin, a message looks like an ordinary throwaway sentence ("yeah let's meet
tomorrow"); with the plugin and the right password, it shows up in clear text instead.

## How it works

1. The message is encrypted with AES-GCM 256. The key is derived from a shared password
   (PBKDF2, SHA-256, 200,000 iterations).
2. The ciphertext bytes are encoded as zero-width Unicode characters, attached after a short
   cover sentence. These characters are invisible and preserved by Discord.
3. On receipt, the plugin finds the invisible part, decrypts it, and replaces the displayed
   content with the real message. Other users only ever see the cover sentence.

Encryption is toggled per channel with the lock icon in the message bar (grey = off,
green = on).

## Usage

- **Password**: set it in the plugin settings, identical for every participant. Share it
  through another channel.
- **Cover sentence**: by default a natural sentence is picked at random. To write the façade
  yourself and keep a conversation coherent, use `visible sentence | secret message`.
  Example: `yeah all good you | meet at 8pm` shows "yeah all good you" to everyone else and
  the real message to recipients who have the plugin.
- **Emoji mode** (optional): instead of invisible characters, the secret is encoded as a
  sequence of visible emojis (16 emojis mapped to the 16 hex values). More conspicuous, so
  keep it for short messages.

### Settings

| Setting | Purpose |
|---|---|
| Passphrase | Shared password (required) |
| Auto Decrypt | Automatically decrypt incoming messages |
| Show 🔓 | Prefix decrypted messages so they stand out |
| Custom Cover | Fixed default cover sentence |
| Separator | Delimiter between cover and secret (default: ` &#124; `) |
| Emoji Mode | Switch to emoji encoding |

## Limitations

- **Length**: invisible characters count toward Discord's 2000-character limit. A secret of
  about 200 characters fits in a single message; split longer ones.
- **Shared password**: anyone with the key can read everything. No per-person secrecy.
- **Metadata**: Discord still sees who talks to whom and when; only the content is hidden.
- **Detectability**: invisible to normal reading, but an automated scan can detect the
  presence of zero-width characters (without being able to read the encrypted content).
- **Client trust**: the text is in clear in the client at the moment you type it.

Real, discreet encryption for private use — not a replacement for Signal.

## Installation

1. Put the folder in `Vencord/src/userplugins/papotage/`.
2. Build Vencord: `pnpm build` (or `node scripts/build/build.mjs`).
3. Enable **Papotage** in the plugin settings, then set the password.

On **Vesktop**, point `state.json` (`vencordDir`) at the build's `dist` folder, and make sure
it contains a `package.json` (otherwise Vesktop re-downloads Vencord over it).

## Development

The core (encryption + steganography, `src/codec.mjs`) is independent of Discord and can be
tested locally:

```bash
npm test
```

The tests cover round-trip, wrong-key rejection, the Discord character budget, emoji
encoding, and the cover syntax.

## Structure

- `src/codec.mjs` — AES-GCM encryption and encoding/decoding (zero-width, emoji, sentence)
- `src/wordlist.mjs` — word lists for the sentence mode
- `src/index.tsx` — Vencord plugin (button, encrypt on send, inline decryption)
- `test/` — codec test suite

## License

MIT.
