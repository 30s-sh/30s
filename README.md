# 30s

> Encrypted handoffs in seconds.

Stop pasting tokens in Slack. Send secrets securely with `30s` — they're encrypted on your device and auto-delete after expiration.

## Install

```bash
curl -sSL https://30s.sh/install.sh | sh
```

## Usage

```bash
# Sign in (or create account)
30s init alice@ac.me

# Send a secret (expires in 30 seconds by default)
30s send -t bob@ac.me "api_key_12345"

# Send with custom expiration
30s send -t bob@ac.me "database_password" 5m

# Check your inbox
30s inbox

# Open a received secret
30s open <drop-id>
```

The secret is encrypted on your device before it ever leaves. The server only stores ciphertext. Recipients decrypt locally with their device key.

## Status

### Self-hosting

30s is open source so you can audit it and run it yourself if you want. That said, **self-hosting is not officially supported right now**. I’m focused on shipping and operating the hosted service, and I don’t have bandwidth to provide deployment support, troubleshooting, or infrastructure docs. This could change in the future.

If you’d like to improve the self-hosting story, **PRs are welcome** (compose files, docs, charts, etc.). Just please expect best-effort review rather than full-time support.

### AI usage (Claude)

Claude was used to help with documentation and some straightforward app plumbing. **All AI-assisted changes were reviewed carefully.** Claude was **not** used to write the sensitive cryptography parts (encryption/decryption, key handling, protocol design), which were implemented manually and reviewed with extra care.

## License

Licensed under either of [Apache License, Version 2.0](https://github.com/30s-sh/30s/blob/main/LICENSE-APACHE)
or [MIT](https://github.com/30s-sh/30s/blob/main/LICENSE-MIT) license at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for
inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed
as above, without any additional terms or conditions.
