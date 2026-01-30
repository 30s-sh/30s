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

# Check your inbox
30s inbox

# Open a received secret
30s open <drop-id>
```

## License

Licensed under either of [Apache License, Version 2.0](https://github.com/30s-sh/30s/blob/main/LICENSE-APACHE)
or [MIT](https://github.com/30s-sh/30s/blob/main/LICENSE-MIT) license at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for
inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed
as above, without any additional terms or conditions.

---

*Built with AI assist for the boring parts; crypto by human.*
