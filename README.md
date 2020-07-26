# `rd` The Record & Debug Tool

`rd` is a Rust language port of [mozilla/rr](https://github.com/mozilla/rr).

## Installing

```bash
cargo install --locked --force --path .
```

Alternatively, use `--debug` like below. Things will run much more slowly but this mode may be useful in debugging `rd` itself. 
```bash
cargo install --debug --locked --force --path .
```
