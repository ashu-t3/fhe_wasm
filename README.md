# fhe_wasm

This project provides WebAssembly (WASM) bindings for Client side encryption for  [fhe.rs](https://github.com/ashu-t3/fhe.rs) rust library .

## Project Structure

- `src/`: Rust source code for the core library.
- `pkg/`: Generated WASM and JavaScript bindings for npm.
- `target/`: Build artifacts and intermediate files.

## Building

To build the WASM package, run:

```sh
wasm-pack build --release
```

## Testing the WASM Code

This project uses [`wasm-bindgen-test`](https://rustwasm.github.io/wasm-bindgen/wasm-bindgen-test/usage.html) for testing Rust code compiled to WebAssembly.

### 1. Install test dependencies

```sh
cargo install wasm-bindgen-cli
cargo install wasm-pack
```

### 2. Run the tests

You can run the tests in a headless browser environment using:

```sh
wasm-pack test --headless --firefox
```
or
```sh
wasm-pack test --headless --chrome
```

You can also run the tests in Node.js:

```sh
wasm-pack test --node
```

### 3. About the tests

The tests are located in `src/lib.rs` under the `#[cfg(test)]` module. They cover encryption and decryption cycles for both public and secret key encryption.

---

**Note:** Make sure you have Firefox, Chrome, or Node.js installed for running the tests in your preferred environment.