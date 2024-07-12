# Rust Developer Take Home Code Assessment

## Using
Run step by step all command lines 

    cargo build
    cargo run generate-keys
    cargo run encrypt [public_key_pem] [text_here]
    cargo run decrypt [private_key_pem] [encrypted_message_here]


- Task 2: **Build sdk for each platform**
  - cargo build --target aarch64-linux-android --release
  - cargo build --target aarch64-apple-ios --release
  - cargo build --target x86_64-pc-windows-gnu --release
