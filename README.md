# Rust Developer Take Home Code Assessment

## Using

Run step by step all command lines

    cargo build
    cargo run generate-keys
    cargo run encrypt public_key.pem [text_here]
    cargo run decrypt private_key.pem [encrypted_message_here]

For advance task:

    cargo run sign sign_key.pem [message_here]
    cargo run verify verify_key.pem [verified_message_here] [signature_here]

- Task 2: **Build sdk for each platform**


        cargo build --target aarch64-linux-android --release
        cargo build --target aarch64-apple-ios --release
        cargo build --target x86_64-pc-windows-gnu --release
