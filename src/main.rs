use std::env;
use crate::encryption::{decrypt, encrypt, generate_keys, get_key_pem, handle_plain_text, sign, verify};
mod encryption;
mod binding;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Please use correct CLI, change this to: <command> [args]");
        return;
    }

    match args[1].as_str() {
        "generate-keys" => generate_keys(),
        "encrypt" => {
            if args.len() != 4 {
                eprintln!("Please use correct CLI, change this to: encrypt <public-key-file> <plaintext>");
                return;
            }
            let plaintext_valid = handle_plain_text(&args[3]);
            let public_key_pem = get_key_pem(&args[2]);
            let encrypted_message = encrypt(&public_key_pem, &plaintext_valid.expect("Error plaintext")).expect("Cannot encrypt message");
            println!("Encrypt message: {}", encrypted_message)
        },
        "decrypt" => {
            if args.len() != 4 {
                eprintln!("Please use correct CLI, change this to: decrypt <private-key-file> <encrypted-message>");
                return;
            }
            let private_key_pem = get_key_pem(&args[2]);
            let decrypted_message = decrypt(&private_key_pem, &args[3]).expect("Cannot encrypt message");
            println!("Message after decrypt: {}", decrypted_message)
        },
        "sign" => {
            if args.len() != 4 {
                eprintln!("Please use correct CLI, change this to: sign <sign-key-file> <message>");
                return;
            }
            let sign_key_pem = get_key_pem(&args[2]);
            let plaintext_valid = handle_plain_text(&args[3]);

            println!("{}", sign(&sign_key_pem, &plaintext_valid.expect("Error plaintext")).expect("Can not sign this message"));
        },
        "verify" => {
            if args.len() != 5 {
                eprintln!("Please use correct CLI, change this to: verify <verify-key-file> <message> <signature_buffer>");
                return;
            }
            let verify_key_pem = get_key_pem(&args[2]);
            let plaintext_valid = handle_plain_text(&args[3]);
            let is_verify = verify(&verify_key_pem, &plaintext_valid.expect("Error plaintext"), &args[4]).expect("Can not sign this message");
            println!("{}", is_verify);
        }
        _ => eprintln!("Unknown command"),
    }
}
