use std::error::Error;
use std::fs::File;
use std::io::{Read, Write};
use rsa::{Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey};
use rand::rngs::OsRng;
use base64::prelude::*;
use jni::objects::JString;
use rsa::pkcs1::{DecodeRsaPrivateKey, DecodeRsaPublicKey, EncodeRsaPrivateKey, EncodeRsaPublicKey, LineEnding};
use rsa::pkcs1v15::{Signature, SigningKey, VerifyingKey};
use rsa::sha2::Sha256;
use rsa::signature::{Keypair, RandomizedSigner, SignatureEncoding, Verifier};

pub enum ESignatureResponse {
    SigningKey(SigningKey<Sha256>),
    VerifyingKey(VerifyingKey<Sha256>),
    PrivateKey(RsaPrivateKey),
    PublicKey(RsaPublicKey),
}

pub fn get_correct_value_key(key_pem: &str, type_of_key: i8) -> Result<ESignatureResponse, &'static str> {
    match type_of_key {
        0 => {
            let signing_key = SigningKey::from_pkcs1_pem(&key_pem).expect("Can not get Singing key");
            return Ok(
                ESignatureResponse::SigningKey(signing_key)
            );
        }
        1 => {
            let verifying_key = VerifyingKey::from_pkcs1_pem(&key_pem).expect("Can not parse to signingKey");
            return Ok(
                ESignatureResponse::VerifyingKey(verifying_key)
            );
        }
        2 => {
            let private_key = RsaPrivateKey::from_pkcs1_pem(&key_pem).expect("Failed to parse key");
            return Ok(
                ESignatureResponse::PrivateKey(private_key)
            );
        }
        3 => {
            let public_key = RsaPublicKey::from_pkcs1_pem(&key_pem).expect("Failed to parse key");
            return Ok(
                ESignatureResponse::PublicKey(public_key)
            );
        }
        _ => Err("Can not get data from file")
    }
}

pub fn generate_keys() {
    let mut rng = rand::thread_rng();
    let bits = 2048;
    let private_key = RsaPrivateKey::new(&mut rng, bits).expect("Failed to generate a key");
    let public_key = RsaPublicKey::from(&private_key);
    let signing_key = SigningKey::<Sha256>::new(private_key.clone());
    let verifying_key = &signing_key.verifying_key();

    let mut priv_file = File::create("private_key.pem").expect("Failed to create private key file");
    priv_file.write_all(&private_key.to_pkcs1_pem(LineEnding::CRLF).expect("Failed to write key").as_bytes()).expect("Failed to write file");

    let mut pub_file = File::create("public_key.pem").expect("Failed to create public key file");
    pub_file.write_all(&public_key.to_pkcs1_pem(LineEnding::CRLF).expect("Failed to write key").as_bytes()).expect("Failed to write file");

    let mut sign_file = File::create("sign_key.pem").expect("Fail to create signing file");
    sign_file.write_all(signing_key.to_pkcs1_pem(LineEnding::CRLF).expect("Can not convert this key").as_bytes()).expect("Failed to write file");

    let mut verify_file = File::create("verify_key.pem").expect("Fail to create verifying file");
    verify_file.write_all(verifying_key.to_pkcs1_pem(LineEnding::CRLF).expect("Can not convert this key").as_bytes()).expect("Failed to write file");


    println!("Keys generated and saved to private_key.pem and public_key.pem");
}

pub fn encrypt(public_key_pem: &str, plaintext: &str) -> Result<String, &'static str> {
    let public_key = get_correct_value_key(public_key_pem, 3).expect("Can not get private key");
    let mut rng = OsRng;
    return match public_key {
        ESignatureResponse::PublicKey(key) => {
            let encrypted = key.encrypt(&mut rng, Pkcs1v15Encrypt, plaintext.as_bytes()).expect("Failed to encrypt");
            return Ok(BASE64_STANDARD.encode(&encrypted));
        }
        _ => Err("Can not decrypt this encrypted message")
    };
}

pub fn decrypt(private_key_pem: &str, encrypted_message: &str) -> Result<String, &'static str> {
    let private_key = get_correct_value_key(private_key_pem, 2).expect("Can not get private key");
    return match private_key {
        ESignatureResponse::PrivateKey(key) => {
            let decrypted = key.decrypt(Pkcs1v15Encrypt, &BASE64_STANDARD.decode(&encrypted_message).expect("Can not decrypt data")).expect("Failed to decrypt");

            Ok(String::from_utf8(decrypted).expect("Failed to convert to string"))
        }
        _ => Err("Can not decrypt this encrypted message")
    };
}

pub fn sign(sign_key_pem: &str, message: &str) -> Result<String, &'static str> {
    let private_key = get_correct_value_key(sign_key_pem, 0).expect("Can not get private key");

    let mut rng = rand::thread_rng();
    match private_key {
        ESignatureResponse::SigningKey(key) => {
            let signature = key.sign_with_rng(&mut rng, message.as_bytes());
            return Ok(BASE64_STANDARD.encode(&signature.to_vec()));
        }
        _ => Err("Can not sign this message")
    }
}

pub fn verify(verify_key_pem: &str, message: &str, signature: &str) -> Result<bool, &'static str> {
    let verify_key = get_correct_value_key(verify_key_pem, 1).expect("Can not get verify key");
    return match verify_key {
        ESignatureResponse::VerifyingKey(key) =>
            {
            let signature = Signature::try_from(BASE64_STANDARD.decode(signature).expect("Can not decode this message").as_slice()).expect("Can not get Signature");
            key.verify(message.as_bytes(), &signature).expect("Can not verify this message");
            Ok(true)
        }
        _ => Err("Can not verify this message")
    };
}

pub fn get_key_pem(key_file: &str) -> String {
    if key_file.len() == 0 {
        return "".to_string();
    }
    let mut key_pem = String::new();
    let mut file = File::open(key_file).expect("Failed to open file");
    file.read_to_string(&mut key_pem).expect("Failed to read file");
    return key_pem;
}

pub fn handle_plain_text(plain_text: &str) -> Result<&str, Box<dyn Error>> {
    if plain_text.len() < 5 {
        return Err(Box::from("this text is not valid"));
    }

    return Ok(plain_text.trim());
}
