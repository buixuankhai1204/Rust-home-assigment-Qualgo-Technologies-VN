#[cfg(target_os = "android")]
#[allow(non_snake_case)]
pub mod android {
    use crate::{encryption};
    use jni::JNIEnv;
    use jni::objects::{JClass, JString};
    use jni::sys::jstring;

    #[no_mangle]
    pub extern "C" fn Java_com_example_mysdk_MySDK_encryptMessage(mut env: JNIEnv, _: JClass, public_key_pem: JString, message: JString) -> jstring {
        let public_key_pem: String = env.get_string(&public_key_pem).expect("Invalid public key").into();
        let message: String = env.get_string(&message).expect("Invalid message").into();
        match encryption::encrypt(&public_key_pem, &message) {
            Ok(encrypted_message) => env.new_string(encrypted_message).expect("Couldn't create java string").into_raw(),
            Err(_) => env.new_string("").expect("Couldn't create java string").into_raw(),
        }
    }

    #[no_mangle]
    pub extern "C" fn Java_com_example_mysdk_MySDK_decryptMessage(mut env: JNIEnv, _: JClass, private_key_pem: JString, encrypted_message: JString) -> jstring {
        let private_key_pem: String = env.get_string(&private_key_pem).expect("Invalid private key").into();
        let encrypted_message: String = env.get_string(&encrypted_message).expect("Invalid encrypted message").into();
        match encryption::decrypt(&private_key_pem, &encrypted_message) {
            Ok(decrypted_message) => env.new_string(decrypted_message).expect("Couldn't create java string").into_raw(),
            Err(_) => env.new_string("").expect("Couldn't create java string").into_raw(),
        }
    }

    #[no_mangle]
    pub extern "C" fn Java_com_example_mysdk_MySDK_signMessage(mut env: JNIEnv, _: JClass, sign_key_pem: JString, message: JString) -> jstring {
        let sign_key_pem: String = env.get_string(&sign_key_pem).expect("Invalid private key").into();
        let message: String = env.get_string(&message).expect("Invalid encrypted message").into();
        match encryption::sign(&sign_key_pem, &message) {
            Ok(sign_message) => env.new_string(sign_message).expect("Couldn't create java string").into_raw(),
            Err(_) => env.new_string("").expect("Couldn't create java string").into_raw(),
        }
    }

    #[no_mangle]
    pub extern "C" fn Java_com_example_mysdk_MySDK_verifyMessage(mut env: JNIEnv, _: JClass, verify_key_pem: JString, message: JString, signature: JString) -> jstring {
        let verify_key_pem: String = env.get_string(&verify_key_pem).expect("Invalid private key").into();
        let message: String = env.get_string(&message).expect("Invalid encrypted message").into();
        let signature: String = env.get_string(&signature).expect("Invalid encrypted message").into();
        match encryption::verify(&verify_key_pem, &message, &signature) {
            Ok(verified_message) => env.new_string("true").expect("Couldn't create java string").into_raw(),
            Err(_) => env.new_string("false").expect("Couldn't create java string").into_raw(),
        }
    }


}

#[cfg(target_os = "ios")]
#[allow(non_snake_case)]
pub mod ios {
    use crate::{encryption};
    use std::ffi::{c_char, CStr, CString};

    #[no_mangle]
    pub extern "C" fn encrypt(public_key_pem: *const c_char, message: *const c_char) -> *const c_char {
        let public_key_pem = unsafe { CStr::from_ptr(public_key_pem) }.to_str().expect("Invalid public key");
        let message = unsafe { CStr::from_ptr(message) }.to_str().expect("Invalid message");
        match encryption::encrypt(public_key_pem, message) {
            Ok(encrypted_message) => CString::new(encrypted_message).expect("CString::new failed").into_raw(),
            Err(_) => CString::new("").expect("CString::new failed").into_raw(),
        }
    }

    #[no_mangle]
    pub extern "C" fn decrypt_message(private_key: *const c_char, encrypted_message: *const c_char) -> *const c_char {
        let private_key = unsafe { CStr::from_ptr(private_key) }.to_str().expect("Invalid private key");
        let encrypted_message = unsafe { CStr::from_ptr(encrypted_message) }.to_str().expect("Invalid encrypted message");
        match encryption::decrypt(private_key, encrypted_message) {
            Ok(decrypted_message) => CString::new(decrypted_message).expect("CString::new failed").into_raw(),
            Err(_) => CString::new("").expect("CString::new failed").into_raw(),
        }
    }

    #[no_mangle]
    pub extern "C" fn sign(sign_key_pem: *const c_char, message: *const c_char) -> *const c_char {
        let sign_key_pem = unsafe { CStr::from_ptr(sign_key_pem) }.to_str().expect("Invalid public key");
        let message = unsafe { CStr::from_ptr(message) }.to_str().expect("Invalid message");
        match encryption::sign(sign_key_pem, message) {
            Ok(signed_message) => CString::new(signed_message).expect("CString::new failed").into_raw(),
            Err(_) => CString::new("").expect("CString::new failed").into_raw(),
        }
    }

    #[no_mangle]
    pub extern "C" fn verify(verify_key_pem: *const c_char, message: *const c_char, signature: *const c_char) -> *const c_char {
        let verify_key_pem = unsafe { CStr::from_ptr(verify_key_pem) }.to_str().expect("Invalid public key");
        let message = unsafe { CStr::from_ptr(message) }.to_str().expect("Invalid message");
        let signature = unsafe { CStr::from_ptr(signature) }.to_str().expect("Invalid message");
        match encryption::verify(verify_key_pem, message, signature) {
            Ok(verify_message) => CString::new("true").expect("CString::new failed").into_raw(),
            Err(_) => CString::new("false").expect("CString::new failed").into_raw(),
        }
    }
}

#[cfg(any(target_os = "windows", target_os = "macos", target_os = "linux"))]
#[allow(non_snake_case)]
pub mod desktop {
    use crate::{encryption};
    use std::ffi::{c_char, CStr, CString, };

    #[no_mangle]
    pub extern "C" fn encrypt(public_key_pem: *const c_char, message: *const c_char) -> *const c_char {
        let public_key_pem = unsafe { CStr::from_ptr(public_key_pem) }.to_str().expect("Invalid public key");
        let message = unsafe { CStr::from_ptr(message) }.to_str().expect("Invalid message");
        match encryption::encrypt(public_key_pem, message) {
            Ok(encrypted_message) => CString::new(encrypted_message).expect("CString::new failed").into_raw(),
            Err(_) => CString::new("").expect("CString::new failed").into_raw(),
        }
    }

    #[no_mangle]
    pub extern "C" fn decrypt_message(private_key_pem: *const c_char, encrypted_message: *const c_char) -> *const c_char {
        let private_key_pem = unsafe { CStr::from_ptr(private_key_pem) }.to_str().expect("Invalid private key");
        let encrypted_message = unsafe { CStr::from_ptr(encrypted_message) }.to_str().expect("Invalid encrypted message");
        match encryption::decrypt(private_key_pem, encrypted_message) {
            Ok(decrypted_message) => CString::new(decrypted_message).expect("CString::new failed").into_raw(),
            Err(_) => CString::new("").expect("CString::new failed").into_raw(),
        }
    }

    #[no_mangle]
    pub extern "C" fn sign(sign_key_pem: *const c_char, message: *const c_char) -> *const c_char {
        let sign_key_pem = unsafe { CStr::from_ptr(sign_key_pem) }.to_str().expect("Invalid public key");
        let message = unsafe { CStr::from_ptr(message) }.to_str().expect("Invalid message");
        match encryption::sign(sign_key_pem, message) {
            Ok(signed_message) => CString::new(signed_message).expect("CString::new failed").into_raw(),
            Err(_) => CString::new("").expect("CString::new failed").into_raw(),
        }
    }

    #[no_mangle]
    pub extern "C" fn verify(verify_key_pem: *const c_char, message: *const c_char, signature: *const c_char) -> *const c_char {
        let verify_key_pem = unsafe { CStr::from_ptr(verify_key_pem) }.to_str().expect("Invalid public key");
        let message = unsafe { CStr::from_ptr(message) }.to_str().expect("Invalid message");
        let signature = unsafe { CStr::from_ptr(signature) }.to_str().expect("Invalid message");
        match encryption::verify(verify_key_pem, message, signature) {
            Ok(verify_message) => CString::new("true").expect("CString::new failed").into_raw(),
            Err(_) => CString::new("false").expect("CString::new failed").into_raw(),
        }
    }
}
