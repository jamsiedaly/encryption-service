use actix_web::{middleware, web, App, Error, HttpResponse, HttpServer};
use serde::{Serialize, Deserialize};
use serde_json::Value;
use aes_gcm::Aes256Gcm; // Or `Aes128Gcm`
use aes_gcm::aead::{Aead, NewAead, generic_array::GenericArray};
use std::ops::Add;
use std::fs;
use std::sync::Mutex;
use std::fs::File;
use std::io::Write;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

#[derive(Serialize, Deserialize, Debug)]
struct SignedResponse {
    signature: u64,
    data: String
}

struct Setting {
    key: String,
    nonce: String
}

async fn encrypt(payload: String, settings: web::Data<Mutex<Setting>>) -> Result<HttpResponse, Error> {
    let key = settings.lock().unwrap().key.to_string();
    let nonce = settings.lock().unwrap().nonce.to_string();
    let mut json: Value = serde_json::from_str(payload.as_str()).unwrap();
    let result = encrypt_json(key, nonce, &mut json);

    Ok(HttpResponse::Ok().content_type("application/json").body(result))
}

fn encrypt_json(key: String, nonce: String, json: &mut Value) -> String {
    let crypto_key = GenericArray::from_slice(key.as_bytes());
    let cipher = Aes256Gcm::new(crypto_key);
    let nonce = GenericArray::from_slice(nonce.as_bytes());

    for object in json.as_object_mut().unwrap().iter_mut() {
        let encrypted_string = cipher.encrypt(nonce, object.1.to_string().as_bytes())
            .expect("encryption failure!");
        let mut string = String::new();
        for character in encrypted_string.clone() {
            string = string.add(character.to_string().as_str()).add("/");
        }
        string.pop();
        *object.1 = Value::String(string.to_string());
    }

    let result = json.to_string();
    result
}

async fn decrypt(payload: String, settings: web::Data<Mutex<Setting>>) -> Result<HttpResponse, Error> {
    let key = settings.lock().unwrap().key.to_string();
    let nonce = settings.lock().unwrap().nonce.to_string();
    let mut json: Value = serde_json::from_str(payload.as_str()).unwrap();
    decrypt_json(key, nonce, &mut json);
    let result = json.to_string();
    Ok(HttpResponse::Ok().body(result).into())
}

fn decrypt_json(key: String, nonce: String, json: &mut Value) {
    let crypto_key = GenericArray::from_slice(key.as_bytes());
    let cipher = Aes256Gcm::new(crypto_key);
    let nonce = GenericArray::from_slice(nonce.as_bytes());

    for object in json.as_object_mut().unwrap().iter_mut() {
        let mut original_value = object.1.to_string();
        original_value.remove(0);
        original_value.remove(original_value.len() - 1);
        let mut value = Vec::new();
        for char_as_number in original_value.split("/").into_iter() {
            let char = char_as_number.parse::<u8>().unwrap();
            value.push(char);
        }
        let encrypted_string = cipher.decrypt(nonce, value.as_ref())
            .expect("encryption failure!");

        let mut string = String::new();
        for character in encrypted_string.clone() {
            string.push(char::from(character));
        }

        *object.1 = Value::String(string.to_string());
    }
}

async fn sign(payload: String) -> Result<HttpResponse, Error> {
    let mut hasher = DefaultHasher::new();
    payload.hash(&mut hasher);
    let response = SignedResponse{ signature: hasher.finish(), data: payload };
    let response = serde_json::to_string(&response)?;
    Ok(HttpResponse::Ok().body(response).into())
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let ip = "0.0.0.0:8080";
    let nonce = String::from("unique nonce");
    let key = load_cipher_key();
    let settings = web::Data::new(Mutex::new(Setting{ key, nonce }));

    HttpServer::new(move || {
        App::new()
            .wrap(middleware::Logger::default())
            .app_data(settings.clone())
            .service(
                web::resource("/encrypt").route(web::post().to(encrypt)))
            .service(
                web::resource("/decrypt").route(web::post().to(decrypt)))
            .service(
                web::resource("/sign").route(web::post().to(sign)))
    })
        .bind(ip)?
        .run()
        .await
}

fn load_cipher_key() -> String {
    let key_file = fs::read_to_string("key");
    let key = if key_file.is_ok() {
        key_file.ok()
    } else {
        let mut file = File::create("key").unwrap();
        let new_key = random_key();
        file.write_all(new_key.as_bytes()).unwrap();
        Option::Some(new_key)
    }.unwrap();
    key
}

fn random_key() -> String {
    use rand::Rng;
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ\
                            abcdefghijklmnopqrstuvwxyz\
                            0123456789)(*&^%$#@!~";
    const KEY_LEN: usize = 32;
    let mut rng = rand::thread_rng();

    return (0..KEY_LEN)
        .map(|_| {
            let idx = rng.gen_range(0..CHARSET.len());
            CHARSET[idx] as char
        })
        .collect();
}

