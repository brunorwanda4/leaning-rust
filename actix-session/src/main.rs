use actix_web::{middleware::Logger, web, App, HttpRequest, HttpResponse, HttpServer, Result};
use aes_gcm::aead::{Aead, AeadCore, OsRng}; // Import AeadCore for generate_nonce
use aes_gcm::{Aes256Gcm, Key, KeyInit, Nonce};
use base64::{engine::general_purpose, Engine as _};
use chrono::{Duration, Utc}; // Use chrono::Duration
use mongodb::bson::DateTime as BsonDateTime;

use mongodb::options::IndexOptions;
use mongodb::{
    bson::{doc, oid::ObjectId},
    Client, Collection,
};
use mongodb::{Database, IndexModel};
use rand::{distributions::Alphanumeric, Rng};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

const SECRET_KEY: &[u8; 32] = b"super_secret_key_123456789012343"; // Now exactly 32 bytes
const SESSION_EXPIRATION_SECONDS: u64 = 60;
// Ensure it's exactly 32 bytes

#[derive(Debug, Serialize, Deserialize)]
struct User {
    username: String,
    password: String,
    email: String,
    role: String,
    image: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct SessionData {
    _id: ObjectId,
    encrypted_data: String,
    token: String,
    expires_at: BsonDateTime,
}

struct AppState {
    users: Collection<User>,
    sessions: Collection<SessionData>,
}

fn generate_token() -> String {
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(32)
        .map(char::from)
        .collect()
}

fn encrypt_data(data: &str) -> String {
    let key = Key::<Aes256Gcm>::from_slice(SECRET_KEY);
    let cipher = Aes256Gcm::new(key);
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng); // ✅ Now correctly importing AeadCore
    let encrypted = cipher
        .encrypt(&nonce, data.as_bytes())
        .expect("Encryption failed");

    let mut combined = nonce.to_vec();
    combined.extend_from_slice(&encrypted);

    general_purpose::STANDARD.encode(combined) // ✅ Encode nonce + encrypted data
}

fn decrypt_data(encrypted: &str) -> String {
    let key = Key::<Aes256Gcm>::from_slice(SECRET_KEY);
    let cipher = Aes256Gcm::new(key);
    let decoded_data = general_purpose::STANDARD
        .decode(encrypted)
        .expect("Base64 decode failed");

    if decoded_data.len() < 12 {
        panic!("Invalid encrypted data format");
    }

    let (nonce_bytes, cipher_text) = decoded_data.split_at(12);
    let nonce = Nonce::from_slice(nonce_bytes);

    let decrypted = cipher
        .decrypt(nonce, cipher_text)
        .expect("Decryption failed");
    String::from_utf8(decrypted).expect("UTF-8 conversion failed")
}

async fn register(user: web::Json<User>, data: web::Data<Arc<AppState>>) -> Result<HttpResponse> {
    let user_data = User {
        username: user.username.clone(),
        password: user.password.clone(),
        email: user.email.clone(),
        role: user.role.clone(),
        image: user.image.clone(),
    };
    data.users.insert_one(&user_data, None).await.unwrap();

    let token = generate_token();
    let session_data = format!(
        "{}|{}|{}|{}",
        user.username,
        user.email,
        user.role,
        user.image.clone().unwrap_or_default()
    );
    let expires_at = BsonDateTime::from_millis(
        (Utc::now() + Duration::seconds(SESSION_EXPIRATION_SECONDS as i64)).timestamp_millis(),
    );

    let encrypted_session = encrypt_data(&session_data);
    let session = SessionData {
        _id: ObjectId::new(),
        encrypted_data: encrypted_session.clone(),
        token: token.clone(),
        expires_at,
    };

    data.sessions.insert_one(&session, None).await.unwrap();

    Ok(HttpResponse::Ok().json(doc! {"token": token}))
}

async fn profile(req: HttpRequest, data: web::Data<Arc<AppState>>) -> Result<HttpResponse> {
    if let Some(token) = req.headers().get("Authorization") {
        let token = token.to_str().unwrap_or("").to_string();

        if let Some(session) = data
            .sessions
            .find_one(doc! {"token": token}, None)
            .await
            .unwrap()
        {
            let decrypted_session = decrypt_data(&session.encrypted_data);
            let parts: Vec<&str> = decrypted_session.split('|').collect();

            if parts.len() < 3 {
                return Ok(HttpResponse::InternalServerError().json(doc! {
                    "error": "Invalid session data format"
                }));
            }

            let response_data = doc! {
                "username": parts[0],
                "email": parts[1],
                "role": parts[2],
                "image": parts.get(3).cloned().unwrap_or("")
            };

            return Ok(HttpResponse::Ok().json(response_data));
        }
    }
    Ok(HttpResponse::Unauthorized().json(doc! {"error": "Invalid session"}))
}

async fn logout(req: HttpRequest, data: web::Data<Arc<AppState>>) -> Result<HttpResponse> {
    if let Some(token) = req.headers().get("Authorization") {
        let token = token.to_str().unwrap_or("").to_string();
        data.sessions
            .delete_one(doc! {"token": token}, None)
            .await
            .unwrap();
        return Ok(HttpResponse::Ok().body("Logged out successfully"));
    }
    Ok(HttpResponse::BadRequest().body("Token missing"))
}

async fn setup_session_expiry_index(db: &Database) -> Result<(), String> {
    let index = IndexModel::builder()
        .keys(doc! { "expires_at": 1 }) // Index on 'expires_at' field
        .options(
            IndexOptions::builder()
                .expire_after(Some(std::time::Duration::from_secs(
                    SESSION_EXPIRATION_SECONDS,
                ))) // Auto-delete expired sessions
                .build(),
        )
        .build();

    db.collection::<SessionData>("sessions")
        .create_index(index, None)
        .await
        .map_err(|e| e.to_string())?;

    Ok(())
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));
    let client = Client::with_uri_str("mongodb://localhost:27017")
        .await
        .unwrap();
    let db = client.database("actix_session_test_db");
    // ✅ Ensure the expiration index is set
    if let Err(err) = setup_session_expiry_index(&db).await {
        eprintln!("Failed to create session expiration index: {}", err);
    }

    let shared_data = Arc::new(AppState {
        users: db.collection("users"),
        sessions: db.collection("sessions"),
    });

    HttpServer::new(move || {
        App::new()
            .wrap(Logger::default())
            .app_data(web::Data::new(shared_data.clone()))
            .route("/register", web::post().to(register))
            .route("/profile", web::get().to(profile)) // ✅ Changed from "/my-name" to "/profile"
            .route("/logout", web::post().to(logout))
    })
    .bind("127.0.0.1:4567")?
    .run()
    .await
}
