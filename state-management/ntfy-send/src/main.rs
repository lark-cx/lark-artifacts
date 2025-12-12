use serde::Deserialize;
use std::fs;
use std::env;
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use pbkdf2::pbkdf2_hmac;
use sha2::Sha256;
use rand::RngCore;

#[derive(Deserialize)]
struct Config {
    server: String,
    topic: String,
    #[serde(default)]
    token: Option<String>,
    #[serde(default)]
    priority: Option<String>,
    #[serde(default)]
    password: Option<String>,  // For encryption
}

fn encrypt_message(message: &str, password: &str) -> Result<String, Box<dyn std::error::Error>> {
    // Generate random salt and nonce
    let mut salt = [0u8; 16];
    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut salt);
    rand::thread_rng().fill_bytes(&mut nonce_bytes);

    // Derive key using PBKDF2 (100k iterations, matching ntfy)
    let mut key = [0u8; 32];
    pbkdf2_hmac::<Sha256>(password.as_bytes(), &salt, 100_000, &mut key);

    // Encrypt
    let cipher = Aes256Gcm::new_from_slice(&key)?;
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher.encrypt(nonce, message.as_bytes())
        .map_err(|e| format!("Encryption failed: {}", e))?;

    // Format: base64(salt) + " " + base64(nonce) + " " + base64(ciphertext)
    let encoded = format!(
        "{} {} {}",
        base64::encode(&salt),
        base64::encode(&nonce_bytes),
        base64::encode(&ciphertext)
    );

    Ok(encoded)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: ntfy-send <message> [title]");
        std::process::exit(1);
    }

    let message = &args[1];
    let title = args.get(2).map(String::as_str);

    // Read config
    let config_path = "/etc/ntfy-send.toml";
    let config_str = fs::read_to_string(config_path)
        .map_err(|e| format!("Failed to read {}: {}", config_path, e))?;
    let config: Config = toml::from_str(&config_str)?;

    // Encrypt message if password provided
    let payload = if let Some(password) = &config.password {
        encrypt_message(message, password)?
    } else {
        message.to_string()
    };

    // Build request
    let url = format!("{}/{}", config.server.trim_end_matches('/'), config.topic);
    let mut req = ureq::post(&url).set("Content-Type", "text/plain");

    if let Some(token) = &config.token {
        req = req.set("Authorization", &format!("Bearer {}", token));
    }
    if let Some(title) = title {
        req = req.set("Title", title);
    }
    if let Some(priority) = &config.priority {
        req = req.set("Priority", priority);
    }

    // Send
    req.send_string(&payload)?;
    
    println!("Message sent{}", if config.password.is_some() { " (encrypted)" } else { "" });
    
    Ok(())
}
