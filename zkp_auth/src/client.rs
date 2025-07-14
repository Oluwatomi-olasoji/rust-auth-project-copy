mod ssi;
//use wallet;
use ssi::issuer::Issuer;
use base64::{Engine as _, engine::general_purpose};
use num_bigint::BigUint;
use tonic::{transport::Server, Code,Request, Response, Status, codegen::http::request};
use crate::zkp_auth::{auth_client::AuthClient, ChallengeRequest, RegisterRequest, SolutionRequest};
use std::io::stdin;
use serde::{Deserialize, Serialize};

//importing the zkp functions i made
use ::zkp_auth::{ ZKP};

use ::zkp_auth::ssi::credential::VerifiableCredential;

pub mod zkp_auth{
    include!("zkp_proto.rs");
}
// Struct to read wallet data from file (matches wallet's WalletData)

#[derive(Serialize, Deserialize)]
pub struct WalletData {
    pub did: String,
    pub credential: VerifiableCredential,
    pub secret: String,
}

#[tokio::main]
async fn main(){
    let mut buf = String::new();

    //creating the zkp instance
    let (alpha, beta, p, q) = ZKP::get_zkp_constants();
    let zkp = ZKP {alpha: alpha.clone(), beta: beta.clone(), p: p.clone(), q: q.clone()};

    let mut client = AuthClient::connect("http://127.0.0.1:50051").await.expect("could not connect to server");
    println!("✓ Connected to the server");

    println!("\n🔐 SELF-SOVEREIGN IDENTITY AUTHENTICATION CLIENT");
    println!("📋 This system uses Decentralized Identifiers (DIDs) for secure, privacy-preserving authentication");

    //getting the DID for authentication
    println!("\nEnter your DID: ");
    stdin().read_line(&mut buf).expect("could not read DID");
    let did = buf.trim().to_string();
    buf.clear();

    // Validate DID format
    if !did.starts_with("did:zkp:") {
        println!("❌ Invalid DID format. Expected format: did:zkp:xxxxx");
        println!("Please run the wallet application first to get your DID");
        return;
    }

    println!("🆔 Using DID: {}", did);

    // === LOAD WALLET DATA FROM FILE USING DID ===
    let did_hash = did.replace(":", "_");
    let wallet_filename = format!("{}_wallet.json", did_hash);
    
    let wallet_data = if let Ok(file_contents) = std::fs::read_to_string(&wallet_filename) {
        match serde_json::from_str::<WalletData>(&file_contents) {
            Ok(data) => {
                println!("✓ Loaded wallet data for DID: {}", did);
                data
            },
            Err(e) => {
                println!("❌ Error parsing wallet file: {}", e);
                println!("Please make sure your wallet file is valid");
                return;
            }
        }
    } else {
        println!("❌ Wallet file not found: {}", wallet_filename);
        println!("Please create wallet using: cargo run --bin wallet");
        return;
    };

    // Verify the DID matches the wallet (should always match now)
    if wallet_data.did != did {
        println!("❌ DID mismatch in wallet file!");
        return;
    }
    println!("✅ DID verified");

    // === PASSWORDLESS LOGIN FLOW ===
    println!("\nPASSWORDLESS SSI AUTHENTICATION");
    println!("🔑 Authenticating with Self-Sovereign Identity...");
    println!("Authenticate with DID: {}? (y/n): ", did);
    
    stdin().read_line(&mut buf).expect("could not read response");
    let response = buf.trim().to_lowercase();
    buf.clear();
    
    if response != "y" {
        println!("Login cancelled");
        return;
    }
    
    // Parse stored credential params from wallet data
    let y1_bytes = general_purpose::STANDARD.decode(&wallet_data.credential.proof.y1).unwrap();
    let y2_bytes = general_purpose::STANDARD.decode(&wallet_data.credential.proof.y2).unwrap();
    let y1 = BigUint::from_bytes_be(&y1_bytes);
    let y2 = BigUint::from_bytes_be(&y2_bytes);
    
    // Parse secret from wallet data
    let secret = wallet_data.secret.parse::<BigUint>().unwrap();
    
    // === REGISTER WITH SERVER FIRST ===
    println!("\n📤 Registering DID with server...");
    let register_request = Request::new(RegisterRequest {
        user: did.clone(),
        y1: y1.to_bytes_be(),
        y2: y2.to_bytes_be(),
    });
    
    match client.register(register_request).await {
        Ok(_) => println!("✓ DID registered successfully with server"),
        Err(e) => {
            println!("❌ Registration failed: {}", e.message());
            return;
        }
    }
    
    println!("\n→ Generating zero-knowledge proof with your DID...");
    
    // Generate authentication data (replaces wallet.generate_auth_data)
    let k = ZKP::generate_random_number_less_than(&q);
    let r1 = ZKP::exponentiate(&alpha, &k, &p);
    let r2 = ZKP::exponentiate(&beta, &k, &p);
    
    // Request challenge using DID instead of username
    let request = Request::new(ChallengeRequest{
        user: did.clone(),  // Use DID for authentication
        r1: r1.to_bytes_be(),
        r2: r2.to_bytes_be(),
    });
    
    let response = client.create_challenge(request).await
        .expect("could not request challenge").into_inner();
        
    let auth_id = response.auth_id;
    let c = BigUint::from_bytes_be(&response.c);
    
    // Generate proof (replaces wallet.generate_proof)
    let s = zkp.solve(&k, &c, &secret);
    
    // create a request to send the proof
    let request = Request::new(SolutionRequest {
        auth_id,
        s: s.to_bytes_be(),
    });
    
    match client.verify_authentication(request).await {
        Ok(response) => {
            let response_data = response.into_inner();
            println!("\n✅ Logged in successfully with Self-Sovereign Identity!");
            println!("🆔 DID: {}", did);
            println!("🔑 Zero-knowledge proof verified!");
            println!("Session: {}", response_data.session_id);
        },
        Err(e) => {
            eprintln!("❌ SSI Login failed: {}", e.message());
        }
    }
}