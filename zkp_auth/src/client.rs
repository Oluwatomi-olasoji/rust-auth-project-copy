mod ssi;
use ssi::wallet::Wallet;
use ssi::issuer::Issuer;
use base64::{Engine as _, engine::general_purpose};
use num_bigint::BigUint;
use tonic::{transport::Server, Code,Request, Response, Status, codegen::http::request};
use crate::zkp_auth::{auth_client::AuthClient, ChallengeRequest, RegisterRequest, SolutionRequest};
use std::io::stdin;

//importing the zkp functions i made
use ::zkp_auth::ZKP;

pub mod zkp_auth{
    include!("zkp_auth.rs");
}

#[tokio::main]
async fn main(){
    let mut buf = String::new();
    //creating the zkp instance
    let (alpha, beta, p, q) = ZKP::get_zkp_constants();
    let zkp = ZKP {alpha: alpha.clone(), beta: beta.clone(), p: p.clone(), q: q.clone()};

    let mut client = AuthClient::connect("http://127.0.0.1:50051").await.expect("could not connect to server");
    println!(" Connected to the server");

    //REGISTERING AS A USER ON THE SERVER
    //getting the username for regustration and authentication
    println!("Provide a username: ");
    stdin().read_line(&mut buf).expect("could not read username");
    let username = buf.trim().to_string();
    buf.clear();//empties the buffer

    //getting the secret as DECIMAL
    println!("Provide a secret to register: ");
    stdin().read_line(&mut buf).expect("could not read username");
    let secret_str: &str = buf.trim();
    let secret = secret_str.parse::<BigUint>()
        .expect("Failed to parse secret as a large number. Make sure to copy-paste the exact number.");
    buf.clear();
    

   // === STEP 1: CREATE/LOAD WALLET ===
println!("\n📁 WALLET MANAGEMENT");
let mut wallet = Wallet::new(secret.clone());

// Try to load existing credential
let has_credential = wallet.load_credential(&username);

// === STEP 2: GET OR CREATE CREDENTIAL ===
let (y1, y2) = if has_credential {
    // Use existing credential
    println!("  Using existing credential");
    wallet.get_zkp_params().unwrap()
} else {
    // Need to create new credential
    println!("  No credential found - creating new one");
    
    // Compute ZKP public parameters
    let y1 = ZKP::exponentiate(&alpha, &secret, &p);
    let y2 = ZKP::exponentiate(&beta, &secret, &p);
    
    // Simulate credential issuance
    let credential = Issuer::issue_credential(&username, &y1, &y2);
    
    // Store in wallet
    wallet.store_credential(credential);
    
    (y1, y2)
};

// === STEP 3: REGISTER WITH SERVER ===
println!("\n📝 REGISTRATION");
let request = RegisterRequest{
    user: username.clone(),
    y1: y1.to_bytes_be(),
    y2: y2.to_bytes_be(),
};

let _response = client.register(request).await.expect("could not register");
println!("  ✓ Registered with server");

// === STEP 4: PASSWORDLESS AUTHENTICATION ===
println!("\n🔐 PASSWORDLESS AUTHENTICATION");

// Request secret again for login
println!("Provide the secret to login: ");
stdin().read_line(&mut buf).expect("could not read username");
let secret_str: &str = buf.trim();
let secret = secret_str.parse::<BigUint>()
    .expect("Failed to parse secret");
buf.clear();

// Generate commitment
let k = ZKP::generate_random_number_less_than(&q);
let r1 = ZKP::exponentiate(&alpha, &k, &p);
let r2 = ZKP::exponentiate(&beta, &k, &p);

// Request challenge
println!("  → Requesting challenge from verifier...");
let request = ChallengeRequest{
    user: username.clone(),
    r1: r1.to_bytes_be(),
    r2: r2.to_bytes_be(),
};

let response = client.create_challenge(request).await
    .expect("could not request challenge").into_inner();
    
let auth_id = response.auth_id;
let c = BigUint::from_bytes_be(&response.c);
println!("  ← Received challenge");

// Use wallet to generate proof
println!("  → Generating ZKP proof...");
let s = zkp.solve(&k, &c, &secret);  // Note: In production, wallet would do this

// Send proof
let request = SolutionRequest {
    auth_id,
    s: s.to_bytes_be(),
};

println!("  → Sending proof to verifier...");

// Verify authentication
match client.verify_authentication(request).await {
    Ok(response) => {
        let inner_response = response.into_inner();
        println!("\n✅ AUTHENTICATION SUCCESSFUL!");
        
        // Show credential info
        if let Some(cred) = wallet.get_credential() {
            println!("\n📋 Authenticated with credential:");
            println!("  ID: {}", cred.id);
            println!("  Holder: {}", cred.claims.name);
            println!("  University: {}", cred.claims.university);
        }
        
        println!("\n🔑 Session ID: {}", inner_response.session_id);
    },
    Err(status) => {
        eprintln!("\n❌ AUTHENTICATION FAILED");
        eprintln!("  Error: {}", status.message());
        std::process::exit(1);
    }
}
}