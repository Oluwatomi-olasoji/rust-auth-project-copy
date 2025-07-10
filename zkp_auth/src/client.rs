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

    //getting the username for regustration and authentication
    println!("Provide a username: ");
    stdin().read_line(&mut buf).expect("could not read username");
    let username = buf.trim().to_string();
    buf.clear();//empties the buffer

    // === REGISTRATION OR LOGIN ===
    let mut wallet = Wallet::new(username.clone());

    if wallet.load() {
        // === PASSWORDLESS LOGIN FLOW ===
        println!("\n🔐 PASSWORDLESS AUTHENTICATION");
        println!("Found wallet for {}. Login with wallet? (y/n): ", username);
        
        stdin().read_line(&mut buf).expect("could not read response");
        let response = buf.trim().to_lowercase();
        buf.clear();
        
        if response != "y" {
            println!("Login cancelled");
            return;
        }
        
        // Get stored credential params
        let (y1, y2) = wallet.get_zkp_params().unwrap();
        
        // No need to register again, go straight to authentication
        println!("\n→ Authenticating with wallet...");
        
        // Generate authentication data using wallet
        let (r1, r2, k) = wallet.generate_auth_data(&zkp).unwrap();
        
        // Request challenge
        let request = ChallengeRequest{
            user: username.clone(),
            r1: r1.to_bytes_be(),
            r2: r2.to_bytes_be(),
        };
        
        let response = client.create_challenge(request).await
            .expect("could not request challenge").into_inner();
            
        let auth_id = response.auth_id;
        let c = BigUint::from_bytes_be(&response.c);
        
        // Wallet generates proof
        let s = wallet.generate_proof(&k, &c, &zkp);
        
        // Send proof
        let request = SolutionRequest {
            auth_id,
            s: s.to_bytes_be(),
        };
        
        match client.verify_authentication(request).await {
            Ok(response) => {
                println!("\n✅ Logged in successfully!");
                println!("Session: {}", response.into_inner().session_id);
            },
            Err(e) => {
                eprintln!("❌ Login failed: {}", e.message());
            }
        }
        
    } else {
        // === NEW USER REGISTRATION ===
        println!("\n👤 NEW USER REGISTRATION");
        println!("No wallet found. Creating new account...");
        
        // Wallet generates its own secret
        let secret = wallet.generate_secret(&q);
        
        // Compute y1, y2
        let y1 = ZKP::exponentiate(&alpha, &secret, &p);
        let y2 = ZKP::exponentiate(&beta, &secret, &p);
        
        // Issue credential
        let credential = Issuer::issue_credential(&username, &y1, &y2);
        wallet.store_credential(credential);
        
        // Register with server
        let request = RegisterRequest{
            user: username.clone(),
            y1: y1.to_bytes_be(),
            y2: y2.to_bytes_be(),
        };
        
        client.register(request).await.expect("could not register");
        
        println!("\n✅ Registration complete!");
        println!("Your wallet has been created. You can now login with just your username.");
    }
}