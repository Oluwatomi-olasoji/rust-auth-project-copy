use ::zkp_auth::ssi::credential::{VerifiableCredential, DID};
use ::zkp_auth::ssi::issuer::Issuer;
use num_bigint::BigUint;
use std::fs;
use ::zkp_auth::ZKP;
use serde::{Serialize, Deserialize};
use base64::{Engine as _, engine::general_purpose};

pub mod zkp_auth {
    include!("zkp_proto.rs");
}

// The wallet stores credentials and generates ZKP proofs

// Store wallet data including secret and DID
#[derive(Serialize, Deserialize)]
pub struct WalletData {
    pub did: String,                        // Store DID as string
    pub credential: VerifiableCredential,
    pub secret: String,                     // Store as string for JSON
}

pub struct Wallet {
    username: String,
    did: Option<DID>,
    credential: Option<VerifiableCredential>,
    zkp_secret: Option<BigUint>,
}

impl Wallet {
    // Create new wallet for a user
    pub fn new(username: String) -> Self {
        Self {
            username,
            did: None,
            credential: None,
            zkp_secret: None,
        }
    }
    
    // Generate a new secret for this wallet
    pub fn generate_secret(&mut self, q: &BigUint) -> BigUint {
        let secret = ZKP::generate_random_number_less_than(q);
        self.zkp_secret = Some(secret.clone());
        println!("✓ Generated new secret for wallet");
        secret
    }
    
    // Store credential, DID AND secret
    pub fn store_credential(&mut self, credential: VerifiableCredential, did: DID) {
        let wallet_data = WalletData {
            did: did.to_string(),
            credential: credential.clone(),
            secret: self.zkp_secret.as_ref().unwrap().to_string(),
        };
        
        // Use DID-based filename instead of username
        let did_hash = did.to_string().replace(":", "_");
        let filename = format!("{}_wallet.json", did_hash);
        let json = serde_json::to_string_pretty(&wallet_data).unwrap();
        fs::write(&filename, json).unwrap();
        
        self.credential = Some(credential);
        self.did = Some(did);
        println!("✓ Wallet saved with credential, DID and secret");
        println!("📁 Wallet file: {}", filename);
    }
    
    // Load wallet including secret and DID
    pub fn load_by_did(did_string: &str) -> Option<WalletData> {
        let did_hash = did_string.replace(":", "_");
        let filename = format!("{}_wallet.json", did_hash);
        
        if let Ok(data) = fs::read_to_string(&filename) {
            if let Ok(wallet_data) = serde_json::from_str::<WalletData>(&data) {
                println!("✓ Loaded wallet for DID: {}", did_string);
                return Some(wallet_data);
            }
        }
        None
    }
    
    // Get the DID for this wallet
    pub fn get_did(&self) -> Option<&DID> {
        self.did.as_ref()
    }
    
    // Generate complete authentication data
    pub fn generate_auth_data(&self, zkp: &ZKP) -> Option<(BigUint, BigUint, BigUint)> {
        if let (Some(cred), Some(secret)) = (&self.credential, &self.zkp_secret) {
            // Generate k for this authentication
            let k = ZKP::generate_random_number_less_than(&zkp.q);
            
            // Get y1, y2 from credential proof (decode from base64)
            let y1_bytes = general_purpose::STANDARD.decode(&cred.proof.y1).unwrap();
            let y2_bytes = general_purpose::STANDARD.decode(&cred.proof.y2).unwrap();
            let y1 = BigUint::from_bytes_be(&y1_bytes);
            let y2 = BigUint::from_bytes_be(&y2_bytes);
            
            // Compute r1, r2
            let r1 = ZKP::exponentiate(&zkp.alpha, &k, &zkp.p);
            let r2 = ZKP::exponentiate(&zkp.beta, &k, &zkp.p);
            
            Some((r1, r2, k))
        } else {
            None
        }
    }
    
    // Generate proof given challenge
    pub fn generate_proof(&self, k: &BigUint, challenge: &BigUint, zkp: &ZKP) -> BigUint {
        let secret = self.zkp_secret.as_ref().unwrap();
        zkp.solve(k, challenge, secret)
    }
    
    // Get ZKP params for registration
    pub fn get_zkp_params(&self) -> Option<(BigUint, BigUint)> {
        if let Some(cred) = &self.credential {
            // Decode from base64
            let y1_bytes = general_purpose::STANDARD.decode(&cred.proof.y1).unwrap();
            let y2_bytes = general_purpose::STANDARD.decode(&cred.proof.y2).unwrap();
            let y1 = BigUint::from_bytes_be(&y1_bytes);
            let y2 = BigUint::from_bytes_be(&y2_bytes);
            Some((y1, y2))
        } else {
            None
        }
    }
}

// Wallet executable main function
#[tokio::main]
async fn main() {
    let mut buf = String::new();
    
    println!("🔐 SSI WALLET - Self-Sovereign Identity System");
    println!("📋 This wallet uses Decentralized Identifiers (DIDs) for authentication");
    
    println!("\nChoose an option:");
    println!("1. Create new wallet");
    println!("2. Load existing wallet");
    println!("Enter choice (1 or 2): ");
    std::io::stdin().read_line(&mut buf).expect("could not read choice");
    let choice = buf.trim().to_string();
    buf.clear();

    match choice.as_str() {
        "1" => {
            // Create new wallet
            println!("Creating new Self-Sovereign Identity wallet...");
            println!("Enter username (for DID generation): ");
            std::io::stdin().read_line(&mut buf).expect("could not read username");
            let username = buf.trim().to_string();
            buf.clear();

            let mut wallet = Wallet::new(username.clone());
            
            let (alpha, beta, p, q) = ::zkp_auth::ZKP::get_zkp_constants();
            let secret = wallet.generate_secret(&q);
            let y1 = ::zkp_auth::ZKP::exponentiate(&alpha, &secret, &p);
            let y2 = ::zkp_auth::ZKP::exponentiate(&beta, &secret, &p);
            
            let (credential, did) = Issuer::issue_credential(&username, &y1, &y2);
            wallet.store_credential(credential, did.clone());
            
            println!("\n✅ New SSI wallet created!");
            println!("\n🆔 YOUR NEW DECENTRALIZED IDENTIFIER (DID):");
            println!("   {}", did.to_string());
            println!("   📝 Save this DID - it's your unique digital identity!");
            println!("\n📤 Use this DID with the client application for authentication");
        },
        "2" => {
            // Load existing wallet by DID
            println!("Enter your DID: ");
            std::io::stdin().read_line(&mut buf).expect("could not read DID");
            let did_string = buf.trim().to_string();
            buf.clear();

            if !did_string.starts_with("did:zkp:") {
                println!("❌ Invalid DID format. Expected format: did:zkp:xxxxx");
                return;
            }

            if let Some(_wallet_data) = Wallet::load_by_did(&did_string) {
                println!("\n🆔 YOUR DECENTRALIZED IDENTIFIER (DID):");
                println!("   {}", did_string);
                println!("   This is your unique, self-sovereign identity!");
                
                println!("\nWallet ready for authentication");
                println!("📤 Copy your DID above and paste it into the client application");
                println!("Press Enter when done...");
                std::io::stdin().read_line(&mut buf).unwrap();
            } else {
                println!("❌ Wallet not found for DID: {}", did_string);
                println!("Make sure you have the correct DID or create a new wallet");
            }
        },
        _ => {
            println!("❌ Invalid choice. Please run the wallet again and choose 1 or 2.");
        }
    }
}