use super::credential::VerifiableCredential;
use num_bigint::BigUint;
use std::fs;
use ::zkp_auth::ZKP;
use serde::{Serialize, Deserialize};

// The wallet stores credentials and generates ZKP proofs


// Store wallet data including secret
#[derive(Serialize, Deserialize)]
pub struct WalletData {
    pub credential: VerifiableCredential,
    pub secret: String,  // Store as string for JSON
}

pub struct Wallet {
    username: String,
    credential: Option<VerifiableCredential>,
    zkp_secret: Option<BigUint>,
}

impl Wallet {
    // Create new wallet for a user
    pub fn new(username: String) -> Self {
        Self {
            username,
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
    
    // Store credential AND secret
    pub fn store_credential(&mut self, credential: VerifiableCredential) {
        let wallet_data = WalletData {
            credential: credential.clone(),
            secret: self.zkp_secret.as_ref().unwrap().to_string(),
        };
        
        let filename = format!("{}_wallet.json", self.username);
        let json = serde_json::to_string_pretty(&wallet_data).unwrap();
        fs::write(&filename, json).unwrap();
        
        self.credential = Some(credential);
        println!("✓ Wallet saved with credential and secret");
    }
    
    // Load wallet including secret
    pub fn load(&mut self) -> bool {
        let filename = format!("{}_wallet.json", self.username);
        
        if let Ok(data) = fs::read_to_string(&filename) {
            if let Ok(wallet_data) = serde_json::from_str::<WalletData>(&data) {
                self.credential = Some(wallet_data.credential);
                self.zkp_secret = Some(wallet_data.secret.parse().unwrap());
                println!("✓ Loaded wallet for {}", self.username);
                return true;
            }
        }
        false
    }
    
    // Generate complete authentication data
    pub fn generate_auth_data(&self, zkp: &ZKP) -> Option<(BigUint, BigUint, BigUint)> {
        if let (Some(cred), Some(secret)) = (&self.credential, &self.zkp_secret) {
            // Generate k for this authentication
            let k = ZKP::generate_random_number_less_than(&zkp.q);
            
            // Get y1, y2 from credential
            let y1 = BigUint::from_bytes_be(&cred.zkp_params.y1);
            let y2 = BigUint::from_bytes_be(&cred.zkp_params.y2);
            
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
            let y1 = BigUint::from_bytes_be(&cred.zkp_params.y1);
            let y2 = BigUint::from_bytes_be(&cred.zkp_params.y2);
            Some((y1, y2))
        } else {
            None
        }
    }
}