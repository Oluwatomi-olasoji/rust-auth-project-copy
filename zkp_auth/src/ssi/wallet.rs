use super::credential::VerifiableCredential;
use num_bigint::BigUint;
use std::fs;
use ::zkp_auth::ZKP;

// The wallet stores credentials and generates ZKP proofs
pub struct Wallet {
    credential: Option<VerifiableCredential>,
    zkp_secret: BigUint,  // The secret 'x' used for ZKP
}

impl Wallet {
    // Create a new wallet with a secret
    pub fn new(secret: BigUint) -> Self {
        Self {
            credential: None,
            zkp_secret: secret,
        }
    }
    
    // === CREDENTIAL STORAGE Functions ===
    
    // Save credential to a JSON file
    pub fn store_credential(&mut self, credential: VerifiableCredential) {
        // Create filename based on username
        let filename = format!("{}_wallet.json", credential.subject);
        
        // Convert credential to JSON
        let json = serde_json::to_string_pretty(&credential).unwrap();
        
        // Write to file
        fs::write(&filename, json).unwrap();
        
        // Also store in memory
        self.credential = Some(credential);
        
        println!("✓ Credential stored in wallet file: {}", filename);
    }
    
    // Load credential from file if it exists
    pub fn load_credential(&mut self, username: &str) -> bool {
        let filename = format!("{}_wallet.json", username);
        
        // Try to read the file
        if let Ok(data) = fs::read_to_string(&filename) {
            // Try to parse the JSON
            if let Ok(cred) = serde_json::from_str::<VerifiableCredential>(&data) {
                self.credential = Some(cred);
                println!("✓ Loaded existing credential from wallet");
                return true;
            }
        }
        
        println!("ℹ️ No existing credential found");
        false
    }
    
    // === ZKP GENERATOR Functions ===
    
    // Generate a ZKP proof for a given challenge
    pub fn generate_proof(&self, challenge: &BigUint, zkp: &ZKP) -> BigUint {
        // Generate random k
        let k = ZKP::generate_random_number_less_than(&zkp.q);
        
        // Compute s = k - c * x mod q
        zkp.solve(&k, challenge, &self.zkp_secret)
    }
    
    // === Helper Functions ===
    
    // Get the stored credential
    pub fn get_credential(&self) -> Option<&VerifiableCredential> {
        self.credential.as_ref()
    }
    
    // Get ZKP parameters from the credential
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
// use super::credential::VerifiableCredential;
// use std::fs;

// pub struct Wallet {
//     pub username: String,
//     pub credential: Option<VerifiableCredential>,
// }

// impl Wallet {
//     // Create new wallet for a user
//     pub fn new(username: String) -> Self {
//         Self {
//             username,
//             credential: None,
//         }
//     }
    
//     // Try to load existing wallet from file
//     pub fn load(username: &str) -> Option<VerifiableCredential> {
//         let filename = format!("{}_credential.json", username);
        
//         if let Ok(data) = fs::read_to_string(&filename) {
//             if let Ok(cred) = serde_json::from_str(&data) {
//                 println!("✓ Found existing credential for {}", username);
//                 return Some(cred);
//             }
//         }
        
//         None
//     }
    
//     // Save credential to file
//     pub fn save_credential(&mut self, credential: VerifiableCredential) {
//         self.credential = Some(credential.clone());
        
//         let filename = format!("{}_credential.json", self.username);
//         let json = serde_json::to_string_pretty(&credential).unwrap();
        
//         fs::write(&filename, json).unwrap();
//         println!("✓ Credential saved to {}", filename);
//     }
// }