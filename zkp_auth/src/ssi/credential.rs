use serde::{Deserialize, Serialize};
use num_bigint::BigUint;
use sha2::{Sha256, Digest};

// W3C Verifiable Credential structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifiableCredential {
    #[serde(rename = "@context")]
    pub context: Vec<String>,
    
    #[serde(rename = "type")]
    pub credential_type: Vec<String>,
    
    pub id: String,
    pub issuer: String,
    
    #[serde(rename = "issuanceDate")]
    pub issuance_date: String,
    
    #[serde(rename = "credentialSubject")]
    pub credential_subject: CredentialSubject,
    
    // Store ZKP public keys as proof
    pub proof: ZKPProof,
}

// What the credential claims about the holder
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialSubject {
    pub id: String,  // DID of holder
    pub name: String,
    pub age: u32,
    pub university: String,
}

// stores the ZKP public parameters with the credential
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZKPProof {
    #[serde(rename = "type")]
    pub proof_type: String,
    #[serde(rename = "verificationMethod")]
    pub verification_method: String,
    pub y1: String,  // Base64 encoded
    pub y2: String,  // Base64 encoded
}

// DID structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DID {
    pub method: String,      // "zkp"
    pub identifier: String,  // derived from public key
}

impl DID {
    // Generate DID from ZKP public keys
    pub fn from_zkp_params(y1: &BigUint, y2: &BigUint) -> Self {
        let combined = format!("{}{}", y1.to_string(), y2.to_string());
        let mut hasher = Sha256::new();
        hasher.update(combined.as_bytes());
        let hash = hasher.finalize();
        let identifier = hex::encode(&hash[..16]); // Use first 16 bytes
        
        Self {
            method: "zkp".to_string(),
            identifier,
        }
    }
    
    // Convert DID to string format
    pub fn to_string(&self) -> String {
        format!("did:{}:{}", self.method, self.identifier)
    }
    
    // Parse DID from string
    pub fn from_string(did_str: &str) -> Option<Self> {
        let parts: Vec<&str> = did_str.split(':').collect();
        if parts.len() == 3 && parts[0] == "did" {
            Some(Self {
                method: parts[1].to_string(),
                identifier: parts[2].to_string(),
            })
        } else {
            None
        }
    }
}