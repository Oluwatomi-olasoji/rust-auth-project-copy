use serde::{Deserialize, Serialize};

// Simple Verifiable Credential structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifiableCredential {
    pub id: String,                    // Unique ID for this credential
    pub issuer: String,                // Who issued it (university)
    pub subject: String,               // Who it's for (username)
    pub claims: Claims,                // The actual claims/attributes
    pub zkp_params: ZKPParams,         // ZKP public parameters
}

// What the credential claims about the holder
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    pub name: String,
    pub age: u32,
    pub university: String,
}

// stores the ZKP public parameters with the credential
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZKPParams {
    pub y1: Vec<u8>,    // Public key part 1
    pub y2: Vec<u8>,    // Public key part 2
}




// use serde::{Deserialize, Serialize};
// use chrono::{DateTime, Utc};

// // W3C Verifiable Credential structure
// #[derive(Debug, Clone, Serialize, Deserialize)]
// pub struct VerifiableCredential {
//     #[serde(rename = "@context")]
//     pub context: Vec<String>,
    
//     #[serde(rename = "type")]
//     pub credential_type: Vec<String>,
    
//     pub id: String,
//     pub issuer: String,
    
//     #[serde(rename = "issuanceDate")]
//     pub issuance_date: String,
    
//     #[serde(rename = "credentialSubject")]
//     pub credential_subject: CredentialSubject,
    
//     // Store ZKP public keys as proof
//     pub proof: ZKPProof,
// }

// #[derive(Debug, Clone, Serialize, Deserialize)]
// pub struct CredentialSubject {
//     pub id: String,  // DID of holder
//     pub name: String,
//     pub university: String,
// }

// #[derive(Debug, Clone, Serialize, Deserialize)]
// pub struct ZKPProof {
//     #[serde(rename = "type")]
//     pub proof_type: String,
//     pub y1: String,  // Base64 encoded
//     pub y2: String,  // Base64 encoded
// }