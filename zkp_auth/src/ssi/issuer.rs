use super::credential::{VerifiableCredential, CredentialSubject, ZKPProof, DID};
use num_bigint::BigUint;
use chrono::Utc;
use base64::{Engine as _, engine::general_purpose};

// Simulated credential issuer (hardcoded for demo)
pub struct Issuer;

impl Issuer {
    // Issue a credential with hardcoded values and return both credential and DID
    pub fn issue_credential(username: &str, y1: &BigUint, y2: &BigUint) -> (VerifiableCredential, DID) {
        println!("\n🏛️ ISSUER: Pan-Atlantic University");
        println!("  Issuing credential for: {}", username);
        
        // Generate DID from ZKP parameters
        let did = DID::from_zkp_params(y1, y2);
        let did_string = did.to_string();
        
        println!("  📋 Generated DID: {}", did_string);
        println!("  🔑 This DID is your unique decentralized identifier!");
        
        // Create the credential
        let credential = VerifiableCredential {
            context: vec![
                "https://www.w3.org/2018/credentials/v1".to_string(),
                "https://www.w3.org/2018/credentials/examples/v1".to_string(),
            ],
            credential_type: vec![
                "VerifiableCredential".to_string(),
                "UniversityCredential".to_string(),
            ],
            id: format!("https://pau.edu.ng/credentials/{}", did.identifier),
            issuer: "did:web:pau.edu.ng".to_string(),
            issuance_date: Utc::now().to_rfc3339(),
            credential_subject: CredentialSubject {
                id: did_string.clone(),
                name: username.to_string(),
                age: 22,  // Hardcoded age
                university: "Pan-Atlantic University".to_string(),
            },
            proof: ZKPProof {
                proof_type: "ZKPSignature2024".to_string(),
                verification_method: format!("{}#zkp-key-1", did_string),
                y1: general_purpose::STANDARD.encode(y1.to_bytes_be()),
                y2: general_purpose::STANDARD.encode(y2.to_bytes_be()),
            },
        };
        
        println!("  ✓ Credential created with ID: {}", credential.id);
        
        (credential, did)
    }
}