use super::credential::{VerifiableCredential, Claims, ZKPParams};
use num_bigint::BigUint;

// Simulated credential issuer (hardcoded for demo)
pub struct Issuer;

impl Issuer {
    // Issue a credential with hardcoded values
    pub fn issue_credential(username: &str, y1: &BigUint, y2: &BigUint) -> VerifiableCredential {
        println!("\n🏛️ ISSUER: Pan-Atlantic University");
        println!("  Issuing credential for: {}", username);
        
        // Create the credential
        let credential = VerifiableCredential {
            id: format!("pau_cred_{}", username),
            issuer: "Pan-Atlantic University".to_string(),
            subject: username.to_string(),
            claims: Claims {
                name: username.to_string(),
                age: 22,  // Hardcoded age
                university: "Pan-Atlantic University".to_string(),
            },
            zkp_params: ZKPParams {
                y1: y1.to_bytes_be(),
                y2: y2.to_bytes_be(),
            },
        };
        
        println!("  ✓ Credential created with ID: {}", credential.id);
        
        credential
    }
}

// use super::credential::{VerifiableCredential, CredentialSubject, ZKPProof};
// use chrono::Utc;
// use base64::{Engine as _, engine::general_purpose};

// pub struct Issuer;

// impl Issuer {
//     // Create a hardcoded credential
//     pub fn create_credential(username: &str, y1_bytes: &[u8], y2_bytes: &[u8]) -> VerifiableCredential {
//         VerifiableCredential {
//             context: vec![
//                 "https://www.w3.org/2018/credentials/v1".to_string(),
//                 "https://www.w3.org/2018/credentials/examples/v1".to_string(),
//             ],
//             credential_type: vec![
//                 "VerifiableCredential".to_string(),
//                 "UniversityCredential".to_string(),
//             ],
//             id: format!("http://example.edu/credentials/{}", username),
//             issuer: "https://example.edu/issuers/pan-atlantic".to_string(),
//             issuance_date: Utc::now().to_rfc3339(),
//             credential_subject: CredentialSubject {
//                 id: format!("did:example:{}", username),
//                 name: username.to_string(),
//                 university: "Pan-Atlantic University".to_string(),
//             },
//             proof: ZKPProof {
//                 proof_type: "ZKPSignature2024".to_string(),
//                 y1: general_purpose::STANDARD.encode(y1_bytes),
//                 y2: general_purpose::STANDARD.encode(y2_bytes),
//             },
//         }
//     }
// }