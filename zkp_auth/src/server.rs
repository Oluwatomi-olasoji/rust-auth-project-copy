mod ssi;
use num_bigint::BigUint;
use tonic::{transport::Server, Code,Request, Response, Status, codegen::http::request};
use zkp_auth::auth_server::{Auth, AuthServer}; 
use zkp_auth::{RegisterRequest, RegisterResponse,ChallengeRequest, ChallengeResponse, SolutionResponse, SolutionRequest};               
use std::collections::HashMap;

use std::fmt::format;
// For the message struct
use std::sync::Mutex;

//importing the zkp functions i made
use ::zkp_auth::ZKP;

pub mod zkp_auth{
    include!("zkp_proto.rs");
}


#[derive(Debug, Default)]
struct AuthImpl {
    pub  userInfo: Mutex<HashMap<String, UserInformation>>,  // Now keyed by DID
    pub  auth_id_user_hashmap:Mutex<HashMap<String, String>>,  // Maps auth_id to DID
  
}

#[derive(Debug, Default)]
pub struct UserInformation {
    pub did: String,        // Store DID instead of username
    pub y1: BigUint, //these two are used for registration
    pub y2: BigUint,

    pub r1: BigUint,//these two are used for authentication
    pub r2: BigUint,

    pub c: BigUint, //the below are used to verify the proof
    pub s: BigUint,
    pub session_id: String,
    
}

#[tonic::async_trait]
impl Auth for AuthImpl {

    async fn register(&self, request:Request<RegisterRequest>) -> Result<Response<RegisterResponse>,Status> {
        println!("Processing Registration: {:?}", request);
        let request = request.into_inner();//into inner gives us access to the the private field

        let user_identifier = request.user;  // This is now a DID

        //to prevent empty entries for y1 and y2, which can break the proof
        if (request.y1.is_empty()|| request.y2.is_empty()) {
        return Err(Status::new(Code::InvalidArgument, "Public key y cannot be empty."));
        }
         
        // Check if this is a DID format
        if user_identifier.starts_with("did:") {
            println!("🆔 Registering user with DID: {}", user_identifier);
        } else {
            println!("⚠️  Warning: Expected DID format (did:method:identifier)");
        }

        let mut userInfo = UserInformation::default();
        userInfo.did = user_identifier.clone();
        userInfo.y1 =  BigUint::from_bytes_be(&request.y1);
        userInfo.y2 = BigUint::from_bytes_be(&request.y2);

        let mut userInfo_storage = &mut self.userInfo.lock().unwrap(); //need to dd errror handling
        
        userInfo_storage.insert(user_identifier, userInfo);
        Ok(Response::new(RegisterResponse { }))
}


    async fn create_challenge(&self, request:Request<ChallengeRequest>) -> Result<Response<ChallengeResponse>,Status> {
        println!("\n=== CHALLENGE SERVICE ===");
        println!("Processing Challenge request: {:?}", request);
        let request = request.into_inner();//into inner gives us access to the the private field

        let user_identifier = request.user;  // This is now a DID
        
        // Check if this is a DID format
        if user_identifier.starts_with("did:") {
            println!("🆔 Creating challenge for DID: {}", user_identifier);
        }
        
        //to prevent any empty requests that can break the code
        if (request.r1.is_empty() || request.r2.is_empty()){
        return Err(Status::new(Code::InvalidArgument, "Commitments cannot be empty."));
        }
        //

        let mut userInfo_storage = &mut self.userInfo.lock().unwrap(); //need to dd errror handling
       
        if let Some(userInfo) = userInfo_storage.get_mut(&user_identifier) {
            userInfo.r1 = BigUint::from_bytes_be(&request.r1);
            userInfo.r2 = BigUint::from_bytes_be(&request.r2);

            let (_,_,_, q) = ZKP::get_zkp_constants(); //takes only the q(order) variable returned from the ZKP library 

            let c = ZKP::generate_random_number_less_than(&q);
            let auth_id = ZKP::generate_random_string(12);
            
            //storing c
            userInfo.c = c.clone();

            //Storing the user id for each DID
            let mut auth_id_user_hashmap = &mut self.auth_id_user_hashmap.lock().unwrap(); //need to dd errror handling
            auth_id_user_hashmap.insert(auth_id.clone(), user_identifier);
            
            Ok(Response::new(ChallengeResponse { auth_id, c: c.to_bytes_be() } ))
        } else {
            Err(Status::new(Code::NotFound, format!("DID: {} not found in database", user_identifier)))
        }

}


      async fn verify_authentication(&self, request:Request<SolutionRequest>) -> Result<Response<SolutionResponse>,Status> {
        
        println!("\n=== ZKP VERIFIER ===");
       

        println!("Processing Verification request: {:?}", request);
        let request = request.into_inner();//into inner gives us access to the the private field

        let auth_id = request.auth_id;
        println!("  Verifying proof for user: {}", auth_id);
        
        //preventing an empty solution
        if auth_id.is_empty() {
        return Err(Status::new(Code::InvalidArgument, "Authentication ID cannot be empty."));
        }

        if request.s.is_empty() {
        return Err(Status::new(Code::InvalidArgument, "Solution 's' cannot be empty."));
        }
        ///////
        
        let mut auth_id_user_hashmap = &mut self.auth_id_user_hashmap.lock().unwrap(); //need to dd errror handling

        if let Some(user_identifier) = auth_id_user_hashmap.get(&auth_id) {
            let mut userInfo_storage = &mut self.userInfo.lock().unwrap(); //need to dd errror handling
            let userInfo = userInfo_storage.get_mut(user_identifier).expect("auth id not found");

            let s = BigUint::from_bytes_be(&request.s);

            //creating the zkp instance
            let (alpha, beta, p, q) = ZKP::get_zkp_constants();
            let zkp = ZKP {alpha, beta, p, q};
            
            //creating the veriication result usinf the verfiy solution function
            let verification_result = zkp.verify_solution(&userInfo.r1, &userInfo.r2, &userInfo.y1, &userInfo.y2, &userInfo.c, &s);
            println!("Veification result: {}", verification_result);

            if verification_result {
    let session_id = ZKP::generate_random_string(12);
    
    println!("  ✅ Proof verified successfully!");
    println!("  ✅ Self-Sovereign Identity assertion confirmed for DID: {}", user_identifier);
    println!("  → Granting access with session: {}", session_id);
    
    Ok(Response::new(SolutionResponse{session_id}))
} else {
    println!("  ❌ Proof verification failed!");
    Err(Status::new(Code::PermissionDenied, 
    format!("Identity verification failed for auth_id: {}", auth_id)))
}
           
        } else {
            Err(Status::new(Code::NotFound, format!("AuthId: {} not found in database", auth_id)))
        }
    
}
}

#[tokio::main] //this makes it an synchronous function
async fn main(){
    let addy = "127.0.0.1:50051".to_string();
    println!("🔐 SSI Authentication Server - Self-Sovereign Identity with Zero-Knowledge Proofs");
    println!("📋 This server verifies Decentralized Identifiers (DIDs) using ZKP");
    println!("The server is running here {}", addy);

    let auth_impl = AuthImpl::default();

    Server::builder().add_service(AuthServer::new(auth_impl))
    .serve(addy.parse().expect("could not convert address"))
    .await
    .unwrap();
}