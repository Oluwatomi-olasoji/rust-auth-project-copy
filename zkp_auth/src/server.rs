
use num_bigint::BigUint;
use tonic::{transport::Server, Code,Request, Response, Status, codegen::http::request};
use zkp_auth::auth_server::{Auth, AuthServer}; 
use zkp_auth::{RegisterRequest, RegisterResponse,ChallengeRequest, ChallengeResponse, SolutionResponse, SolutionRequest};               use std::collections::HashMap;

use std::fmt::format;
// For the message struct
use std::sync::Mutex;

//importing the zkp functions i made
use ::zkp_auth::ZKP;

pub mod zkp_auth{
    include!("zkp_auth.rs");
}


#[derive(Debug, Default)]
struct AuthImpl {
    pub  userInfo: Mutex<HashMap<String, UserInformation>>,
    pub  auth_id_user_hashmap:Mutex<HashMap<String, String>>,
  
}

#[derive(Debug, Default)]
pub struct UserInformation {
    pub username: String,
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

        let username = request.user;
        
        let mut userInfo = UserInformation::default();
        userInfo.username = username.clone();
        userInfo.y1 =  BigUint::from_bytes_be(&request.y1);
        userInfo.y2 = BigUint::from_bytes_be(&request.y2);

        let mut userInfo_storage = &mut self.userInfo.lock().unwrap(); //need to dd errror handling
        
        userInfo_storage.insert(username, userInfo);
        Ok(Response::new(RegisterResponse { }))
}


    async fn create_challenge(&self, request:Request<ChallengeRequest>) -> Result<Response<ChallengeResponse>,Status> {
        println!("Processing Challenge request: {:?}", request);
        let request = request.into_inner();//into inner gives us access to the the private field

        let username = request.user;
        
        let mut userInfo_storage = &mut self.userInfo.lock().unwrap(); //need to dd errror handling
       
        if let Some(userInfo) = userInfo_storage.get_mut(&username) {
            userInfo.r1 = BigUint::from_bytes_be(&request.r1);
            userInfo.r2 = BigUint::from_bytes_be(&request.r2);

            let (_,_,_, q) = ZKP::get_zkp_constants(); //takes only the q(order) variable returned from the ZKP library 

            let c = ZKP::generate_random_number_less_than(&q);
            let auth_id = "olololo".to_string();

            //Storing the user id for each username
            let mut auth_id_user_hashmap = &mut self.auth_id_user_hashmap.lock().unwrap(); //need to dd errror handling
            auth_id_user_hashmap.insert(auth_id.clone(), username);
            
            Ok(Response::new(ChallengeResponse { auth_id, c: c.to_bytes_be() } ))
        } else {
            Err(Status::new(Code::NotFound, format!("User: {} not found in database", username)))
        }

}
     async fn verify_authentication(&self, request:Request<SolutionRequest>) -> Result<Response<SolutionResponse>,Status> {
        todo!()
}
    
}

#[tokio::main] //this makes it an synchronous function
async fn main(){
    let addy = "127.0.0.1:50051".to_string();
    println!("The server is running here {}", addy);

    let auth_impl = AuthImpl::default();

    Server::builder().add_service(AuthServer::new(auth_impl))
    .serve(addy.parse().expect("could not convert address"))
    .await
    .unwrap();
}