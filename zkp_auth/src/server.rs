pub mod zkp_auth{
    include!("zkp_auth.rs");
}
use tonic::{transport::Server, Code,Request, Response, Status, codegen::http::request};
use zkp_auth::auth_server::{Auth, AuthServer}; 
use zkp_auth::{RegisterRequest, RegisterResponse};

use crate::zkp_auth::{ChallengeRequest, ChallengeResponse, SolutionResponse, SolutionRequest};               // For the message struct

#[derive(Debug, Default)]
struct AuthImpl {}

#[tonic::async_trait]
impl Auth for AuthImpl {
    async fn register(&self, request:Request<RegisterRequest>) -> Result<Response<RegisterResponse>,Status> {
        todo!()
}
    async fn create_challenge(&self, request:Request<ChallengeRequest>) -> Result<Response<ChallengeResponse>,Status> {
        todo!()
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