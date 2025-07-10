use num_bigint::BigUint;
use tonic::{transport::Server, Code,Request, Response, Status, codegen::http::request};
use crate::zkp_auth::{auth_client::AuthClient, ChallengeRequest, RegisterRequest, SolutionRequest};
use std::io::stdin;

//importing the zkp functions i made
use ::zkp_auth::ZKP;

pub mod zkp_auth{
    include!("zkp_auth.rs");
}

#[tokio::main]
async fn main(){
    let mut buf = String::new();
    //creating the zkp instance
    let (alpha, beta, p, q) = ZKP::get_zkp_constants();
    let zkp = ZKP {alpha: alpha.clone(), beta: beta.clone(), p: p.clone(), q: q.clone()};

    let mut client = AuthClient::connect("http://127.0.0.1:50051").await.expect("could not connect to server");
    println!(" Connected to the server");

    //getting the username for regustration and authentication
    println!("Provide a username: ");
    stdin().read_line(&mut buf).expect("could not read username");
    let username = buf.trim().to_string();
    buf.clear();//empties the buffer

    //getting the secret as DECIMAL
    println!("Provide a secret to register: ");
    stdin().read_line(&mut buf).expect("could not read username");
    let secret_str: &str = buf.trim();
    let secret = secret_str.parse::<BigUint>()
        .expect("Failed to parse secret as a large number. Make sure to copy-paste the exact number.");
    buf.clear();
    

    //REGISTERING AS A USER ON THE SERVER
    //computing y1 and y2 with the exponentiate function defined in the lib.rs 
    let y1 = ZKP::exponentiate(&alpha, &secret, &p);
    let y2 = ZKP::exponentiate(&beta, &secret, &p);

    //creating registration request
    let request = RegisterRequest{
        user: username.clone(),
        y1: y1.to_bytes_be(), //only bytes can be passed to grpc so
        y2: y2.to_bytes_be(),
    };

    //sending registration request and collecting registration response
    let _response = client.register(request).await.expect("could not register with server");
    //println!("{:?}", _response);


    //LOGGIN IN
    //computing r1 and r2 with the exponentiateiate function defined in the lib.rs 
    
    //requesting for the secret a new
    println!("Provide the secret to login: ");
    stdin().read_line(&mut buf).expect("could not read username");
    let secret_str: &str = buf.trim();
    let secret = secret_str.parse::<BigUint>()
        .expect("Failed to parse secret as a large number. Make sure to copy-paste the exact number.");
    buf.clear();

    let k = ZKP::generate_random_number_less_than(&q);
    let r1 = ZKP::exponentiate(&alpha, &k, &p);
    let r2 = ZKP::exponentiate(&beta, &k, &p);
  
    //creating the challenge request (first step to login is to request for the challenge)
    let request = ChallengeRequest{
        user: username.clone(),
        r1: r1.to_bytes_be(), //only bytes can be passed to grpc so
        r2: r2.to_bytes_be(),
    };

    //sending the request and getting the challenge as a resposne from the server
    let response = client.create_challenge(request).await.expect("could not request challenge from server").into_inner();
    //println!("{:?}", _response);

    let auth_id = response.auth_id;
    let c = BigUint::from_bytes_be(&response.c);
    
    //computing the proof (solution to the challenege)
    let s= zkp.solve(&k, &c, &secret);

    //creating the request that sends the proof to the server( 2nd step to loggind in)
    let request = SolutionRequest {
        auth_id,
        s: s.to_bytes_be(),
    };

    //sending the solution and getting a response from the server (authenticated or not authenticated)
    let response_from_server = client.verify_authentication(request).await;

    match response_from_server {
    Ok(response) => {
        // Authentication successful
        let inner_response = response.into_inner();
        println!("You've logged in and the session id is {}", inner_response.session_id);
    },
    Err(status) => {
        // Authentication failed or other gRPC error
        eprintln!("Authentication failed: Code: {:?}, Message: {}", status.code(), status.message());
        std::process::exit(1); // Exit with an error code
    }
    }
    // let response = client.verify_authentication(request).await.expect("could not verfiy authentication in server").into_inner();
    // println!("Youve logged in and the session id is {}", response.session_id);

}
