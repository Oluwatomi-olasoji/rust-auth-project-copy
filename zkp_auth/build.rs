fn main(){
tonic_build::configure()
.build_server(true)
.out_dir("src/")
.compile(
    &["proto/zkp_authentication_protobuff.proto"],
    &["proto/"]
)
.unwrap();

}