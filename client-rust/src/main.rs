use aws_credential_types::Credentials;
use aws_sigv4::http_request::SignableBody;
use aws_sigv4::http_request::{sign, SigningSettings, SigningError, SignableRequest};
use aws_sigv4::sign::v4;
use http;
use std::time::SystemTime;
use reqwest::{self, Error, Response};
use serde_json::{from_str, Value};

const METHOD: &str = "POST";
const ENDPOINT: &str = "http://localhost:8765/validate";
const ENDPOINT_RESIGN: &str = "http://localhost:8765/validateAndSign";
const SERVICE: &str = "simulator";
const REGION: &str = "test";
const NAME: &str = "demo-rust";
const KID: &str = "primary";
const SECRET_KEY: &str = "testkey";

#[tokio::main]
async fn main() -> Result<(), SigningError> {
    let response_sign = sign_func().await;
    match response_sign {
        Ok(value) => {
            // I need to use two 'let' statement because, for borrowing functionality, I can't use 'value'
            // twice inside the println!(), so I need to use it and put the result on different variables
            // otherwise, the second time I use 'value', compiler says 'value already borrowed'
            let status = value.status();
            let stampa = value.bytes().await;
            println!("Response {:?}, with status code: {:?} \n", stampa, status)
        },
        Err(error) => println!("Error: {}", error),
    }

    let response_resign = resign_func().await;
    match response_resign {
        Ok(value) => {
            // I need to use two 'let' statement because, for borrowing functionality, I can't use 'value'
            // twice inside the println!(), so I need to use it and put the result on different variables
            // otherwise, the second time I use 'value', compiler says 'value already borrowed'
            let status = value.status();
            let stampa = value.bytes().await;
            println!("Response {:?}, with status code: {:?}", stampa, status)
        },
        Err(error) => println!("Error: {}", error),
    }

    Ok(())
}

async fn sign_func() -> Result<Response, Error> {
    // r#...# stands for raw string that ignore special characters
    let req_body = r#"{ "data": "hello world" }"#;
    // Create json body to ensure that when I pass it as bytes or string, it will be created correctly
    let json_body = from_str::<Value>(req_body).unwrap();

    // Set up information and settings for the signing
    // You can obtain credentials from `SdkConfig`.
    let identity = Credentials::new(
        format!("{NAME}:{KID}"), // access_key_id
        format!("{SECRET_KEY}"), // secret_key
        None,
        None,
        "hardcoded-credentials"
    ).into();

    let signing_settings = SigningSettings::default();

    let signing_params = v4::SigningParams::builder()
        .identity(&identity)
        .region(REGION)
        .name(SERVICE)
        .time(SystemTime::now())
        .settings(signing_settings)
        .build()
        .unwrap()
        .into();

    // Needed this to be able to pass the body as_bytes in SignableRequest::new(). If I don't do this, the
    // compiler complains about 'temporary value dropped while borrowed' and suggest to use 'let' statement
    // to create a 'live longer' variable
    let body = json_body.to_string();

    // Convert the HTTP request into a signable request
    let signable_request = SignableRequest::new(
        METHOD,
        ENDPOINT,
        std::iter::empty(),
        SignableBody::Bytes(body.as_bytes())
    ).expect("signable request");

    // Create a request in which will be added the headers of the signature
    let mut my_req = http::Request::new("...");

    // Sign and then apply the signature to the request
    let signing_instructions ;
    match sign(signable_request, &signing_params) {
        Ok(result) => {
            signing_instructions = result.into_parts();
            signing_instructions.0.apply_to_request_http1x(&mut my_req);
        }
        Err(err) => {
            println!("Errore: {}", err)
        }
    };

    println!("Authorization header: {:?}", my_req.headers().get("Authorization"));
    println!("X-Amz-Date header: {:?}", my_req.headers().get("X-Amz-Date"));

    // Create a client to make effectively the request
    let client = reqwest::Client::new();
    let mut headers = reqwest::header::HeaderMap::new();

    // Create an headers list in which will insert all headers name, as 'static mut' cause
    // the headers.insert() needs a static variable as first element and needs it to live
    // 'long enough' so I need to catch these elements from a Vec<String> cause a String
    // exists until the end of execution of binary
    static mut HEADERS_LIST: Vec<String> = vec![];
    // Using a counter to insert elements in the right position of Vec
    let mut i = 0;
    // Unsafe is needed because I'm using a static mut variable that is unsafe in Rust
    unsafe {
        // Need to use keys() cause iter() says to me that it doesn't 'live long enough'
        // and I use its values inside insert(), so the complain is about this use of values
        for val in my_req.headers().keys() {
            println!("HeaderName {i}: {}", val.to_string());
            HEADERS_LIST.insert(i, val.to_string());
            i = i + 1;
        }
    }

    // Here the unsafe is needed cause we are using the unsafe 'static mut' variable, so Rust requires it. And I think
    // that the compiler doesn't complain about iter() as before, always because we are using unsafe variable.
    // I did all this just to make Rust populates automatically the headers without having to put them by hand
    unsafe {
        for el in HEADERS_LIST.iter() {
            if my_req.headers().get(el) != None {
                headers.insert(el.as_str(), my_req.headers().get(el.to_string()).unwrap().to_str().unwrap().parse().unwrap());
            }
        }
    }

    // Actually make the request
    return client.post(ENDPOINT)
        // .body(req_body) // this is to send the body as string
        .json(&json_body)
        .headers(headers.clone())
        .send()
        .await;
}

async fn resign_func() -> Result<Response, Error> {
    // r#...# stands for raw string that ignore special characters
    let req_body = r#"{ "data": "hello world" }"#;
    // Create json body to ensure that when I pass it as bytes or string, it will be created correctly
    let json_body = from_str::<Value>(req_body).unwrap();

    // Set up information and settings for the signing
    // You can obtain credentials from `SdkConfig`.
    let identity = Credentials::new(
        format!("{NAME}:{KID}"), // access_key_id
        format!("{SECRET_KEY}"), // secret_key
        None,
        None,
        "hardcoded-credentials"
    ).into();

    let signing_settings = SigningSettings::default();

    let signing_params = v4::SigningParams::builder()
        .identity(&identity)
        .region(REGION)
        .name(SERVICE)
        .time(SystemTime::now())
        .settings(signing_settings)
        .build()
        .unwrap()
        .into();

    // Needed this to be able to pass the body as_bytes in SignableRequest::new(). If I don't do this, the
    // compiler complains about 'temporary value dropped while borrowed' and suggest to use 'let' statement
    // to create a 'live longer' variable
    let body = json_body.to_string();

    // Convert the HTTP request into a signable request
    let signable_request = SignableRequest::new(
        METHOD,
        ENDPOINT_RESIGN,
        std::iter::empty(),
        SignableBody::Bytes(body.as_bytes())
    ).expect("signable request");

    // Create a request in which will be added the headers of the signature
    let mut my_req = http::Request::new("...");

    // Sign and then apply the signature to the request
    let signing_instructions ;
    match sign(signable_request, &signing_params) {
        Ok(result) => {
            signing_instructions = result.into_parts();
            signing_instructions.0.apply_to_request_http1x(&mut my_req);
        }
        Err(err) => {
            println!("Errore: {}", err)
        }
    };

    println!("Authorization header: {:?}", my_req.headers().get("Authorization"));
    println!("X-Amz-Date header: {:?}", my_req.headers().get("X-Amz-Date"));

    // Create a client to make effectively the request
    let client = reqwest::Client::new();
    let mut headers = reqwest::header::HeaderMap::new();

    // Create an headers list in which will insert all headers name, as 'static mut' cause
    // the headers.insert() needs a static variable as first element and needs it to live
    // 'long enough' so I need to catch these elements from a Vec<String> cause a String
    // exists until the end of execution of binary
    static mut HEADERS_LIST: Vec<String> = vec![];
    // Using a counter to insert elements in the right position of Vec
    let mut i = 0;
    // Unsafe is needed because I'm using a static mut variable that is unsafe in Rust
    unsafe {
        // Need to use keys() cause iter() says to me that it doesn't 'live long enough'
        // and I use its values inside insert(), so the complain is about this use of values
        for val in my_req.headers().keys() {
            println!("HeaderName {i}: {}", val.to_string());
            HEADERS_LIST.insert(i, val.to_string());
            i = i + 1;
        }
    }

    // Here the unsafe is needed cause we are using the unsafe 'static mut' variable, so Rust requires it. And I think
    // that the compiler doesn't complain about iter() as before, always because we are using unsafe variable.
    // I did all this just to make Rust populates automatically the headers without having to put them by hand
    unsafe {
        for el in HEADERS_LIST.iter() {
            if my_req.headers().get(el) != None {
                headers.insert(el.as_str(), my_req.headers().get(el.to_string()).unwrap().to_str().unwrap().parse().unwrap());
            }
        }
    }

    // Actually make the request
    return client.post(ENDPOINT_RESIGN)
        // .body(req_body) // this is to send the body as string
        .json(&json_body)
        .headers(headers)
        .send()
        .await;
}