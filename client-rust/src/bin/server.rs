use std::{collections::HashMap, time::SystemTime};
use regex::Regex;
use actix_web::{post, App, HttpRequest, HttpResponse, HttpServer, Responder};
use aws_credential_types::Credentials;
use aws_sigv4::{http_request::{sign, SignableBody, SignableRequest, SigningSettings}, sign::v4};
use time::{error, format_description, OffsetDateTime, PrimitiveDateTime};

fn sanitize_headers(auth_header: &str) -> Vec<&str> {
    // Get something like "SignedHeaders=content-length;host;x-amz-date,"
    // '.*' gets all kinds of char and for every repetition; \s is whitespace
    let re = Regex::new(r".*\sSignedHeaders.*\s").unwrap();
    let headers_list = re.captures(&auth_header).unwrap().get(0).unwrap().as_str();

    // Get something like "content-length;host;x-amz-date,"
    let parsed_headers = headers_list.split("=").last().unwrap();
    
    // Get something like "[content-length, host, x-amz-date,]"
    let mut signed_headers = parsed_headers.split(";").collect::<Vec<_>>();

    // I need to set the signed_headers len to a variable because I using the len() method to refer to its
    // last element and so I'm using that variable as immutable even if I'm using it as mutable in the same
    // operation and this is not allowed in Rust due to memory security
    let len = signed_headers.len();
    // Remove ',' from the last element so that after I can use the exact string as header; here I use
    // .next() to get the first element of the split, cause I'm splitting "x-amz-date," for example
    signed_headers[len-1] = signed_headers[signed_headers.len()-1].split(",").next().unwrap();

    println!("SignedHeaders sanitized: {:?}", signed_headers);
    signed_headers
}

// Parses `YYYYMMDD'T'HHMMSS'Z'` formatted dates into a `SystemTime`.
fn parse_date_time(data: &str) -> Result<SystemTime, error::Parse> {
    const DATE_TIME_FORMAT: &str = "[year][month][day]T[hour][minute][second]Z";
    let date_time = PrimitiveDateTime::parse(
        data,
        &format_description::parse(DATE_TIME_FORMAT).unwrap(),
    );

    let mut dt = OffsetDateTime::now_utc();
    match date_time {
        Ok(value) => {
            dt = value.assume_utc();
        }
        Err(error) => {
            println!("Error parsing datetime: {error}");
        }
    }
    Ok(dt.into())
}

#[post("/validate")]
async fn validate(req_body: String, req: HttpRequest) -> impl Responder {
    println!("Request body received: {}", req_body);

    // Variables
    let method = "POST";
    let endpoint = "http://localhost:8765/validate";
    let service = "simulator";
    let region = "test";
    let name = "test";
    let kid = "kid";
    let secret_key = "testkey";

    // Set up information and settings for the signing
    // You can obtain credentials from `SdkConfig`.
    let identity = Credentials::new(
        format!("{name}:{kid}"), // access_key_id
        format!("{secret_key}"), // secret_key
        None,
        None,
        "hardcoded-credentials"
    ).into();

    // Sanitize headers to get 'SignedHeaders' that needs to be inserted in the sign function to validate purpose
    let headers_list = sanitize_headers(req.headers().get("Authorization").unwrap().to_str().unwrap());

    // Create a map of headers that needs to be inserted in the signature after
    let mut headers_map = HashMap::<&str, &str>::new();
    for (name, val) in req.headers() {
        for el in &headers_list {
            if *el == name.to_string() {
                headers_map.insert(name.as_str(), val.to_str().unwrap());
            }
        }
    }

    // get the value of 'X-Amz-Date' header and parse it to SystemTime cause this is the type needed
    // by the .time() of builder below. With the .remove() method we get the header value and right
    // after it removes the header from the HashMap, so we get two things at once
    let time = parse_date_time(headers_map.remove(&"x-amz-date").unwrap());

    let signing_settings = SigningSettings::default();

    let signing_params = v4::SigningParams::builder()
        .identity(&identity)
        .region(region)
        .name(service)
        .time(time.unwrap())
        .settings(signing_settings)
        .build()
        .unwrap()
        .into();

    // Convert the HTTP request into a signable request
    let signable_request = SignableRequest::new(
        method,
        endpoint,
        headers_map.into_iter(),
        SignableBody::Bytes(req_body.as_bytes())
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

    if req.headers().get("Authorization").unwrap().as_bytes() == my_req.headers().get("Authorization").unwrap().as_bytes() {
        HttpResponse::Ok().body("Request validated successfully")
    } else {
        println!(
            "Authorization of incoming request is: {}",
            req.headers().get("Authorization").unwrap().to_str().unwrap()
        );
        HttpResponse::BadRequest().body("Request not validated")
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    println!("Server listening on port: 8765");

    HttpServer::new(|| {
        App::new()
            .service(validate)
    })
    .bind(("127.0.0.1", 8765))?
    .run()
    .await
}