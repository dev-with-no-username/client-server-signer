from fastapi import FastAPI, HTTPException, Request
from sigv4_sign import Credentials, SigV4Sign
 
name = "test"
service = "simulator"
region = "test"
method = "POST"
url = "http://localhost:8765/validate"
kid = "kid"
secret_key = "testkey"

app = FastAPI()

@app.get("/")
def read_root():
    return {"Hello": "World"}

@app.post("/validate")
async def validate_request(request: Request):
    print("request headers: ", request.headers, "\n")
    raw_body = await request.body()
    print("request body:", raw_body, "\n")
    
    # get all the headers of incoming request to ensure that them will be added to the request 
    # that will be signs for checking purpose
    headers_to_add = sanitize_headers(request.headers.get("Authorization"))

    # create credentials
    creds = Credentials(access_key=f"{name}:{kid}", secret_key=secret_key, token=None)

    # prepare the headers dict to be passed to the sign function
    headers = {}
    for el in headers_to_add:
        headers[el] = request.headers.get(el)

    # config data to create aws request correctly
    aws_request_config = {
        'method': method,
        'url': url,
        'data': raw_body if raw_body else None,
        'headers': headers
    }

    # sign request
    signed_request = SigV4Sign().sign_request(creds, service, region, aws_request_config, False)
    print(f'signed_request: {signed_request}', "\n")
    print(f'signed_request body: {signed_request.body}', "\n")

    signed_request_auth = signed_request.headers.get("Authorization")
    request_auth = request.headers.get("authorization")
    print(f'Authorization of incoming request: {request_auth}', "\n")
    print(f'Authorization of signed request: {signed_request_auth}', "\n")

    if signed_request_auth.split("Signature=")[1] == request_auth.split("Signature=")[1]:
        return HTTPException(status_code=200, detail="Request validated successfully")

    raise HTTPException(status_code=400, detail="Request not validated")

def sanitize_headers(auth_header):
    # get all the elements of the Authorization header
    headers_list = auth_header.split(" ")

    # get something like "SignedHeaders=content-length;host;x-amz-date,"
    signed_headers_list = headers_list[2]

    # get something like "[content-length, host, x-amz-date]"
    signed_headers = signed_headers_list.split("=")[1].split(";")

    # remove ',' from the last element so that after I can use the exact string as header
    signed_headers[-1] = signed_headers[-1].split(",")[0]
    
    print("headers to be signed ", signed_headers, "\n")
    return signed_headers