from sigv4_sign import Credentials, SigV4Sign
import requests

name = "demo-python"
kid = "primary"
secret_key = "testkey"
service = "simulator"
region = "test"
method = "POST"
url = "http://localhost:8765/validate"
url_resign = "http://localhost:8765/validateAndSign"
# body needs to be a string without whitespaces to make work every server, in particular Javascript
# that with JSON.parse() of the body will remove whitespaces, so, if bodies used in signing functions
# are different between client and server, then the Signature will be different and it's a problem
body = '{"data":"hello world"}'

##################################
####### test endpoint sign #######
##################################

# config data to create aws request correctly
aws_request_config = {
    'method': method,
    'url': url,
    'data': body,
}

# create credentials
creds = Credentials(access_key=f"{name}:{kid}", secret_key=secret_key, token=None)

# sign request
signed_request = SigV4Sign().sign_request(creds, service, region, aws_request_config, False)
print(f'signed_request: {signed_request}')
print(f'signed_request body: {signed_request.body}')

# making the request to server
try:
    r = requests.post(url=url, data=body, headers=signed_request.headers)
    print(f'status_code: {r.status_code}')
    print(f'response_body: {r.content}')
except Exception as e:
    print(f"request error: {e}")

##################################
###### test endpoint resign ######
##################################
    
# config data to create aws request correctly
aws_request_config = {
    'method': method,
    'url': url_resign,
    'data': body,
}

# creds remains the same as above
signed_request = SigV4Sign().sign_request(creds, service, region, aws_request_config, False)
print(f'\nsigned_request: {signed_request}')
print(f'signed_request body: {signed_request.body}')

try:
    rs = requests.post(url=url_resign, data=body, headers=signed_request.headers)
    print(f'status_code: {rs.status_code}')
    print(f'response_body: {rs.content}')
except Exception as e:
    print(f"request error: {e}")
