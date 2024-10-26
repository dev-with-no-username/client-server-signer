import boto3
from botocore import crt, awsrequest

class SigV4Sign:

    def __init__(self, boto3_session=boto3.Session()):
        self.session = boto3_session
    
    def sign_request(self, creds, service, region, aws_request_config, double_sign):
        # create signer struct with credentials, service, region info, that will be used to sign the request
        sigV4A = crt.auth.CrtSigV4Auth(creds, service, region)
        # create an AWSRequest with some configuration info needed by the signer
        request = awsrequest.AWSRequest(**aws_request_config)
        # create the Signature and add 'Authorization' header
        sigV4A.add_auth(request)
        # add headers needed by default (if not presents), but it doesn't sign them so I need to add them in another request below
        prepped = request.prepare()
        # create another AWSRequest to make sure that all needed headers are considered during the creation of Signature and the
        # add of 'Authorization' header
        signed_request = awsrequest.AWSRequest(method=prepped.method, url=prepped.url, data=prepped.body, headers=prepped.headers)
        # add 'Authorization' header that contains all needed headers in its calculus
        sigV4A.add_auth(signed_request)
        # redo the prepare() method to allow return a parsed request to easily read when printed out
        parsed_signed_request = signed_request.prepare()

        if double_sign == True:
            return parsed_signed_request
        else:
            return prepped 
    
class Credentials:

    def __init__(self, access_key, secret_key, token):
        self.access_key = access_key
        self.secret_key = secret_key
        self.token = token