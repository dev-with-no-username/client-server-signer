const crt = require("aws-crt");
const { HttpRequest } = require("aws-crt/dist/native/http");
const crypto = require('crypto');

function sigV4Sign(method, endpoint, service, region, name, kid, secretKey, body) {
  const host = new URL(endpoint).host;
  const accessKey = name + ":" + kid

  const request = new HttpRequest(method, endpoint);
  request.headers.add('host', host);

  const config = {
    service: service,
    region: region,
    algorithm: crt.auth.AwsSigningAlgorithm.SigV4,
    signature_type: crt.auth.AwsSignatureType.HttpRequestViaHeaders,
    // below is the hash of the body that allows us to pass it to the request correctly. There is no other way to pass
    // it clearly and make the library do the job. The Readable object that existed before, didn't work
    signed_body_value: crypto.createHash("sha256").update(JSON.stringify(body)).digest("hex"),
    provider: crt.auth.AwsCredentialsProvider.newStatic(accessKey, secretKey),
    use_double_uri_encode: true,
    should_normalize_uri_path: true,
  };

  crt.auth.aws_sign_request(request, config)
  console.debug("Authorization header: ", request.headers.get("Authorization"))
  console.debug("X-Amz-Date header: ", request.headers.get("X-Amz-Date"))
  return request;
}

function validate(method, endpoint, service, region, name, kid, secretKey, body, reqHeaders, signedHeaders) {
  const accessKey = name + ":" + kid

  const request = new HttpRequest(method, endpoint);

  for (let header of signedHeaders) {
    if (header != "x-amz-date") {
      request.headers.add(header, reqHeaders[header])
    }
  }

  const config = {
    service: service,
    region: region,
    algorithm: crt.auth.AwsSigningAlgorithm.SigV4,
    signature_type: crt.auth.AwsSignatureType.HttpRequestViaHeaders,
    // below is the hash of the body that allows us to pass it to the request correctly. There is no other way to pass
    // it clearly and make the library do the job. The Readable object that existed before, didn't work.
    signed_body_value: crypto.createHash("sha256").update(JSON.stringify(body)).digest("hex"),
    provider: crt.auth.AwsCredentialsProvider.newStatic(accessKey, secretKey),
    use_double_uri_encode: true,
    should_normalize_uri_path: true,
    date: reqHeaders["x-amz-date"]
  };

  crt.auth.aws_sign_request(request, config)
  console.debug("Authorization header: ", request.headers.get("Authorization"))
  console.debug("X-Amz-Date header: ", request.headers.get("X-Amz-Date"))
  return request;
}

module.exports = {
    sigV4Sign,
    validate
}