const { sigV4Sign } = require('./sigv4_sign')

let method = "POST";
let endpoint = "http://localhost:8765/validate";
let endpointResign = "http://localhost:8765/validateAndSign";
let service = "simulator";
let region = "test";
let name = "demo-javascript";
let kid = "primary";
let secretKey = "testkey";
let body = "hello world";
let reqBody = { "data": body };

// function from ./sigv4a_sign.js
let signedRequest = sigV4Sign(method, endpoint, service, region, name, kid, secretKey, reqBody);

let options = {
  method: "POST",
  headers: signedRequest.headers._flatten(),
  body: JSON.stringify(reqBody)
}

fetch(endpoint, options)
  .then((response) => {
    if (response.status === 200) {
      console.debug("Response status code:", response.status)
    } else {
      console.debug("Something went wrong on API server. Status code:", response.status);
    }
    // this line below sends the response to the next .then() allowing to read its body
    return response.text()
  })
  .then((body) => {
    console.debug("Response body:", body)
    return body
  })
  .catch((error) => {
    console.error(error);
  });

// test endpoint resign
signedRequest = sigV4Sign(method, endpointResign, service, region, name, kid, secretKey, reqBody);

options = {
  method: "POST",
  headers: signedRequest.headers._flatten(),
  body: JSON.stringify(reqBody)
}

fetch(endpointResign, options)
  .then((response) => {
    if (response.status === 200) {
      console.debug("Response status code:", response.status)
    } else {
      console.debug("Something went wrong on API server. Status code:", response.status);
    }
    // this line below sends the response to the next .then() allowing to read its body
    return response.text()
  })
  .then((body) => {
    console.debug("Response body:", body)
    return body
  })
  .catch((error) => {
    console.error(error);
  });