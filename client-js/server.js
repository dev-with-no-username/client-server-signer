const http = require('http');
const { validate } = require('./sigv4_sign')

let method = "POST";
let endpoint = "http://localhost:8765/validate";
let service = "simulator";
let region = "test";
let name = "test";
let kid = "kid";
let secretKey = "testkey";

const server = http.createServer((req, res) => {
  if (req.method === 'POST' && req.url === '/validate') {
    // Read headers
    const headers = req.headers;
    const authHeader = headers["authorization"]
    const signedHeaders = sanitizeHeaders(authHeader)

    let body = ''; // Store the received data chunks

    req.on('data', (chunk) => {
      body += chunk.toString(); // Append each chunk to the body string
    });

    req.on('end', () => {
        console.log("Request body:", body)
        // Here I have to parse the body to a json first, cause the body is received as a string and if I don't
        // parse it, then the Signature obtained will be different from that of incoming request.
        const data = JSON.parse(body)
        let signedRequest = validate(method, endpoint, service, region, name, kid, secretKey, data, headers, signedHeaders);
    
        if (signedRequest.headers.get("authorization") == authHeader) {
            res.writeHead(200);
            res.end('Validation completed');
        } else {
          res.writeHead(400);
          res.end('Request not validated');
        }
    });

  } else {
    // Handle other requests (optional)
    res.writeHead(404);
    res.end('Not Found');
  }
});

function sanitizeHeaders(authHeader) {
    // get all the elements of the Authorization header
    headersList = authHeader.split(" ")

    // get something like "SignedHeaders=content-length;host;x-amz-date,"
    signedHeadersList = headersList[2]

    // get something like "[content-length, host, x-amz-date]"
    signedHeaders = signedHeadersList.split("=")[1].split(";")

    // remove ',' from the last element so that after I can use the exact string as header
    signedHeaders[signedHeaders.length - 1] = signedHeaders[signedHeaders.length - 1].split(",")[0]
    
    console.debug("headers to be signed ", signedHeaders)
    return signedHeaders
}

server.listen(8765, () => {
  console.log('Server listening on port 8765');
});