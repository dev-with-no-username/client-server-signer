package com.sigv4aSigning;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.AwsCredentials;
import software.amazon.awssdk.auth.credentials.EnvironmentVariableCredentialsProvider;
import software.amazon.awssdk.authcrt.signer.internal.AwsCrt4aSigningAdapter;
import software.amazon.awssdk.authcrt.signer.internal.SdkSigningResult;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.crt.auth.credentials.Credentials;
import software.amazon.awssdk.crt.auth.signing.AwsSigningConfig;
import software.amazon.awssdk.http.SdkHttpFullRequest;
import software.amazon.awssdk.http.SdkHttpMethod;

import java.io.IOException;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.TimeZone;
import java.util.Map.Entry;

public class Server {
    private final AwsCredentials awsCredentials;
    public static final Integer PORT = 8765;
    public static final String PROTOCOL = "http";
    public static final String URL = "http://localhost:8765/validate";
    public static final String ACCESS_KEY_ID = "test:kid";
    public static final String SECRET_ACCESS_KEY = "testkey";
    public static final String SERVICE_NAME = "simulator";
    public static final String REGION = "test";

    public static void main(String[] args) throws IOException {
        int port = 8765;
        HttpServer server = HttpServer.create(new InetSocketAddress(port), 0);
        server.createContext("/validate", Server::handleRequest);
        server.setExecutor(null); // use default executor
        server.start();
        System.out.println("Server started on port " + port);
    }

    private static void handleRequest(HttpExchange exchange) throws IOException {
        try {
            if (exchange.getRequestMethod().equalsIgnoreCase("POST")) {
                // Get request body
                InputStream inputStream = exchange.getRequestBody();
                StringBuilder bodyString = new StringBuilder();
                byte[] buffer = new byte[1024]; // adjust buffer size as needed
                int bytesRead;
                while ((bytesRead = inputStream.read(buffer)) != -1) {
                    bodyString.append(new String(buffer, 0, bytesRead, StandardCharsets.UTF_8));
                }
                inputStream.close();
                String body = bodyString.toString();
                System.out.println("Request body " + body);
                
                // Get request headers
                Map<String, String> headers = new HashMap<>();
                for (Entry<String, List<String>> entry : exchange.getRequestHeaders().entrySet()) {
                    headers.put(entry.getKey(), String.join(",", entry.getValue()));
                }
                
                AwsCredentials awsCredentials = AwsBasicCredentials.create(ACCESS_KEY_ID, SECRET_ACCESS_KEY);
                Server sigV4ASign = Server.create(awsCredentials);
                URI uri = URI.create(URL);
        
                Map<String, List<String>> signedHeaders = sigV4ASign.getHeaders(
                    SERVICE_NAME, REGION, SdkHttpMethod.POST, uri, body, headers
                );
    
                if (signedHeaders.get("Authorization").get(0).equals(headers.get("Authorization"))) {
                    // Send response
                    exchange.sendResponseHeaders(200, "Request validated successfully".getBytes().length);
                    exchange.getResponseBody().write("Request validated successfully".getBytes());
                    exchange.close();    
                } else {
                    // Send response
                    exchange.sendResponseHeaders(400, "Request not validated".getBytes().length);
                    exchange.getResponseBody().write("Request not validated".getBytes());
                    exchange.close();
                }
            } else {
                exchange.sendResponseHeaders(400, "Request not validated".getBytes().length);
                exchange.getResponseBody().write("Request not validated".getBytes());
                exchange.close();
            }
        } catch (Exception e) {
            System.out.println("Exception type: " + e + " , message: " + e.getMessage());
        }
    }

    public static Server create() {
        return new Server(EnvironmentVariableCredentialsProvider.create().resolveCredentials());
    }

    public static Server create(AwsCredentials awsCredentials) {
        return new Server(awsCredentials);
    }

    private Server(AwsCredentials awsCredentials) {
        this.awsCredentials = awsCredentials;
    }

    public Map<String, List<String>> getHeaders(String serviceName,
                                                    String region,
                                                    SdkHttpMethod method,
                                                    URI url,
                                                    String body,
                                                    Map<String,String> headers) {

        SdkHttpFullRequest.Builder prepRequest = SdkHttpFullRequest.builder()
            .method(method)
            .encodedPath(url.getPath())
            .port(PORT)
            .protocol(PROTOCOL)
            .host(url.getHost())
            .contentStreamProvider(RequestBody.fromString(body).contentStreamProvider()); // body can be passed only as stream
        
        String[] signedHeaders = sanitizeHeaders(headers);
        
        for (String entry : signedHeaders) {
            System.out.println("Header to sign: " + entry);
            prepRequest.putHeader(entry, headers.get(entry));
        }

        System.out.println("Content-length header: " + prepRequest.headers().get("Content-length"));
        System.out.println("Host header: " + prepRequest.headers().get("Host"));
        System.out.println("X-amz-date header: " + prepRequest.headers().get("X-amz-date"));
        SdkHttpFullRequest request = prepRequest.build();

        // AwsSigningConfig() automatically sets these default values:
        // 
        // algorithm = AwsSigningAlgorithm.SIGV4 // symmetric
        // useDoubleUriEncode = true
        // shouldNormalizeUriPath = true
        // time = System.currentTimeMillis()
        AwsSigningConfig configuration = new AwsSigningConfig();
        byte[] accessKey = ACCESS_KEY_ID.getBytes();
        byte[] secret = SECRET_ACCESS_KEY.getBytes();
        Credentials creds = new Credentials(accessKey, secret, null);
        configuration.setCredentials(creds);
        configuration.setRegion(region);
        configuration.setService(serviceName);

        // transform 'X-amz-date' headers (for ex: '20240311T131157Z') in milliseconds
        // to set this value on configuration, that will be the 'X-Amz-Date' of the sign()
        SimpleDateFormat format = new SimpleDateFormat("yyyyMMdd'T'HHmmss'Z'");
        format.setTimeZone(TimeZone.getTimeZone("UTC"));
        try {
            Date date = format.parse(prepRequest.headers().get("X-amz-date").get(0));
            long time = date.getTime();
            configuration.setTime(time);

            // once added the value to configuration, remove the header that otherwise break the sign()
            prepRequest.removeHeader("X-amz-date");
        } catch (Exception e) {
            System.out.println("Exception type: " + e + " , message: " + e.getMessage());
        }

        AwsCrt4aSigningAdapter signingAdapter = new AwsCrt4aSigningAdapter();
        SdkSigningResult signedRequest = signingAdapter.sign(request, configuration);
        SdkHttpFullRequest preparedRequest = signedRequest.getSignedRequest();
        System.out.println("Headers " + preparedRequest.headers().toString());

        return preparedRequest.headers();
    }

    public String[] sanitizeHeaders(Map<String,String> headers) {
        // get all the elements of the Authorization header
        String[] headersList = headers.get("Authorization").split(" ");

        // get something like "SignedHeaders=content-length;host;x-amz-date,"
        String signedHeadersList = headersList[2];

        // get something like "[content-length, host, x-amz-date]"
        String[] signedHeaders = signedHeadersList.split("=")[1].split(";");

        // remove ',' from the last element so that after I can use the exact string as header
        signedHeaders[signedHeaders.length - 1] = signedHeaders[signedHeaders.length - 1].split(",")[0];

        // uppercase the first character of headers because the headers Map<> have headers name like
        // "Content-lenght", "X-amz-date", so it needs to be modified to be able to retrieve the header
        // value after the end of this sanitizeHeaders() function 
        String[] parsedHeaders = new String[signedHeaders.length];
        StringBuilder builder = new StringBuilder();
        for (int i = 0; i < signedHeaders.length; i++) {
            char[] arr = signedHeaders[i].toCharArray();
            for (int j = 0; j < arr.length; j++ ) {
                if (j == 0) {
                    builder.append(Character.toUpperCase(arr[j]));
                } else {
                    builder.append(arr[j]);
                }
            }
            parsedHeaders[i] = builder.toString();
            builder.setLength(0);
        }

        return parsedHeaders;
    }
}
