package com.sigv4aSigning;

import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.util.EntityUtils;
import org.json.JSONObject;
import software.amazon.awssdk.auth.credentials.*;
import software.amazon.awssdk.authcrt.signer.AwsCrtS3V4aSigner;
import software.amazon.awssdk.authcrt.signer.internal.AwsCrt4aSigningAdapter;
import software.amazon.awssdk.authcrt.signer.internal.SdkSigningResult;
import software.amazon.awssdk.core.interceptor.ExecutionAttributes;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.crt.auth.credentials.Credentials;
import software.amazon.awssdk.crt.auth.signing.AwsSigningConfig;
import software.amazon.awssdk.http.SdkHttpFullRequest;
import software.amazon.awssdk.http.SdkHttpMethod;
import software.amazon.awssdk.regions.RegionScope;

import java.io.IOException;
import java.net.*;
import java.util.List;
import java.util.Map;

public class SigV4Sign {

    private final AwsCredentials awsCredentials;
    public static final Integer HTTPS_PORT = 443;
    public static final Integer HTTP_PORT = 8765;
    public static final String PROTOCOL_HTTPS = "https";
    public static final String PROTOCOL_HTTP = "http";
    public static final String url = "http://localhost:8765/validate";
    public static final String urlResign = "http://localhost:8765/validateAndSign";
    public static final String accessKeyId = "demo-java:primary";
    public static final String secretAccessKey = "testkey";
    public static final String serviceName = "simulator";
    public static final String region = "test";
    public static final JSONObject body = new JSONObject();

    public static void main(String[] args) {
        try {
            AwsCredentials awsCredentials = AwsBasicCredentials.create(accessKeyId, secretAccessKey);
            SigV4Sign sigV4ASign = SigV4Sign.create(awsCredentials);
            URI uri = URI.create(url);

            // I need to create a JSON insted of a String, because some servers, like Javascript, when parse
            // the body, delete whitespaces, so it results in a different Signature. Creating a JSON and then
            // pass it as a String, it's ok because the toString() method will parse correctly removing whitespaces 
            body.put("data", "hello world");

            Map<String, List<String>> headers = sigV4ASign.getHeaders(serviceName, region, SdkHttpMethod.POST, uri);

            HttpClient client = HttpClientBuilder.create().build();
            HttpPost post = new HttpPost(url);

            for (Map.Entry<String, List<String>> entry : headers.entrySet()) {
                for (String value : entry.getValue()) {
                    post.setHeader(entry.getKey(), value);
                }
            }

            StringEntity entity = new StringEntity(body.toString());
            post.setEntity(entity);

            HttpResponse response = client.execute(post);

            int statusCode = response.getStatusLine().getStatusCode();
            System.out.println("Response status code: " + statusCode);

            String responseString = EntityUtils.toString(response.getEntity(), "UTF-8");
            System.out.println("Response body: " + responseString);

            ////////////////////////////
            /////// test resign ///////
            //////////////////////////
            uri = URI.create(urlResign);
            headers = sigV4ASign.getHeaders(serviceName, region, SdkHttpMethod.POST, uri);

            client = HttpClientBuilder.create().build();
            post = new HttpPost(urlResign);

            for (Map.Entry<String, List<String>> entry : headers.entrySet()) {
                for (String value : entry.getValue()) {
                    post.setHeader(entry.getKey(), value);
                }
            }

            entity = new StringEntity(body.toString());
            post.setEntity(entity);

            response = client.execute(post);

            statusCode = response.getStatusLine().getStatusCode();
            System.out.println("Response status code: " + statusCode);

            responseString = EntityUtils.toString(response.getEntity(), "UTF-8");
            System.out.println("Response body: " + responseString);
        } catch (IOException e) {
            System.out.println("Exception type: " + e + " , message: " + e.getMessage());
        }
    }


    public static SigV4Sign create() {
        return new SigV4Sign(EnvironmentVariableCredentialsProvider.create().resolveCredentials());
    }

    public static SigV4Sign create(AwsCredentials awsCredentials) {
        return new SigV4Sign(awsCredentials);
    }

    private SigV4Sign(AwsCredentials awsCredentials) {
        this.awsCredentials = awsCredentials;
    }

    public Map<String, List<String>> getHeaders(String serviceName,
                                                     String region,
                                                     SdkHttpMethod method,
                                                     URI url) {

        SdkHttpFullRequest request = SdkHttpFullRequest.builder()
            .method(method)
            .encodedPath(url.getPath())
            .port(HTTP_PORT)
            .protocol(PROTOCOL_HTTP)
            .host(url.getHost())
            .contentStreamProvider(RequestBody.fromString(body.toString()).contentStreamProvider()) // body can be passed only as stream
            // .putHeader("Content-Length", "48") // this line breaks the request to the server, so it can't be added before sign
            .build();
        
        // AwsSigningConfig() automatically sets these default values:
        // 
        // algorithm = AwsSigningAlgorithm.SIGV4 // symmetric
        // useDoubleUriEncode = true
        // shouldNormalizeUriPath = true
        // time = System.currentTimeMillis()
        AwsSigningConfig configuration = new AwsSigningConfig();
        byte[] accessKey = accessKeyId.getBytes();
        byte[] secret = secretAccessKey.getBytes();
        Credentials creds = new Credentials(accessKey, secret, null);
        configuration.setCredentials(creds);
        configuration.setRegion(region);
        configuration.setService(serviceName);

        AwsCrt4aSigningAdapter signingAdapter = new AwsCrt4aSigningAdapter();
        SdkSigningResult signedRequest = signingAdapter.sign(request, configuration);
        SdkHttpFullRequest preparedRequest = signedRequest.getSignedRequest();
        System.out.println("Headers " + preparedRequest.headers().toString());

        return preparedRequest.headers();
    }

    public Map<String, List<String>> getHeadersResign(String serviceName,
                                                     String region,
                                                     SdkHttpMethod method,
                                                     URI url) {

        SdkHttpFullRequest request = SdkHttpFullRequest.builder()
            .method(method)
            .encodedPath(url.getPath())
            .port(HTTP_PORT)
            .protocol(PROTOCOL_HTTP)
            .host(url.getHost())
            .contentStreamProvider(RequestBody.fromString(body.toString()).contentStreamProvider()) // body can be passed only as stream
            // .putHeader("Content-Length", "48") // this line breaks the request to the server, so it can't be added before sign
            .build();
        
        // AwsSigningConfig() automatically sets these default values:
        // 
        // algorithm = AwsSigningAlgorithm.SIGV4 // symmetric
        // useDoubleUriEncode = true
        // shouldNormalizeUriPath = true
        // time = System.currentTimeMillis()
        AwsSigningConfig configuration = new AwsSigningConfig();
        byte[] accessKey = accessKeyId.getBytes();
        byte[] secret = secretAccessKey.getBytes();
        Credentials creds = new Credentials(accessKey, secret, null);
        configuration.setCredentials(creds);
        configuration.setRegion(region);
        configuration.setService(serviceName);

        AwsCrt4aSigningAdapter signingAdapter = new AwsCrt4aSigningAdapter();
        SdkSigningResult signedRequest = signingAdapter.sign(request, configuration);
        SdkHttpFullRequest preparedRequest = signedRequest.getSignedRequest();
        System.out.println("Headers " + preparedRequest.headers().toString());

        return preparedRequest.headers();
    }

    public Map<String, List<String>> getHeadersBasic(SdkHttpFullRequest request,
                                                ExecutionAttributes ea,
                                                RegionScope regionScope) {

        AwsCrtS3V4aSigner signer = AwsCrtS3V4aSigner.builder()
                .defaultRegionScope(regionScope)
                .build();

        return signer.sign(request, ea)
                .headers();
    }

    public AwsCredentials getAwsCredentials() {
        return awsCredentials;
    }
}
