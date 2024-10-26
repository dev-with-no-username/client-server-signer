package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/rs/zerolog/log"
)

const (
	SignHeader                = "Authorization"
	SignDateHeader            = "X-Amz-Date"
	TimeFormatISO8601DateTime = "20060102T150405Z"
)

type SignatureDetails struct {
	Algorithm     string
	Service       string
	Region        string
	Signature     string
	SignedHeaders string
	Date          string
	IssuerName    string
	Credential    aws.Credentials
}

type SignContext struct {
	Req                  *http.Request
	Body                 string
	SigTime              time.Time
	AuthenticationHeader string
	SignatureDetails     SignatureDetails
}

type ContextSignedHeadersKey struct {
	Key string
}

var (
	signeHeadersKeyIntoContext = ContextSignedHeadersKey{Key: "signedHeaders"}
)

/*
Parses AWS Signature Header and returns SignatureHeader struct

# AWS Signature Header Example

AWS4-HMAC-SHA256 Credential=test:kid/20230822/test/simulator/aws4_request, SignedHeaders=host;x-amz-date;x-expected-status, Signature=8e07ac95528526abd3ca9d03be997b436b540f7c450d1202871d2665b5970de4
*/
func (pr *Provider) parseSignatureHeaders(auth string) (SignatureDetails, error) {
	const credential = "Credential"
	const signedHeaders = "SignedHeaders"
	const signature = "Signature"

	sigParse := SignatureDetails{}

	// Divides input string in an array of substrings (based on a function that, for each character in the string, returns true if character is a separator)
	parts := strings.FieldsFunc(auth, func(r rune) bool {
		return r == ' ' || r == '=' || r == ','
	})

	// Checks if is an AWS Signature Header
	if len(parts) != 7 {
		return sigParse, fmt.Errorf("invalid authentication header format")
	}

	data := make(map[string]string)

	// Iterates parts (array of substrings) and creates data map
	for i := 1; i < len(parts)-1; i += 2 {
		key := parts[i]
		value := parts[i+1]
		data[key] = value
	}

	// Sets SignatureHeader -> Algorithm
	sigParse.Algorithm = parts[0]

	// Parses "Credential" field
	credsElm := strings.Split(data[credential], "/")

	// Gets issuer credential
	creds, err := pr.GetIssuerCredential(credsElm[0])

	if err != nil {
		return sigParse, err
	}

	// Sets SignatureHeader -> Credential
	sigParse.Credential = creds
	sigParse.IssuerName = strings.Split(creds.AccessKeyID, ":")[0]

	// Sets SignatureHeader -> Date, Region, Service
	sigParse.Date = credsElm[1]
	sigParse.Region = credsElm[2]
	sigParse.Service = credsElm[3]

	// Sets SignatureHeader -> SignedHeaders if not empty
	if data[signedHeaders] == "" {
		return sigParse, fmt.Errorf("empty Signedheaders in Authorization header")
	}
	sigParse.SignedHeaders = data[signedHeaders]

	// Sets SignatureHeader -> Signature if not empty
	if data[signature] == "" {
		return sigParse, fmt.Errorf("empty Signature in Authorization header")
	}
	sigParse.Signature = data[signature]

	return sigParse, nil
}

/*
Returns an array of signedHeaders found in AWS Signature Header
*/
func (pr *Provider) GetSignedHeaders(auth string) ([]string, error) {
	signatureHeader, err := pr.parseSignatureHeaders(auth)

	if err != nil {
		return nil, err
	}

	return strings.Split(signatureHeader.SignedHeaders, ";"), nil
}

/*
Builds and returns Sign Context. It will be use for validation request func
*/
func (pr *Provider) buildSignContext(req *http.Request) (SignContext, error) {
	// Sets SignContext -> Req
	sigCtx := SignContext{
		Req: req,
	}

	// Calculates hash request body (if is not empty) and sets SignContext -> Body
	emptyBody := true
	if req.ContentLength > 0 {
		emptyBody = false
		log.Trace().Int64("Body lenght", req.ContentLength).Msg("buildSigContext:: hashing body request")
		buf, err := io.ReadAll(req.Body)
		if err != nil {
			return sigCtx, err
		}

		req.Body = io.NopCloser(bytes.NewBuffer(buf))
		bodyB := sha256.Sum256(buf)
		sigCtx.Body = fmt.Sprintf("%x", bodyB)
	}

	// Log warning for empty body request
	if emptyBody {
		log.Warn().Int64("Body length", req.ContentLength).Msg("buildSigContext:: warning for request body content length (unkonw or empty body)")
	}

	// Gets signature time (X-Amz-Date), parses it and, if valid, sets SignContext -> SigTime
	sigTime := req.Header.Get(SignDateHeader)
	parsedSigTime, err := time.Parse(TimeFormatISO8601DateTime, sigTime)
	if err != nil {
		return sigCtx, err
	}
	sigCtx.SigTime = parsedSigTime

	// Gets authorization header (Authorization) and, if found, sets SignContext -> SignatureHeader
	auth := req.Header.Get(SignHeader)
	if auth == "" {
		return sigCtx, errors.New("error: Authorization header not found")
	}
	sigCtx.AuthenticationHeader = auth

	// Parses AWS signature header and, if valid, sets SignContext -> SignatureDetails
	parsedHeaders, err := pr.parseSignatureHeaders(auth)
	if err != nil {
		return sigCtx, err
	}
	sigCtx.SignatureDetails = parsedHeaders

	return sigCtx, nil
}

/*
Sanitizes request headers deleting headers that are not present in safeHeaders string

Returns a map of deleted headers
*/
func (pr *Provider) sanitizeHeaders(req *http.Request, safeHeaders string) map[string][]string {
	deletedheader := make(map[string][]string)
	for headerName := range req.Header {
		if !strings.Contains(strings.ToLower(safeHeaders), fmt.Sprintf("%s;", strings.ToLower(headerName))) {
			deletedheader[headerName] = append(deletedheader[headerName], req.Header.Get(headerName))
			req.Header.Del(headerName)

			// due to the fact that Go have a Request struct that has some headers both in the 'Header' field
			// and in the specific field, such as 'ContentLength', we have to void both fields to ensure that
			// sigv4 library doesn't add it later (because it does this)
			if strings.ToLower(headerName) == "content-length" {
				req.ContentLength = 0
			}
		}
	}
	return deletedheader
}

/*
Signs input http request
*/
func (pr *Provider) Sign(req *http.Request) error {
	// Gets a clone of input http request with its context
	reqClone := req.Clone(req.Context())

	// Gets AWS Signer
	signer := v4.NewSigner()

	var bodyHash string

	// Calculates hash request body (if is not empty)
	if req.ContentLength > 0 {
		log.Trace().Int64("Body lenght", req.ContentLength).Msg("Sign:: hashing body request")
		buf, err := io.ReadAll(req.Body)
		if err != nil {
			return err
		}

		req.Body = io.NopCloser(bytes.NewBuffer(buf))
		bodyB := sha256.Sum256(buf)
		bodyHash = fmt.Sprintf("%x", bodyB)
	}

	// Log trace for empty body request
	if len(bodyHash) == 0 {
		log.Trace().Int64("Body lenght", req.ContentLength).Msg("Sign:: warning for request body content length (unkonw or empty body)")
	}

	// Gets client credentials
	creds, err := pr.GetClientCredential()
	if err != nil {
		return err
	}

	// Gets safeHeaders string. It will be use for sanitize request header
	safeHeaders := pr.formatHeadersToSign()

	// Gets signed headers string from request clone context (added by validate func) and, if not empty, adds last ";" saparator character to allow parsing of all headers in sanitizeHeaders()
	if signHeaders := reqClone.Context().Value(signeHeadersKeyIntoContext); signHeaders != "" {
		safeHeaders = fmt.Sprintf("%s;%s;", safeHeaders, signHeaders)
	}

	// Sanitizes request clone headers
	pr.sanitizeHeaders(reqClone, safeHeaders)

	// Signs request clone
	err = signer.SignHTTP(context.Background(), creds, reqClone, bodyHash, pr.Client.Service, pr.Client.Region, time.Now())
	if err != nil {
		return err
	}

	// Gets "Authorization" and "X-Amz-Date" headers, added by AWS Signer, from request clone
	signature := reqClone.Header.Get(SignHeader)
	sigTime := reqClone.Header.Get(SignDateHeader)

	// Sets "Authorization" and "X-Amz-Date" headers to original request header
	req.Header.Set(SignHeader, signature)
	req.Header.Set(SignDateHeader, sigTime)

	// Sets clone request host to original request host. It could be the same or not, depends on using proxies by client to reach server
	req.Host = reqClone.Host

	return nil
}

/*
Validates input http request
*/
func (pr *Provider) Validate(req *http.Request) (bool, *http.Request, error) {
	// Gets a clone of input http request with its context
	reqClone := req.Clone(req.Context())

	// Builds sign context from original request
	signCtx, err := pr.buildSignContext(req)
	if err != nil {
		return false, req, err
	}

	issTimeout := pr.IssuersTimeout[signCtx.SignatureDetails.IssuerName]

	// Check signature expiration
	notBefore := time.Now().Add(-issTimeout)

	if signCtx.SigTime.Before(notBefore) && issTimeout > 0 {
		return false, req, nil
	}

	// Adds last ";" saparator character to allow parsing of all signed headers and sanitizes request clone signed headers
	pr.sanitizeHeaders(reqClone, fmt.Sprintf("%s;", signCtx.SignatureDetails.SignedHeaders))

	// Gets AWS Signer
	signer := v4.NewSigner()

	// Signs request clone using sign context from original request
	err = signer.SignHTTP(context.Background(), signCtx.SignatureDetails.Credential, reqClone, signCtx.Body, signCtx.SignatureDetails.Service, signCtx.SignatureDetails.Region, signCtx.SigTime)
	if err != nil {
		return false, req, err
	}

	// Compares "Authorization" headers (one from original request and one from request clone)
	if reqClone.Header.Get(SignHeader) != signCtx.AuthenticationHeader {

		fwhost := req.Header.Get("X-Forwarded-Host")

		// Try to use 'X-Forwarded-Host' instead of 'Host' if is not empty
		if fwhost != "" {
			validWithForwardedHost, err := validateWithForwardedHost(reqClone, signer, signCtx, fwhost)
			if err != nil {
				return false, req, err
			}
			if !validWithForwardedHost {
				log.Error().Msgf("DIFFERENT HEADERS: before %v, after %v", signCtx.AuthenticationHeader, reqClone.Header.Get("Authorization"))
				return false, req, nil
			}
		} else {
			return false, req, err
		}

	}

	// Creates a new request with context that contains "signedHeaders" string validated
	ctx := context.WithValue(req.Context(), signeHeadersKeyIntoContext, signCtx.SignatureDetails.SignedHeaders)
	newReq := req.WithContext(ctx)

	return true, newReq, nil
}

// changeHost tries to use 'X-Forwarded-Host', instead of 'Host', to execute the validation
func validateWithForwardedHost(reqClone *http.Request, signer *v4.Signer, signCtx SignContext, forwardedHost string) (bool, error) {

	reqClone.Host = forwardedHost
	err := signer.SignHTTP(context.Background(), signCtx.SignatureDetails.Credential, reqClone, signCtx.Body, signCtx.SignatureDetails.Service, signCtx.SignatureDetails.Region, signCtx.SigTime)
	if err != nil {
		log.Error().Err(err).Msg("Trying to use X-Forwarded-Host as Host")
		return false, err
	}

	// execute the validation
	if reqClone.Header.Get(SignHeader) == signCtx.AuthenticationHeader {
		return true, nil
	}

	return false, nil
}
