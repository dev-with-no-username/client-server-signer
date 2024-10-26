package main

import (
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
)

type Secret struct {
	Name          string   `json:"name"`
	ResolvedName  string   `json:"resolved_name"`
	Value         []byte   `json:"-"`
	Encrypted     bool     `json:"encrypted"`
	Base64Encoded bool     `json:"base64encoded"`
	Split         bool     `json:"split"`
	Parts         []string `json:"parts"`
}

type SecretKey struct {
	Kid string
	Key Secret
}

type Issuer struct {
	Name    string
	Enabled bool
	Timeout time.Duration
	Keys    []SecretKey
}

type Client struct {
	Name          string
	Service       string
	Region        string
	Key           SecretKey
	HeadersToSign []string
}

type Config struct {
	Issuers []Issuer
	Client  Client
}

type Provider struct {
	Client         Client
	IssuersKeys    map[string]string
	IssuersTimeout map[string]time.Duration
}

type ProviderOption func(*Provider)

/*
Sets Client for Provider
*/
func WithClient(c Client) ProviderOption {
	return func(p *Provider) {
		p.Client = c
	}
}

/*
Sets Issuers for Provider
*/
func WithIssuers(issuers []Issuer) ProviderOption {
	return func(p *Provider) {
		keys := map[string]string{}
		timeouts := map[string]time.Duration{}
		for _, iss := range issuers {
			if !iss.Enabled {
				continue
			}

			if iss.Timeout != 0 {
				timeouts[iss.Name] = iss.Timeout
			}
			for _, k := range iss.Keys {
				key := fmt.Sprintf("%s:%s", iss.Name, k.Kid)
				keys[key] = string(k.Key.Value)
			}
		}

		p.IssuersKeys = keys
		p.IssuersTimeout = timeouts
	}
}

/*
Creates Provider with ProviderOption
*/
func NewProvider(opts ...ProviderOption) *Provider {
	provider := &Provider{}

	for _, o := range opts {
		o(provider)
	}

	return provider
}

/*
Returns issuer credentials if found
*/
func (pr *Provider) GetIssuerCredential(key string) (aws.Credentials, error) {
	value, found := pr.IssuersKeys[key]

	if !found {
		return aws.Credentials{}, fmt.Errorf("issuer:kid not found %s ", key)
	}

	return aws.Credentials{
		AccessKeyID:     key,
		SecretAccessKey: value,
	}, nil
}

/*
Returns client credentials
*/
func (pr *Provider) GetClientCredential() (aws.Credentials, error) {
	return aws.Credentials{
		AccessKeyID:     fmt.Sprintf("%s:%s", pr.Client.Name, pr.Client.Key.Kid),
		SecretAccessKey: string(pr.Client.Key.Key.Value),
	}, nil
}

/*
Returns provider's client
*/
func (pr *Provider) GetClient() Client {
	return pr.Client
}

/*
Formats headers to sign, if defined, in a string with ";" as separator

Like this: headerToSign1;headerToSign2;headerToSign3;...headerToSignN
*/
func (pr *Provider) formatHeadersToSign() string {
	formattedHeadersToSign := ""
	if len(pr.Client.HeadersToSign) <= 0 {
		return ""
	}
	formattedHeadersToSign = strings.ToLower(pr.Client.HeadersToSign[0])
	for _, header := range pr.Client.HeadersToSign[1:] {
		formattedHeadersToSign = fmt.Sprintf("%s;%s", formattedHeadersToSign, strings.ToLower(header))
	}
	return formattedHeadersToSign
}
