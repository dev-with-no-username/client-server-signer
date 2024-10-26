package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"
)

func main() {
	// Create a new Gin router
	router := gin.Default()

	// Route for POST requests to "/messages"
	router.POST("/validate", func(c *gin.Context) {
		validated, req, err := validateRequest(c.Request)
		if err != nil {
			log.Error().Err(err)
			return
		}

		log.Debug().Msgf("request headers %s", req.Header)

		body, err := io.ReadAll(req.Body)
		if err != nil {
			log.Error().Err(err)
			return
		}
		log.Debug().Msgf("request body %s", body)

		if !validated {
			log.Debug().Msgf("request valid: %v", validated)
			c.JSON(http.StatusBadRequest, gin.H{"Message": "Request not valid"})
			return
		}

		// Respond with success message
		c.JSON(http.StatusOK, gin.H{"Message": "Request validated successfully"})
	})

	// Route for POST requests to "/validateAndSign"
	router.POST("/validateAndSign", func(c *gin.Context) {
		validated, req, err := validateAndSignRequest(c.Request)
		if err != nil {
			log.Error().Err(err)
			return
		}

		log.Debug().Msgf("request headers %s", req.Header)

		body, err := io.ReadAll(req.Body)
		if err != nil {
			log.Error().Err(err)
			return
		}
		log.Debug().Msgf("request body %s", body)

		if !validated {
			log.Debug().Msgf("request valid: %v", validated)
			c.JSON(http.StatusBadRequest, gin.H{"Message": "Request not valid"})
			return
		}

		// Respond with success message
		c.JSON(http.StatusOK, gin.H{"Message": "Request validated and signed successfully"})
	})

	// Start the server on port 8765
	fmt.Println("Server listening on port 8765")
	router.Run(":8765")
}

func validateRequest(req *http.Request) (bool, *http.Request, error) {
	provider := NewProvider(
		WithIssuers([]Issuer{
			{
				Name:    "test",
				Enabled: true,
				Keys: []SecretKey{
					{
						Kid: "kid",
						Key: Secret{
							Value: []byte("testkey"),
						},
					},
				},
			},
			{
				Name:    "demo-python",
				Enabled: true,
				Keys: []SecretKey{
					{
						Kid: "primary",
						Key: Secret{
							Value: []byte("testkey"),
						},
					},
				},
			},
			{
				Name:    "demo-java",
				Enabled: true,
				Keys: []SecretKey{
					{
						Kid: "primary",
						Key: Secret{
							Value: []byte("testkey"),
						},
					},
				},
			},
			{
				Name:    "demo-js",
				Enabled: true,
				Keys: []SecretKey{
					{
						Kid: "primary",
						Key: Secret{
							Value: []byte("testkey"),
						},
					},
				},
			},
			{
				Name:    "demo-rust",
				Enabled: true,
				Keys: []SecretKey{
					{
						Kid: "primary",
						Key: Secret{
							Value: []byte("testkey"),
						},
					},
				},
			},
		}),
	)

	validated, request, err := provider.Validate(req)
	return validated, request, err
}

func validateAndSignRequest(req *http.Request) (bool, *http.Request, error) {
	provider := NewProvider(
		WithIssuers([]Issuer{
			{
				Name:    "test",
				Enabled: true,
				Keys: []SecretKey{
					{
						Kid: "kid",
						Key: Secret{
							Value: []byte("testkey"),
						},
					},
				},
			},
			{
				Name:    "demo-python",
				Enabled: true,
				Keys: []SecretKey{
					{
						Kid: "primary",
						Key: Secret{
							Value: []byte("testkey"),
						},
					},
				},
			},
			{
				Name:    "demo-java",
				Enabled: true,
				Keys: []SecretKey{
					{
						Kid: "primary",
						Key: Secret{
							Value: []byte("testkey"),
						},
					},
				},
			},
			{
				Name:    "demo-js",
				Enabled: true,
				Keys: []SecretKey{
					{
						Kid: "primary",
						Key: Secret{
							Value: []byte("testkey"),
						},
					},
				},
			},
			{
				Name:    "demo-rust",
				Enabled: true,
				Keys: []SecretKey{
					{
						Kid: "primary",
						Key: Secret{
							Value: []byte("testkey"),
						},
					},
				},
			},
		}),
	)

	validated, request, err := provider.Validate(req)
	if err != nil {
		return false, request, err
	}

	request.Header.Add("X-Service-Header-To-Sign", "Service")

	err = provider.Sign(request)

	if err != nil {
		fmt.Println("Error in the request signature:", err)
	}

	fmt.Println("Request signature: \n", request.Header.Get("Authorization"))

	requestDetails := struct {
		Headers map[string][]string `json:"headers"`
	}{
		Headers: request.Header,
	}

	_, err = json.Marshal(requestDetails)
	if err != nil {
		return false, request, err
	}

	return validated, request, err
}
