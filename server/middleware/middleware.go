// Copyright (C) 2015 NTT Innovation Institute, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package middleware

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/cloudwan/gohan/schema"
	"github.com/gin-gonic/gin"
	"github.com/rackspace/gophercloud"
)

const webuiPATH = "/webui"

func filterHeaders(headers http.Header) http.Header {
	filtered := http.Header{}
	for k, v := range headers {
		if k == "X-Auth-Token" {
			filtered[k] = []string{"***"}
			continue
		}
		filtered[k] = v
	}
	return filtered
}

//IdentityService for user authentication & authorization
type IdentityService interface {
	GetTenantID(string) (string, error)
	GetTenantName(string) (string, error)
	VerifyToken(string) (schema.Authorization, error)
	GetServiceAuthorization() (schema.Authorization, error)
	GetClient() *gophercloud.ServiceClient
}

//HTTPJSONError helper for returning JSON errors
func HTTPJSONError(c *gin.Context, err string, code int) {
	errorMessage := ""
	if code == http.StatusInternalServerError {
		log.Error(err)
	} else {
		errorMessage = err
		log.Notice(err)
	}
	response := map[string]interface{}{"error": errorMessage}
	responseJSON, _ := json.Marshal(response)
	c.JSON(code, responseJSON)
}

//Authentication authenticates user using keystone
func Authentication() gin.HandlerFunc {
	return func(c *gin.Context) {
		identityService := c.MustGet("identityService").(IdentityService)
		req := c.Request
		if req.Method == "OPTIONS" {
			c.Next()
			return
		}
		//TODO(nati) make this configurable
		if strings.HasPrefix(req.URL.Path, webuiPATH) {
			c.Next()
			return
		}

		if req.URL.Path == "/" || req.URL.Path == "/webui" {
			c.Redirect(http.StatusTemporaryRedirect, webuiPATH)
			return
		}

		if req.URL.Path == "/v2.0/tokens" {
			c.Next()
			return
		}
		authToken := req.Header.Get("X-Auth-Token")
		if authToken == "" {
			HTTPJSONError(c, "No X-Auth-Token", http.StatusUnauthorized)
			return
		}

		auth, err := identityService.VerifyToken(authToken)
		if err != nil {
			HTTPJSONError(c, err.Error(), http.StatusUnauthorized)
		}
		c.Set("auth", auth)
		context := c.MustGet("context").(Context)
		context["tenant_id"] = auth.TenantID()
		context["tenant_name"] = auth.TenantName()
		context["auth_token"] = auth.AuthToken()
		context["catalog"] = auth.Catalog()
		context["auth"] = auth
		c.Next()
	}
}

//Context type
type Context map[string]interface{}

//WithContext injects new empty context object
func WithContext() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Set("context", Context{})
		c.Next()
	}
}

// JSONURLs strips ".json" suffixes added to URLs
func JSONURLs() gin.HandlerFunc {
	return func(c *gin.Context) {
		req := c.Request
		if !strings.Contains(req.URL.Path, "gohan") && !strings.Contains(req.URL.Path, webuiPATH) {
			req.URL.Path = strings.TrimSuffix(req.URL.Path, ".json")
		}
		c.Next()
	}
}
