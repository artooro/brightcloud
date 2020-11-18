package brightcloud

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/mrjones/oauth"
)

// OAuth consumer
type OAuth struct {
	key    string
	secret string
}

// SignRequest should take a URL and sign it
func (o *OAuth) SignRequest(req *http.Request) *http.Request {
	orderedParams := oauth.NewOrderedParams()
	orderedParams.Add("oauth_version", "1.0")
	orderedParams.Add("oauth_consumer_key", o.key)
	orderedParams.Add("oauth_signature_method", "HMAC-SHA1")
	orderedParams.Add("oauth_timestamp", fmt.Sprintf("%v", time.Now().Unix()))

	nonce, err := o.generateNonce()
	if err != nil {
		log.Fatalf("unable to generate nonce: %v", err)
	}
	orderedParams.Add("oauth_nonce", nonce)

	baseString := o.baseString(req, orderedParams)
	sig := o.buildSignature(req, baseString)

	// Build Authorization header
	authHeader := "OAuth realm=\"\","
	var authHeaderParams []string
	for _, key := range orderedParams.Keys() {
		for _, value := range orderedParams.Get(key) {
			valString := fmt.Sprintf("%v=\"%v\"", url.QueryEscape(key), url.QueryEscape(value))
			authHeaderParams = append(authHeaderParams, valString)
		}
	}
	authHeader = authHeader + strings.Join(authHeaderParams, ",")
	authHeader = authHeader + fmt.Sprintf(",oauth_signature=\"%v\"", sig)

	req.Header.Add("Authorization", authHeader)
	return req
}

func (o *OAuth) baseString(req *http.Request, orderedParams *oauth.OrderedParams) string {
	parts := make([]string, 3)

	// Method
	parts[0] = req.Method

	// Normalized URL
	port := ""
	if req.URL.Port() != "443" && req.URL.Port() != "80" && req.URL.Port() != "" {
		port = fmt.Sprintf(":%v", req.URL.Port())
	}
	normalizedURL := fmt.Sprintf("%s://%s%s%s", req.URL.Scheme, req.URL.Host, port, req.URL.Path)
	parts[1] = url.QueryEscape(normalizedURL)

	// Normalized URL parameters
	params := make([]string, 5)
	for pos, key := range orderedParams.Keys() {
		for _, value := range orderedParams.Get(key) {
			params[pos] = url.QueryEscape(fmt.Sprintf("%s=%s", key, value))
		}
	}
	parts[2] = strings.Join(params, "%26")

	return strings.Join(parts, "&")
}

func (o *OAuth) buildSignature(req *http.Request, basestring string) string {
	key := fmt.Sprintf("%v&", url.QueryEscape(o.secret))
	mac := hmac.New(sha1.New, []byte(key))
	mac.Write([]byte(basestring))
	rawHash := mac.Sum(nil)

	return url.QueryEscape(base64.StdEncoding.EncodeToString(rawHash))
}

func (o *OAuth) generateNonce() (string, error) {
	b := make([]byte, 16)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	mac := md5.New()
	_, err = mac.Write(b)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", mac.Sum(nil)), nil
}

// NewOauthConsumer will configure a new oauth instance
func NewOauthConsumer(key, secret string) *OAuth {
	o := new(OAuth)
	o.key = key
	o.secret = secret
	return o
}
