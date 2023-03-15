// Package vault provides minimal primitives for getting secrets
// out of a hashicorp vault.
package lib-vault

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"time"

	getenv "github.com/caarlos0/env/v6"
	"github.com/pkg/errors"
)

type VaultEnv struct {
	VaultUseSRV bool   `env:"VAULT_IS_SRV" envDefault:"true"`
	VaultAddr   string `env:"VAULT_ADDR" envDefault:"_vault._tcp"`
	VaultUser   string `env:"VAULT_USERNAME,required"`
	VaultPass   string `env:"VAULT_PASSWORD,required,unset"`
	VaultPort   int    `env:"VAULT_PORT"`
	TVault      *Vault
	VaultIsLog  bool `env:"VAULT_IS_LOGGED" envDefault:"false"`
}

// A Vault structure contains internal variables needed to connect to the vault
type Vault struct {
	service string
	user    string
	pass    string
	url     string
	token   string
	client  *http.Client
}

// authRequest is a simple structure used internally to encode a vault auth request
type authRequest struct {
	Password string `json:"password"`
}

// authResponse is a structure used internally to decode a vault auth response
type authResponse struct {
	LeaseID       string `json:"lease_id"`
	Renewable     bool   `json:"renewable"`
	LeaseDuration int    `json:"lease_duration"`
	Auth          struct {
		ClientToken string   `json:"client_token"`
		Policies    []string `json:"policies"`
		Metadata    struct {
			Username string `json:"username"`
		} `json:"metadata"`
		LeaseDuration int  `json:"lease_duration"`
		Renewable     bool `json:"renewable"`
	} `json:"auth"`
}

// secretResponse is a structure used internally to decode a vault get secret response
type secretResponse struct {
	Data struct {
		Metadata struct {
			Version      int       `json:"version"`
			Destroyed    bool      `json:"destroyed"`
			DeletionTime string    `json:"deletion_time"`
			CreatedTime  time.Time `json:"created_time"`
		} `json:"metadata"`
		Data map[string]string `json:"data"`
	} `json:"data"`
}

type ListResponse struct {
	RequestId     string `json:"request_id"`
	LeaseId       string `json:"lease_id"`
	Renewable     bool   `json:"renewable"`
	LeaseDuration int    `json:"lease_duration"`
	Data          struct {
		Keys []string `json:"keys"`
	} `json:"data"`
	WrapInfo interface{} `json:"wrap_info"`
	Warnings interface{} `json:"warnings"`
	Auth     interface{} `json:"auth"`
}

// An Instance is a structure that can be use first: to get the information for vault from the environment variables
// and second: to obtaint the vault key using its Setup function
type Instance struct {
	UseSRV   bool   `env:"VAULT_IS_SRV,required"`
	Addr     string `env:"VAULT_ADDR,required"`
	User     string `env:"VAULT_USERNAME,required"`
	Pass     string `env:"VAULT_PASSWORD,required,unset"`
	VaultKey string `env:"VAULT_KEY"`
	vault    *Vault
	Key      []byte
}

// NewFromService creates a new vault structure from a DNS SRV record.
// The actual url used is the first one of the returned SRV addresses.
// It relies on the non-deterministic nature of the order of the returned addresses.
// The proto must be http or https depending on the vault setup.
func NewFromService(serviceAddr string, proto string, user string, pass string) (*Vault, error) {
	_, addrs, err := net.LookupSRV("", "", serviceAddr)
	if err != nil {
		return nil, errors.Wrap(err, "could not lookup srv record")
	}
	if len(addrs) > 0 {
		return &Vault{
			service: serviceAddr,
			user:    user,
			pass:    pass,
			url:     fmt.Sprintf("%s://%s:%d/v1", proto, addrs[0].Target, addrs[0].Port),
			client:  httpClient(),
		}, nil
	}
	return nil, errors.Errorf("no srv addrs found for %s", serviceAddr)
}

// NewFromHost creates a new vault structure from a hostname.
// If multiple addresses are returned, the first one of the DNS server response is
// used. The proto must be http or https depending on the vault setup.
func NewFromHost(hostAddr string, port int, proto string, user string, pass string) (*Vault, error) {
	addrs, err := net.LookupHost(hostAddr)
	if err != nil {
		return nil, errors.Wrap(err, "could not lookup host")
	}
	if len(addrs) > 0 {
		return &Vault{
			user:   user,
			pass:   pass,
			url:    fmt.Sprintf("%s://%s:%d/v1", proto, addrs[0], port),
			client: httpClient(),
		}, nil
	}
	return nil, errors.Errorf("could not lookup %s", hostAddr)
}

// NewFromHostWithClient creates a new vault structure from a hostname and a custom http client.
// If multiple addresses are returned, the first one of the DNS server response is
// used. The proto must be http or https depending on the vault setup.
func NewFromHostWithClient(hostAddr string, port int, proto string, user string, pass string, httpClient *http.Client) (*Vault, error) {
	addrs, err := net.LookupHost(hostAddr)
	if err != nil {
		return nil, errors.Wrap(err, "could not lookup host")
	}
	if len(addrs) > 0 {
		return &Vault{
			user:   user,
			pass:   pass,
			url:    fmt.Sprintf("%s://%s:%d/v1", proto, addrs[0], port),
			client: httpClient,
		}, nil
	}
	return nil, errors.Errorf("could not lookup %s", hostAddr)
}

func (v *Vault) GetURL() string {
	return v.url
}

// GetToken authenticates the user against the vault.
// On success a temporary token is returned which can be used for subsequent vault access.
// The token is also stored in the vault structure.
func (v *Vault) GetToken() (string, error) {
	requestURL := fmt.Sprintf("%s/auth/userpass/login/%s", v.url, v.user)
	// log.Println("url destination is", requestURL)
	authRequest := authRequest{
		Password: v.pass,
	}
	data, err := json.Marshal(&authRequest)
	if err != nil {
		return "", errors.Wrap(err, "could not marshal authRequest")
	}
	// log.Println("do marshal")
	resp, err := v.client.Post(requestURL, "application/json", bytes.NewReader(data))
	if err != nil {
		return "", errors.Wrap(err, "post failed")
	}
	// log.Println("step0")
	if resp == nil {
		return "", errors.New("nil response")
	}
	if resp.Body != nil {
		defer func() {
			_ = resp.Body.Close()
		}()
	}
	// log.Println("step1")
	if resp.StatusCode != 200 {
		return "", errors.Errorf("authRequest returned: %s", resp.Status)
	}
	// log.Println("step2")
	data, err = io.ReadAll(resp.Body)
	if err != nil {
		return "", errors.Wrap(err, "could not read authResponse")
	}
	// log.Println("response:", string(data))
	authResponse := authResponse{}
	err = json.Unmarshal(data, &authResponse)
	if err != nil {
		// log.Println("could not parse authResponse")
		return "", errors.Wrap(err, "could not parse authResponse")
	}
	v.token = authResponse.Auth.ClientToken
	return authResponse.Auth.ClientToken, nil
}

// GetSecret retrieves a secret from vault.
// Required parameters are: a secretPath e.g. /secret/mysecret and
// a key for the map in which the secret is stored.
// The secret is returned "as is". Occuring errors are returned with an empty string
// as the secret's value.
func (v *Vault) GetSecret(secretPath string, key string) (value string, err error) {
	secrets, err := v.GetSecrets("", secretPath, false)
	if err != nil {
		return "", err
	}
	return secrets[key], nil
}

// GetSecrets retrieves secrets from vault.
// Required parameters are: a secretPath e.g. /secret/mysecret
// The secrets are returned "as is". Occuring errors are returned with an empty maps
// as the secrets' value.
func (v *Vault) GetSecrets(logInfo, secretPath string, isVaultLogged bool) (value map[string]string, err error) {
	rawURL := fmt.Sprintf("%s/%s", v.url, secretPath)
	if isVaultLogged {
		log.Println(logInfo, "debug: full URL to vault:", rawURL)
	}
	requestURL, err := url.Parse(rawURL)
	if err != nil {
		return map[string]string{}, errors.Wrap(err, "could not parse url")
	}
	req := http.Request{
		Method: "GET",
		URL:    requestURL,
		Header: map[string][]string{"X-Vault-Token": {v.token}},
	}
	resp, err := v.client.Do(&req)
	if err != nil {
		return map[string]string{}, errors.Wrap(err, "get failed")
	}
	if resp == nil {
		return map[string]string{}, errors.New("nil response")
	}
	if resp.Body != nil {
		defer func() {
			_ = resp.Body.Close()
		}()
	}
	if resp.StatusCode != 200 {
		return map[string]string{}, errors.Errorf("getSecret returned: %s", resp.Status)
	}
	data, err := io.ReadAll(resp.Body)
	var secretResponse secretResponse
	err = json.Unmarshal(data, &secretResponse)
	if err != nil {
		return map[string]string{}, errors.Wrap(err, "could not unmarshal response")
	}
	return secretResponse.Data.Data, nil
}

func (v *Vault) ListSecrets(secret string) (ListResponse, error) {
	var listResponse ListResponse
	rawURL := fmt.Sprintf("%s/secret/metadata/%s", v.url, secret)
	requestURL, err := url.Parse(rawURL)
	if err != nil {
		return listResponse, errors.Wrap(err, "could not parse url")
	}
	req := http.Request{
		Method: "LIST",
		URL:    requestURL,
		Header: map[string][]string{"X-Vault-Token": {v.token}},
	}
	resp, err := v.client.Do(&req)
	if err != nil {
		return listResponse, errors.Wrap(err, "list failed")
	}
	if resp == nil {
		return listResponse, errors.New("nil response")
	}
	if resp.Body != nil {
		defer func() {
			_ = resp.Body.Close()
		}()
	}
	if resp.StatusCode != 200 {
		return listResponse, errors.Errorf("listSecrets returned: %s", resp.Status)
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return listResponse, errors.Wrap(err, "could not read all response body")
	}

	err = json.Unmarshal(data, &listResponse)
	if err != nil {
		return listResponse, errors.Wrap(err, "could not unmarshal response")
	}
	return listResponse, nil
}

// Function httpClient tries to construct a http.Client with timeouts
func httpClient() *http.Client {
	var client = http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			DialContext: (&net.Dialer{
				Timeout: 5 * time.Second,
			}).DialContext,
			TLSHandshakeTimeout: 5 * time.Second,
		},
	}
	return &client
}

// NewInstance tries to return an instance of vault created with information from the enviroment variables
func NewInstance() (*Instance, error) {
	v := Instance{}

	err := getenv.Parse(&v)
	if err != nil {
		return nil, errors.Wrap(err, "could not parse environment")
	}

	if v.UseSRV {
		v.vault, err = NewFromService(v.Addr, "https", v.User, v.Pass)
	} else {
		v.vault, err = NewFromHost(v.Addr, 8200, "http", v.User, v.Pass)
	}
	if err != nil {
		return nil, errors.Wrap(err, "could not create a vault service")
	}

	_, err = v.vault.GetToken()
	if err != nil {
		return nil, errors.Wrap(err, "could not get a token from vault")
	}

	secret, err := v.vault.GetSecret(filepath.Dir(v.VaultKey), filepath.Base(v.VaultKey))
	if err != nil {
		return nil, errors.Wrap(err, "could not get key from vault")
	}

	v.Key, err = base64.StdEncoding.DecodeString(secret)
	if err != nil {
		return nil, errors.Wrap(err, "could not decode key")
	}
	return &v, nil
}

