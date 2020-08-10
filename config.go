package sidecred

import (
	"encoding/json"
	"errors"
	"fmt"
)

// Config ...
type Config struct {
	Version   int                  `json:"version"`
	Namespace string               `json:"namespace"`
	Stores    []*StoreConfig       `json:"stores"`
	Requests  []*CredentialRequest `json:"requests"`
}

// StoreConfig ...
type StoreConfig struct {
	Type   StoreType       `json:"type,omitempty"`
	Alias  string          `json:"alias,omitempty"`
	Config json.RawMessage `json:"config,omitempty"`
}

// CredentialRequest ...
type CredentialRequest struct {
	Type        CredentialType `json:"type"`
	Store       string         `json:"store"`
	Credentials []*Request     `json:"credentials"`
}

// Validate the configuration.
func (c *Config) Validate() error {
	if c.Version != 1 {
		return fmt.Errorf("invalid configuration version: %d", c.Version)
	}
	if c.Namespace == "" {
		return fmt.Errorf("%q must be defined", "namespace")
	}

	stores := make(map[string]struct{}, len(c.Stores))
	for i, s := range c.Stores {
		if err := s.validate(); err != nil {
			return fmt.Errorf("stores[%d]: invalid config: %s", i, err.Error())
		}
		alias := s.getAlias()
		_, found := stores[alias]
		if found {
			return fmt.Errorf("stores[%d]: duplicate alias %q", i, alias)
		}
		stores[alias] = struct{}{}
	}

	type requestsKey struct {
		Type  CredentialType
		Store string
	}

	requests := make(map[requestsKey]struct{}, len(c.Requests))
	for i, r := range c.Requests {
		if err := r.validate(); err != nil {
			return fmt.Errorf("requests[%d]: invalid request: %s", i, err.Error())
		}
		switch r.Type {
		case
			AWSSTS,
			GithubAccessToken,
			GithubDeployKey,
			ArtifactoryAccessToken,
			Randomized:
		default:
			return fmt.Errorf("requests[%d]: unknown type: %s", i, string(r.Type))
		}
		if _, found := stores[r.Store]; !found {
			return fmt.Errorf("requests[%d]: invalid store alias: %q", i, r.Store)
		}
		key := requestsKey{Type: r.Type, Store: r.Store}
		_, found := requests[key]
		if found {
			return fmt.Errorf("requests[%d]: duplicate request: %+v", i, key)
		}
		requests[key] = struct{}{}
	}

	return nil
}

// GetStoreConfig ...
func (c *Config) GetStoreConfig(alias string) *StoreConfig {
	for _, s := range c.Stores {
		if s.getAlias() == alias {
			return s
		}
	}
	return nil
}

func (c *CredentialRequest) validate() error {
	if c.Type == "" {
		return fmt.Errorf("%q must be defined", "type")
	}
	if c.Store == "" {
		return fmt.Errorf("%q must be defined", "store")
	}
	if len(c.Credentials) == 0 {
		return errors.New("no credentials requested")
	}

	creds := make(map[string]struct{}, len(c.Credentials))
	for i, cc := range c.Credentials {
		if cc.Name == "" {
			return fmt.Errorf("credentials[%d]: %q must be defined", i, "name")
		}
		_, found := creds[cc.Name]
		if found {
			return fmt.Errorf("credentials[%d]: duplicate name %q", i, cc.Name)
		}
		creds[cc.Name] = struct{}{}
	}
	return nil
}

func (c *StoreConfig) getAlias() string {
	if c.Alias != "" {
		return c.Alias
	}
	return string(c.Type)
}

func (c *StoreConfig) validate() error {
	return nil
}
