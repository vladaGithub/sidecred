package sidecred_test

import (
	"strings"
	"testing"
	"time"

	"github.com/telia-oss/sidecred"
	"github.com/telia-oss/sidecred/store/inprocess"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"
	"sigs.k8s.io/yaml"
)

var (
	testCredentialType = sidecred.CredentialType("fake")
	testStateID        = "fake.state.id"
	testTime           = time.Now().Add(1 * time.Hour)
)

func TestProcess(t *testing.T) {
	tests := []struct {
		description          string
		namespace            string
		config               string
		resources            []*sidecred.Resource
		requests             []*sidecred.Request
		expectedSecrets      map[string]string
		expectedResources    []*sidecred.Resource
		expectedCreateCalls  int
		expectedDestroyCalls int
	}{
		{
			description: "sidecred works",
			namespace:   "team-name",
			config: strings.TrimSpace(`
---
version: 1
namespace: team-name 

stores:
  - type: inprocess

requests:
  - store: inprocess
    credentials:
      - type: fake
        name: fake.state.id

            `),
			expectedSecrets: map[string]string{
				"team-name.fake-credential": "fake-value",
			},
			expectedResources: []*sidecred.Resource{{
				ID:         testStateID,
				Expiration: testTime,
				InUse:      true,
			}},
			expectedCreateCalls: 1,
		},
		{
			description: "does not create credentials when they exist in state",
			namespace:   "team-name",
			config: strings.TrimSpace(`
---
version: 1
namespace: team-name 

stores:
  - type: inprocess

requests:
  - store: inprocess
    credentials:
      - type: fake
        name: fake.state.id

            `),
			resources: []*sidecred.Resource{{
				ID:         testStateID,
				Expiration: testTime,
			}},
			expectedSecrets: map[string]string{},
			expectedResources: []*sidecred.Resource{{
				ID:         testStateID,
				Expiration: testTime,
				InUse:      true,
			}},
			expectedCreateCalls: 0,
		},
		{
			description: "replaces expired resources (within the rotation window)",
			namespace:   "team-name",
			config: strings.TrimSpace(`
---
version: 1
namespace: team-name 

stores:
  - type: inprocess

requests:
  - store: inprocess
    credentials:
      - type: fake
        name: fake.state.id
            `),
			resources: []*sidecred.Resource{{
				ID:         testStateID,
				Expiration: time.Now().Add(3 * time.Minute),
			}},
			expectedResources: []*sidecred.Resource{{
				ID:         testStateID,
				Expiration: testTime,
				InUse:      true,
			}},
			expectedCreateCalls:  1,
			expectedDestroyCalls: 1,
		},
		{
			description: "destroys deposed resources",
			namespace:   "team-name",
			config: strings.TrimSpace(`
---
version: 1
namespace: team-name 

stores:
  - type: inprocess

requests:
  - store: inprocess
    credentials:
      - type: fake
        name: fake.state.id
            `),
			resources: []*sidecred.Resource{{
				ID:         testStateID,
				Expiration: time.Now(),
			}},
			expectedResources: []*sidecred.Resource{{
				ID:         testStateID,
				Expiration: testTime,
				InUse:      true,
			}},
			expectedCreateCalls:  1,
			expectedDestroyCalls: 1,
		},
		{
			description: "destroys resources that are no longer requested",
			namespace:   "team-name",
			config: strings.TrimSpace(`
---
version: 1
namespace: team-name 

stores:
  - type: inprocess

requests:
  - store: inprocess
    credentials: []
            `),
			resources: []*sidecred.Resource{{
				ID:         "other.state.id",
				Expiration: testTime,
			}},
			requests:             []*sidecred.Request{},
			expectedResources:    []*sidecred.Resource{},
			expectedDestroyCalls: 1,
		},
		{
			description: "does nothing if there are no requests",
			namespace:   "team-name",
			config: strings.TrimSpace(`
---
version: 1
namespace: team-name 

stores:
  - type: inprocess

requests:
  - store: inprocess
    credentials: []
            `),
			expectedSecrets: map[string]string{},
		},
		{
			description: "does nothing if there are no providers for the request",
			namespace:   "team-name",
			resources:   []*sidecred.Resource{},
			config: strings.TrimSpace(`
---
version: 1
namespace: team-name 

stores:
  - type: inprocess

requests:
  - store: inprocess
    credentials:
      - type: aws:sts
        name: fake.state.id
            `),
			expectedSecrets:   map[string]string{},
			expectedResources: []*sidecred.Resource{},
		},
		{
			description: "credentials can inherit type from the request",
			namespace:   "team-name",
			resources:   []*sidecred.Resource{},
			config: strings.TrimSpace(`
---
version: 1
namespace: team-name 

stores:
  - type: inprocess

requests:
  - store: inprocess
    type: fake
    credentials:
      - name: fake.state.id
            `),
			expectedSecrets: map[string]string{
				"team-name.fake-credential": "fake-value",
			},
			expectedResources: []*sidecred.Resource{{
				ID:         testStateID,
				Expiration: testTime,
				InUse:      true,
			}},
			expectedCreateCalls: 1,
		},
	}

	for _, tc := range tests {
		t.Run(tc.description, func(t *testing.T) {
			var (
				config   = &sidecred.Config{}
				store    = inprocess.New()
				state    = sidecred.NewState()
				provider = &fakeProvider{}
				logger   = zaptest.NewLogger(t)
			)

			err := yaml.Unmarshal([]byte(tc.config), &config)
			require.NoError(t, err)

			for _, r := range tc.resources {
				state.AddResource(provider.Type(), r)
			}

			s, err := sidecred.New([]sidecred.Provider{provider}, []sidecred.SecretStore{store}, 10*time.Minute, logger)
			require.NoError(t, err)

			err = s.Process(tc.namespace, config, state)
			require.NoError(t, err)
			assert.Equal(t, tc.expectedCreateCalls, provider.CreateCallCount(), "create calls")
			assert.Equal(t, tc.expectedDestroyCalls, provider.DestroyCallCount(), "destroy calls")

			for _, p := range state.Providers {
				assert.Equal(t, tc.expectedResources, p.Resources)
			}

			for k, v := range tc.expectedSecrets {
				value, found, err := store.Read(k, nil)
				assert.NoError(t, err)
				assert.True(t, found, "secret exists")
				assert.Equal(t, v, value)
			}
		})
	}
}

// This test exists because looping over pointers as done when cleaning up expired/deposed
// resources (and deposed secrets) can lead to surprising behaviours. The test below ensures
// that things are working as intended.
func TestProcessCleanup(t *testing.T) {
	tests := []struct {
		description          string
		namespace            string
		resources            []*sidecred.Resource
		secrets              []*sidecred.Secret
		expectedDestroyCalls int
	}{
		{
			description: "cleanup works",
			namespace:   "team-name",
			resources: []*sidecred.Resource{
				{
					ID:         "r1",
					Expiration: time.Now(),
				},
				{
					ID:         "r2",
					Expiration: time.Now(),
				},
				{
					ID:         "r3",
					Expiration: time.Now(),
				},
			},
			secrets: []*sidecred.Secret{
				{
					ResourceID: "r1",
					Path:       "path1",
					Expiration: time.Now(),
				},
				{
					ResourceID: "r1",
					Path:       "path2",
					Expiration: time.Now(),
				},
				{
					ResourceID: "r2",
					Path:       "path3",
					Expiration: time.Now(),
				},
			},
			expectedDestroyCalls: 3,
		},
	}

	for _, tc := range tests {
		t.Run(tc.description, func(t *testing.T) {
			var (
				store    = inprocess.New()
				state    = sidecred.NewState()
				provider = &fakeProvider{}
				logger   = zaptest.NewLogger(t)
			)

			for _, r := range tc.resources {
				state.AddResource(provider.Type(), r)
			}

			for _, s := range tc.secrets {
				state.AddSecret(&sidecred.StoreConfig{Type: store.Type()}, s)
			}

			s, err := sidecred.New([]sidecred.Provider{provider}, []sidecred.SecretStore{store}, 10*time.Minute, logger)
			require.NoError(t, err)

			err = s.Process(tc.namespace, &sidecred.Config{Version: 1, Namespace: "team-name"}, state)
			require.NoError(t, err)
			assert.Equal(t, tc.expectedDestroyCalls, provider.DestroyCallCount(), "destroy calls")

			for _, p := range state.Providers {
				if !assert.Equal(t, 0, len(p.Resources)) {
					for _, s := range p.Resources {
						assert.Nil(t, s)
					}
				}
			}

			for _, p := range state.Stores {
				if !assert.Equal(t, 0, len(p.Secrets)) {
					for _, s := range p.Secrets {
						assert.Nil(t, s)
					}
				}
			}
		})
	}
}

// Fake implementation of sidecred.Provider.
type fakeProvider struct {
	createCallCount  int
	destroyCallCount int
}

func (f *fakeProvider) Type() sidecred.ProviderType {
	return sidecred.ProviderType("fake")
}

func (f *fakeProvider) Create(r *sidecred.Request) ([]*sidecred.Credential, *sidecred.Metadata, error) {
	f.createCallCount++
	return []*sidecred.Credential{{
			Name:       "fake-credential",
			Value:      "fake-value",
			Expiration: testTime,
		}},
		nil,
		nil
}

func (f *fakeProvider) Destroy(r *sidecred.Resource) error {
	f.destroyCallCount++
	return nil
}

func (f *fakeProvider) CreateCallCount() int {
	return f.createCallCount
}

func (f *fakeProvider) DestroyCallCount() int {
	return f.destroyCallCount
}
