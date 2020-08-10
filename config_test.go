package sidecred_test

import (
	"strings"
	"testing"

	"github.com/telia-oss/sidecred"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"sigs.k8s.io/yaml"
)

func TestConfig(t *testing.T) {
	tests := []struct {
		description string
		config      string
		expected    string
	}{
		{
			description: "works",
			config: strings.TrimSpace(`
---
version: 1
namespace: cloudops

stores:
  - type: secretsmanager
    config:
      secret_template: "/concourse/{{ .Namespace }}/{{ .Name }}"

requests:
  - type: aws:sts
    store: secretsmanager
    credentials:
      - name: open-source-dev-read-only
        role_arn: arn:aws:iam::role/role-name
        duration: 900
            `),
			expected: "",
		},
		{
			description: "errors if alias does not exist",
			config: strings.TrimSpace(`
---
version: 1
namespace: cloudops

stores:
  - type: secretsmanager
    alias: concourse
    config:
      secret_template: "/concourse/{{ .Namespace }}/{{ .Name }}"

requests:
  - type: aws:sts
    store: secretsmanager
    credentials:
      - name: open-source-dev-read-only
        role_arn: arn:aws:iam::role/role-name
        duration: 900
            `),
			expected: `requests[0]: invalid store alias: "secretsmanager"`,
		},
		{
			description: "errors on duplicate credential names",
			config: strings.TrimSpace(`
---
version: 1
namespace: cloudops

providers:
  - type: aws

stores:
  - type: secretsmanager
    config:
      secret_template: "/concourse/{{ .Namespace }}/{{ .Name }}"

credentials:
  - type: aws:sts
    store: concourse
    creds:
      - name: open-source-dev-read-only
        config:
          role_arn: arn:aws:iam::role/role-name
          duration: 900

requests:
  - type: aws:sts
    store: concourse
    credentials:
      - name: open-source-dev-read-only
        config:
          role_arn: arn:aws:iam::role/role-name
          duration: 900
      - name: open-source-dev-read-only
        config:
          role_arn: arn:aws:iam::role/role-name
          duration: 900
            `),
			expected: `requests[0]: invalid request: credentials[1]: duplicate name "open-source-dev-read-only"`,
		},
		{
			description: "errors on duplicate requests",
			config: strings.TrimSpace(`
---
version: 1
namespace: cloudops

stores:
  - type: secretsmanager
    alias: concourse
    config:
      template: "/concourse/{{ .Namespace }}/{{ .Name }}"

requests:
  - store: concourse
    type: aws:sts
    credentials:
      - name: open-source-dev-read-only
        role_arn: arn:aws:iam::role/role-arn
        duration: 900
  - store: concourse
    type: aws:sts
    credentials:
      - name: open-source-dev-read-only
        role_arn: arn:aws:iam::role/role-arn
        duration: 900
            `),
			expected: `requests[1]: duplicate request: {Type:aws:sts Store:concourse}`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.description, func(t *testing.T) {
			var (
				config *sidecred.Config
				actual string
				err    error
			)

			err = yaml.Unmarshal([]byte(tc.config), &config)
			require.NoError(t, err)

			err = config.Validate()
			if err != nil {
				actual = err.Error()
			}
			assert.Equal(t, tc.expected, actual)
		})
	}
}
