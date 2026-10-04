package auth

import (
	"errors"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetAPIKey(t *testing.T) {
	type testCase struct {
		headers http.Header

		expected string
		err      error
	}

	t.Run("get apy key", func(t *testing.T) {
		tests := []testCase{
			{headers: http.Header{}, expected: "", err: ErrNoAuthHeaderIncluded},
			{
				headers:  http.Header{"Authorization": []string{"ApiKey"}},
				expected: "",
				err:      errors.New("malformed authorization header"),
			},
			{
				headers:  http.Header{"Authorization": []string{"ApiKey my-secret"}},
				expected: "my-secret",
				err:      nil,
			},
		}

		for _, test := range tests {
			actual, err := GetAPIKey(test.headers)

			if test.err != nil {
				assert.EqualError(t, err, test.err.Error())
				assert.Equal(t, test.expected, actual)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, test.expected, actual)
			}

		}
	})
}
