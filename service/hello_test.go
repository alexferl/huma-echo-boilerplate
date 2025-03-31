package service

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestService_Hello(t *testing.T) {
	s := &Service{}
	ctx := context.Background()

	resp, err := s.Hello(ctx, &struct{}{})

	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, "Hello, World!", resp.Body.Message)
}
