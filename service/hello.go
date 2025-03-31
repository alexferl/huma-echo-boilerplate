package service

import (
	"context"
)

type HelloResponse struct {
	Body struct {
		Message string `json:"message"`
	}
}

func (s *Service) Hello(context.Context, *struct{}) (*HelloResponse, error) {
	resp := &HelloResponse{}
	resp.Body.Message = "Hello, World!"
	return resp, nil
}
