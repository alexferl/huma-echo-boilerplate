package service

import (
	"context"
	"fmt"

	"github.com/labstack/echo/v4"
)

type HelloResponse struct {
	Body struct {
		Message string `json:"message"`
	}
}

func (s *Service) Hello(ctx context.Context, _ *struct{}) (*HelloResponse, error) {
	echoCtx, ok := ctx.Value(echoCtxKey{}).(echo.Context)
	msg := "World"
	if ok {
		header := echoCtx.Request().Header.Get("X-Hello")
		if header != "" {
			msg = header
		}
	}

	resp := &HelloResponse{}
	resp.Body.Message = fmt.Sprintf("Hello, %s!", msg)
	return resp, nil
}
