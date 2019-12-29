package server

import (
	"context"
	"fmt"
	rpc2 "github.com/pepeunlimited/authorization-twirp/rpc"
	"github.com/pepeunlimited/microservice-kit/rpcz"
	"github.com/pepeunlimited/microservice-kit/validator"
	"github.com/pepeunlimited/users/rpc"
	"log"
	"testing"
)

var secret string = "s3cr3t"

func TestAuthorizationServer_SignIn(t *testing.T) {
	server := NewAuthorizationServer(secret, rpc.NewUserServiceMock(nil, false))
	ctx := context.TODO()
	resp0, err := server.SignIn(ctx, &rpc2.SignInParams{
		Username: "kakkaliisa",
		Password: "siimoo",
	})
	if err != nil {
		t.Error(err)
		t.FailNow()
	}
	if validator.IsEmpty(resp0.Token) {
		t.FailNow()
	}
	ctx = rpcz.AddAuthorization(resp0.Token)
	resp1, err := server.Verify(ctx, &rpc2.VerifyParams{})
	log.Print(resp1)
}

func TestAuthorizationServer_SignInError(t *testing.T) {
	server := NewAuthorizationServer(secret, rpc.NewUserServiceMock([]error{fmt.Errorf("custom-error")}, false))
	ctx := context.TODO()
	_, err := server.SignIn(ctx, &rpc2.SignInParams{
		Username: "kakkaliisa",
		Password: "siimoo",
	})
	if err == nil {
		t.FailNow()
	}
}