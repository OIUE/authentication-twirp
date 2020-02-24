package twirp

import (
	"context"
	"fmt"
	"github.com/pepeunlimited/authentication-twirp/pkg/rpc/auth"
	"github.com/pepeunlimited/microservice-kit/validator"
	"github.com/pepeunlimited/users/pkg/rpc/credentials"
	"github.com/twitchtv/twirp"
	"log"
	"testing"
	"time"
)

var secret1 string = "s3cr3t"
var secret2 string = "s3cr3t-2"

func TestAuthorizationServer_SignIn(t *testing.T) {
	server := NewAuthenticationServer(secret1, secret2, credentials.NewCredentialsMock(nil, false))
	ctx := context.TODO()
	resp0, err := server.SignIn(ctx, &auth.SignInParams{
		Username: "kakkaliisa",
		Password: "siimoo",
	})
	if err != nil {
		t.Error(err)
		t.FailNow()
	}
	if validator.IsEmpty(resp0.AccessToken) {
		t.FailNow()
	}
	log.Print(resp0)
	_, err = server.VerifyAccessToken(ctx, &auth.VerifyAccessTokenParams{AccessToken: resp0.AccessToken})
	if err != nil {
		t.Error(err)
		t.FailNow()
	}
}

func TestAuthorizationServer_SignInError(t *testing.T) {
	server := NewAuthenticationServer(secret1, secret2, credentials.NewCredentialsMock([]error{fmt.Errorf("custom-error")}, false))
	ctx := context.TODO()
	_, err := server.SignIn(ctx, &auth.SignInParams{
		Username: "kakkaliisa",
		Password: "siimoo",
	})
	if err == nil {
		t.FailNow()
	}
}

func TestAuthorizationServer_VerifyExpired(t *testing.T) {
	server := NewAuthenticationServer(secret1, secret2, credentials.NewCredentialsMock(nil, false))
	ctx := context.TODO()
	token, err := server.accessToken.SignIn(1*time.Second, "username", nil, []string{"User"}, nil)
	time.Sleep(2 * time.Second)
	_, err = server.VerifyAccessToken(ctx, &auth.VerifyAccessTokenParams{AccessToken: token})
	if err == nil {
		t.FailNow()
	}
	if err.(twirp.Error).Msg() != "access_token_expired" {
		t.FailNow()
	}
}

func TestAuthorizationServer_VerifyMalformed(t *testing.T) {
	server := NewAuthenticationServer(secret1, secret2, credentials.NewCredentialsMock(nil, false))
	ctx := context.TODO()
	token := "eyJhbGciOiJIUzI1NIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6InNpaW1vbyIsImtYWlsIjoic2ltb29AZ21haWwuY29tIiwicm9sZXMiOlsidXNlciJdLCJ1c2VyX2lkIjozLCJleHAiOjE1Nzc2MTczOTR9.AC7mkWENKOwHdZWkbD0QaBR1mMhxR1mo8PKztwQ47qA"
	_, err := server.VerifyAccessToken(ctx, &auth.VerifyAccessTokenParams{AccessToken: token})
	if err == nil {
		t.FailNow()
	}
	if err.(twirp.Error).Msg() != "access_token_malformed" {
		t.Error(err)
		t.FailNow()
	}
}

func TestAuthorizationServer_VerifyCantAccessUserService(t *testing.T) {
	server := NewAuthenticationServer(secret1, secret2, credentials.NewCredentialsMock([]error{fmt.Errorf("asd")}, false))
	ctx := context.TODO()
	_, err := server.SignIn(ctx, &auth.SignInParams{
		Username: "a",
		Password: "b",
	})
	if err == nil {
		t.FailNow()
	}
	if err.Error() != "asd" {
		t.FailNow()
	}
}

func TestAuthorizationServer_SignInCantAccessUserService(t *testing.T) {
	server := NewAuthenticationServer(secret1, secret2, credentials.NewCredentialsMock([]error{fmt.Errorf("asd")}, false))
	ctx := context.TODO()
	token,_ := server.accessToken.SignIn(2*time.Second, "username", nil, []string{"User"}, nil)
	_, err := server.VerifyAccessToken(ctx, &auth.VerifyAccessTokenParams{AccessToken: token})
	if err != nil {
		t.Error(err)
		t.FailNow()
	}
}

func TestAuthorizationServer_RefreshAccessToken(t *testing.T) {
	server := NewAuthenticationServer(secret1, secret2, credentials.NewCredentialsMock(nil, false))
	ctx := context.TODO()
	resp0,_ := server.SignIn(ctx, &auth.SignInParams{
		Username: "u",
		Password: "p",
	})
	resp1, err := server.RefreshAccessToken(ctx, &auth.RefreshAccessTokenParams{
		RefreshToken: resp0.RefreshToken,
	})
	if err != nil {
		t.Error(err)
		t.FailNow()
	}
	if validator.IsEmpty(resp1.AccessToken) {
		t.FailNow()
	}
	if !validator.IsEmpty(resp1.RefreshToken) {
		t.FailNow()
	}
}