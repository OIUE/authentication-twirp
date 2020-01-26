package main

import (
	"github.com/pepeunlimited/authentication-twirp/internal/app/app1/server"
	"github.com/pepeunlimited/authentication-twirp/authrpc"
	"github.com/pepeunlimited/microservice-kit/headers"
	"github.com/pepeunlimited/microservice-kit/jwt"
	"github.com/pepeunlimited/microservice-kit/middleware"
	"github.com/pepeunlimited/microservice-kit/misc"
	"github.com/pepeunlimited/users/credentialsrpc"
	"log"
	"net/http"
)

const (
	Version = "0.1.2.8"
)

func main() {
	log.Printf("Starting the authentication-twirp... version=[%v]", Version)

	accessTokenSecret := misc.GetEnv(jwt.AccessTokenSecretKey, "v3ry-s3cr3t-k3y-666")
	refreshTokenSecret := misc.GetEnv(jwt.RefreshTokenSecretKey, "v3ry-s3cr3t-k3y-999")
	credentialsAddress := misc.GetEnv(credentialsrpc.RpcCredentialsHost, "http://localhost:8080")

	as := authrpc.NewAuthenticationServiceServer(
		server.NewAuthenticationServer(accessTokenSecret,
		refreshTokenSecret,
			credentialsrpc.NewCredentialsServiceProtobufClient(credentialsAddress,http.DefaultClient)),
		nil)
	mux := http.NewServeMux()
	mux.Handle(as.PathPrefix(), middleware.Adapt(as, headers.Authorizationz()))

	if err := http.ListenAndServe(":8080", mux); err != nil {
		log.Panic(err)
	}
}