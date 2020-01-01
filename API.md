# cURL

### Install
```$ brew install jq > curl ... | jq```

##### SignIn
```
$ curl -H "Content-Type: application/json" \
 -X POST "http://api.dev.pepeunlimited.com/twirp/pepeunlimited.authorization.AuthorizationService/SignIn" \
 -d '{"username": "kakkaliisa", "password": "p4sw0rd"}'
```
##### VerifyAccessToken
```
$ curl -H "Content-Type: application/json" \
 -X POST "api.dev.pepeunlimited.com/twirp/pepeunlimited.authorization.AuthorizationService/VerifyAccessToken" \
 -d '{"access_token": "24.00"}'
```
##### RefreshAccessToken
```
$ curl -H "Content-Type: application/json" \
 -X POST "api.dev.pepeunlimited.com/twirp/pepeunlimited.authorization.AuthorizationService/RefreshAccessToken" \
 -d '{"refresh_token": "24.00"}'
```