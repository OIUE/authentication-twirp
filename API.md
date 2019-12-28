# cURL

### Install
```$ brew install jq > curl ... | jq```

##### SignIn
```
$ curl -H "Content-Type: application/json" \
 -X POST "localhost:8080/twirp/pepeunlimited.authorization.AuthorizationService/SignIn" \
 -d '{"username": "kakkaliisa", "password": "p4sw0rd"}'
```
##### SignIn
```
$ curl -H "Content-Type: application/json" -H "Authorization: Bearer REPLACE_WITH_TOKEN" \
 -X POST "localhost:8080/twirp/pepeunlimited.authorization.AuthorizationService/SignIn" \
 -d '{"standard_vat": "24.00"}'
```