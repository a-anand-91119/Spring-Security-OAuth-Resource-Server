### How to test?
- Send a POST request to `/api/auth/token` using basic authenication
    - username: `foobar`
    - password: `foobar`
- The response of the request will be a JWT token.
- Pass the token in the `Authorization` header to `/` api.