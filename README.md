# gauth

> [!NOTE]
> The implemenation only has been tested with the Authentik Auth provider. More information can be found [here](https://goauthentik.io/)


An auth OIDC-based implemenation for [SOARCA](https://github.com/COSSAS/SOARCA) based using the [GIN](https://github.com/gin-gonic/gin) framework. Library provides convient functionality and middleware for the OIDCS token validation and redirects. 
Gauth uses encrypted stored cookies for storing the jwt-token client-side. For more information on secure cookies we refer to [Gorilla](https://github.com/gorilla/sessions). By default the life time of a stored session cookie is set to 8 hours, see `COOKIE_LIFETIME` under `/cookies/cookie.go`. 


The library can be used in two modes: 

- `OIDC Redirect mode`: Provides the redirect functionality for the OICS flow
- `Token validation mode`: Provides a middleware for token validation

In the examples section below more information is provided. 

## Installation

First, install the GAuth package:
```bash
go get github.com/COSSAS/gauth
```
## Using gauth 


### Required Environment Variables for Basic Validation

For OIDC authentication:
- `OIDC_ISSUER`: OIDC provider URL
- `OIDC_CLIENT_ID`: Application client ID
- `OIDC_CLIENT_SECRET`: Application client secret (for redirect mode)

### Required Additional Environment variables for OIDC flow. 

- `OIDC_REDIRECT_URL`: "http://localhost:8081/auth/soarca_gui/callback"
- `COOKIE_SECRET_KEY`: "SOME_COOKIE_SECRET" #openssl rand -base64 32  or head -c 32 /dev/urandom | base64 # OPTIONAL
- `OIDC_SKIP_TLS_VERIFY`: Set to `true` for development (not recommended for production)


### OIDC functionality:

- `gauth.OIDCRedirectToLogin(c *gin.Context)`: redirect unauthenticated users to OIDC login
- `gauth.OIDCCallBack(c *gin.Context, "/dashboard")`: handle OIDC provider callback after authentication
- `gauth.Logout(c *gin.Context, "/login")`: logout route to clear session and redirect

### Middleware functionality:

`gauth.LoadAuthContext()`: Attempts to authenticate the user via session cookie or bearer token
`gauth.Middleware([]string)`:
- Ensures the user is authenticated
- Optional group-based authorization
- Passes if no groups are specified
- Requires user to be in ALL specified groups


## examples

Examples are located in the `/examples/` directory. Real life implementation can be found here: <To be added>

### OIDC Redirect Mode example:

#### Basic OIDC Authentication
- `examples/basic/main.go`: Demonstrates OIDC authentication configuration using:
  - Default configuration
  - Login and callback routes
  - Protected routes with middleware
  - Logout functionality


## Security Considerations

- Always use `HTTPS` in production
- Set `OIDC_SKIP_TLS_VERIFY` to false
- Manage environment variables securely
- Currently JWT-tokens are stored encrypted on the client-side. 
