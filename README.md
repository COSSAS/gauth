# gauth

> [!NOTE]
> The implemenation only has been tested with the Authentik Auth provider. More information can be found [here](https://goauthentik.io/)

An auth OIDC-based implemenation for SOARCA based on the Gin framework.

Gauth uses encrypted stored cookies for storing the jwt-token client-side. For more information on secure cookies we refer to [Gorilla](https://github.com/gorilla/sessions). By default the life time of a stored session cookie is set to 8 hours, see `COOKIE_LIFETIME` under `/cookies/cookie.go`. 


The library can be used in two modes: 

- OIDC Redirect mode: Provides the redirect functions for the OICS flow
- Token validation mode: Provides a middleware for token validation

In the examples section more information is provided. 

## Installation

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


- OIDC_REDIRECT_URL: "http://localhost:8081/auth/soarca_gui/callback"
- COOKIE_SECRET_KEY: "SOME_COOKIE_SECRET" #openssl rand -base64 32  or head -c 32 /dev/urandom | base64 # OPTIONAL
- OIDC_SKIP_TLS_VERIFY: Set to true for development (not recommended for production)

## examples

Examples are located in the `/examples/` directory. Real life implementation can be found here: <To be added>



### OIDC Redirect Examples

#### Basic OIDC Authentication
- `examples/basic/main.go`: Demonstrates OIDC authentication configuration using:
  - Default configuration
  - Login and callback routes
  - Protected routes with middleware
  - Logout functionality

### Configuration Modes

- `DefaultConfig()`: Basic verification mode
- `OIDCRedirectConfig()`: Full redirect authentication mode
