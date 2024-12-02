# gauth

> [!NOTE]
> The implemenation only has been tested with the Authentik Auth provider. More information can be found [here](https://goauthentik.io/)

An auth implemenation for SOARCA based on the Gin framework.

Gauth uses encrypted stored cookies for storing the jwt-token client-side. For more information on secure cookies we refer to [Gorilla](https://github.com/gorilla/sessions). By default the life time of a stored session cookie is set to 8 hours, see `COOKIE_LIFETIME` under `/cookies/cookie.go`. 

## Installation

```bash
go get github.com/COSSAS/gauth
```

## Using gauth 

### Required Environment Variables

For OIDC authentication:
- `OIDC_ISSUER`: OIDC provider URL
- `OIDC_CLIENT_ID`: Application client ID
- `OIDC_CLIENT_SECRET`: Application client secret (for redirect mode)


## examples

Examples are located in the `/examples/basic` directory.

### Basic OIDC Redirect Examples

#### Basic OIDC Authentication
- `examples/basic/main.go`: Demonstrates OIDC authentication configuration using:
  - Default configuration
  - Login and callback routes
  - Protected routes with middleware
  - Logout functionality

### Configuration Modes

- `DefaultConfig()`: Basic verification mode
- `OIDCRedirectConfig()`: Full redirect authentication mode
