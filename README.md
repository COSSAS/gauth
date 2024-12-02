# gauth

> [!NOTE]  
> The implemenation only has been tested with the Authentik Auth provider. More information can be found [here](https://goauthentik.io/)

An auth implemenation for SOARCA.

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


## Examples


### Location
Examples are located in the `/examples/basic` directory.

### Available Examples

#### Basic OIDC Authentication
- `examples/basic/main.go`: Demonstrates OIDC authentication configuration using:
  - Default configuration
  - Login and callback routes
  - Protected routes with middleware
  - Logout functionality

### Configuration Modes

- `DefaultConfig()`: Basic verification mode
- `OIDCRedirectConfig()`: Full redirect authentication mode
