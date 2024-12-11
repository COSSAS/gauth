
# Authentik OAuth Token Retrieval Client (M2M)

This repository provides an example implementation of a Machine-to-Machine (M2M) application using the [Authentik OAuth2 Client Credentials](https://docs.goauthentik.io/docs/add-secure-apps/providers/oauth2/client_credentials) provider.

## Configuration

### Environment Variables

The following environment variables must be set to configure the application:

- **`BASE_URL`**:  
  Base URL of the authentication server.  
  *Default*: `https://localhost:9443`  
  *Example*: `https://your-auth-server.com`

- **`CLIENT_ID`**:  
  OAuth client identifier.  
  *Required* (no default value).  
  *Example*: `WxUcBMGZdI7c0e5oYp6mYdEd64acpXSuWKh8zBH5`

- **`SERVICE_ACCOUNT`**:  
  Service account username.  
  *Required* (no default value).  
  *Example*: `test2test`

- **`SERVICE_TOKEN`**:  
  Service account password/token.  
  *Required* (no default value).  
  *Example*: `2Dzvbs5O7wjfaUj1k1YSqctRgVA5hDtsi18xIrmKeIn1pV0rn4G5nuuFQUwH`

- **`SKIP_TLS_VERIFY`**:  
  Disable TLS certificate verification.  
  *Default*: `false`

## Usage

### Setting Environment Variables

Set the required environment variables before running the application. For example:

```bash
export BASE_URL=https://localhost:9443
export CLIENT_ID=WxUcBMGZdI7c0e5oYp6mYdEd64acpXSuWKh8zBH5
export SERVICE_ACCOUNT=test2test
export SERVICE_TOKEN=2Dzvbs5O7wjfaUj1k1YSqctRgVA5hDtsi18xIrmKeIn1pV0rn4G5nuuFQUwH
export SKIP_TLS_VERIFY=true
```

## Running the script

Run the script using the following command:

`go run main.go`

Example Output:

When the application is successfully run, you will see output similar to the following:

Access Token: <retrieved-access-token>
Token Type: Bearer
Expires In: 3600 seconds

The retrieved access token can then be used for authorized access to other resources.

For more details, refer to the Authentik Documentation.

This README ensures clarity and provides copyable Markdown for easy use in your repository. It explicitly mentions that the implementation is for M2M (Machine-to-Machine) applications.
