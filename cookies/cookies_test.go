package cookies

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

const (
	testSecretKey     = "53481928395695659701516098079887"
	testEncryptionKey = "75757536457839383375666084204512"
)

func setupTest() (*CookieJar, *gin.Context, *httptest.ResponseRecorder) {
	cookieJar := NewCookieJar([]byte(testSecretKey), []byte(testEncryptionKey))
	writer := httptest.NewRecorder()
	ginContext, _ := gin.CreateTestContext(writer)
	ginContext.Request, _ = http.NewRequest(http.MethodGet, "/", nil)
	return cookieJar, ginContext, writer
}

func TestSetCallBackState(t *testing.T) {
	cookieJar, ginContext, writer := setupTest()

	stateCookie, err := NewCookie(State, "test-state")
	assert.NoError(t, err)

	err = cookieJar.Store(ginContext, stateCookie)
	assert.NoError(t, err)

	cookies := writer.Result().Cookies()
	assert.NotEmpty(t, cookies, "Expected cookies to be set in the response")

	newRequest, _ := http.NewRequest(http.MethodGet, "/", nil)
	for _, cookie := range cookies {
		newRequest.AddCookie(cookie)
	}

	newWriter := httptest.NewRecorder()
	newContext, _ := gin.CreateTestContext(newWriter)
	newContext.Request = newRequest

	value, isNew, err := cookieJar.Get(newContext, State)
	assert.NoError(t, err)
	assert.False(t, isNew, "Expected existing state session")
	assert.Equal(t, "test-state", value, "Expected the state value to match 'test-state'")
}

func TestSetCallBackNonce(t *testing.T) {
	cookieJar, ginContext, writer := setupTest()

	nonceCookie, err := NewCookie(Nonce, "test-nonce")
	assert.NoError(t, err)

	err = cookieJar.Store(ginContext, nonceCookie)
	assert.NoError(t, err)

	cookies := writer.Result().Cookies()
	assert.NotEmpty(t, cookies, "Expected cookies to be set in the response")

	newRequest, _ := http.NewRequest(http.MethodGet, "/", nil)
	for _, cookie := range cookies {
		newRequest.AddCookie(cookie)
	}

	newWriter := httptest.NewRecorder()
	newContext, _ := gin.CreateTestContext(newWriter)
	newContext.Request = newRequest

	value, isNew, err := cookieJar.Get(newContext, Nonce)
	assert.NoError(t, err)
	assert.False(t, isNew, "Expected existing nonce session")
	assert.Equal(t, "test-nonce", value, "Expected the nonce value to match 'test-nonce'")
}

func TestGetStateSession(t *testing.T) {
	cookieJar, ginContext, writer := setupTest()

	// Test with no existing state
	value, isNew, err := cookieJar.Get(ginContext, State)
	assert.NoError(t, err)
	assert.True(t, isNew)
	assert.Empty(t, value)

	// Set a state
	stateCookie, err := NewCookie(State, "test-state")
	assert.NoError(t, err)
	err = cookieJar.Store(ginContext, stateCookie)
	assert.NoError(t, err)

	cookies := writer.Result().Cookies()
	assert.NotEmpty(t, cookies)

	newRequest, _ := http.NewRequest(http.MethodGet, "/", nil)
	for _, cookie := range cookies {
		newRequest.AddCookie(cookie)
	}
	newWriter := httptest.NewRecorder()
	newContext, _ := gin.CreateTestContext(newWriter)
	newContext.Request = newRequest

	value, isNew, err = cookieJar.Get(newContext, State)
	assert.NoError(t, err)
	assert.False(t, isNew)
	assert.Equal(t, "test-state", value)
}

func TestGetUserToken(t *testing.T) {
	cookieJar, ginContext, writer := setupTest()

	// Test with no existing token
	value, isNew, err := cookieJar.Get(ginContext, Token)
	assert.NoError(t, err)
	assert.True(t, isNew)
	assert.Empty(t, value)

	// Set a token
	tokenCookie, err := NewCookie(Token, "test-token")
	assert.NoError(t, err)
	err = cookieJar.Store(ginContext, tokenCookie)
	assert.NoError(t, err)

	cookies := writer.Result().Cookies()
	assert.NotEmpty(t, cookies)

	newRequest, _ := http.NewRequest(http.MethodGet, "/", nil)
	for _, cookie := range cookies {
		newRequest.AddCookie(cookie)
	}
	newWriter := httptest.NewRecorder()
	newContext, _ := gin.CreateTestContext(newWriter)
	newContext.Request = newRequest

	value, isNew, err = cookieJar.Get(newContext, Token)
	assert.NoError(t, err)
	assert.False(t, isNew)
	assert.Equal(t, "test-token", value)
}

func TestSetUserToken(t *testing.T) {
	cookieJar, ginContext, writer := setupTest()

	tokenCookie, err := NewCookie(Token, "test-token")
	assert.NoError(t, err)
	assert.NoError(t, err)
	err = cookieJar.Store(ginContext, tokenCookie)

	cookies := writer.Result().Cookies()
	assert.NotEmpty(t, cookies)

	newRequest, _ := http.NewRequest(http.MethodGet, "/", nil)
	for _, cookie := range cookies {
		newRequest.AddCookie(cookie)
	}
	newWriter := httptest.NewRecorder()
	newContext, _ := gin.CreateTestContext(newWriter)
	newContext.Request = newRequest

	value, isNew, err := cookieJar.Get(newContext, Token)
	assert.NoError(t, err)
	assert.False(t, isNew)
	assert.Equal(t, "test-token", value)
}

func TestDeleteStateSession(t *testing.T) {
	cookieJar, ginContext, _ := setupTest()

	stateCookie, err := NewCookie(State, "test-state")
	assert.NoError(t, err)
	err = cookieJar.Store(ginContext, stateCookie)
	assert.NoError(t, err)

	err = cookieJar.Delete(ginContext, State)
	assert.NoError(t, err)

	value, isNew, err := cookieJar.Get(ginContext, State)
	assert.NoError(t, err)
	assert.True(t, isNew)
	assert.Empty(t, value)
}

func TestDeleteNonceSession(t *testing.T) {
	cookieJar, ginContext, _ := setupTest()

	nonceCookie, err := NewCookie(Nonce, "test-nonce")
	assert.NoError(t, err)
	err = cookieJar.Store(ginContext, nonceCookie)
	assert.NoError(t, err)

	err = cookieJar.Delete(ginContext, Nonce)
	assert.NoError(t, err)

	value, isNew, err := cookieJar.Get(ginContext, Nonce)
	assert.NoError(t, err)
	assert.True(t, isNew)
	assert.Empty(t, value)
}
