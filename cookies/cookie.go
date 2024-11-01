package cookies

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/sessions"
)

const (
	CALLBACK_STATE = "soarca_gui_state"
	CALLBACK_NONCE = "soarca_gui_nonce"
	USER_TOKEN     = "soarca_token"
)

type CookieType uint

const (
	State CookieType = iota
	Nonce
	Token
)

type Cookie struct {
	CookieType CookieType
	Value      string
}

func (cookie *Cookie) SetCookieValue(value string) {
	cookie.Value = value
}

type ICookieJar interface {
	Store(ginContext *gin.Context, cookie Cookie) error
	Get(ginContext *gin.Context, cookieType CookieType) (value string, isNew bool, err error)
	Delete(ginContext *gin.Context, cookieType CookieType) error
}
type CookieJar struct {
	store sessions.Store
}

func NewCookie(cookieType CookieType, value string) (Cookie, error) {
	if value == "" {
		return Cookie{}, fmt.Errorf("cookie value cannot be empty")
	}

	switch cookieType {
	case State, Nonce, Token:
	default:
		return Cookie{}, fmt.Errorf("invalid cookie type: %d", cookieType)
	}

	return Cookie{
		CookieType: cookieType,
		Value:      value,
	}, nil
}

func NewCookieJar(secret []byte, encryptionKey []byte) *CookieJar {
	return &CookieJar{store: sessions.NewCookieStore(secret, encryptionKey)}
}

func (jar *CookieJar) Delete(ginContext *gin.Context, cookieType CookieType) error {
	var sessionName string
	var keyName string
	switch cookieType {
	case Nonce:
		sessionName = CALLBACK_NONCE
		keyName = "nonce"
	case State:
		sessionName = CALLBACK_STATE
		keyName = "state"
	case Token:
		sessionName = USER_TOKEN
		keyName = "token"
	default:
		return errors.New("no correct cookie type has been supplied, should be of type: Nonce | State | Token")
	}

	session, err := jar.store.Get(ginContext.Request, sessionName)
	if err != nil {
		return err
	}

	session.Options.MaxAge = -1
	delete(session.Values, keyName)

	return session.Save(ginContext.Request, ginContext.Writer)
}

func (jar *CookieJar) Store(ginContext *gin.Context, cookie Cookie) error {
	var session *sessions.Session
	var err error

	switch cookie.CookieType {
	case Nonce:
		session, err = jar.store.Get(ginContext.Request, CALLBACK_NONCE)
		if err != nil {
			return err
		}
		session.Values["nonce"] = cookie.Value
		session.Options.MaxAge = 60 * 5
	case State:
		session, err = jar.store.Get(ginContext.Request, CALLBACK_STATE)
		if err != nil {
			return err
		}
		session.Values["state"] = cookie.Value
		session.Options.MaxAge = 60 * 5
	case Token:
		session, err = jar.store.Get(ginContext.Request, USER_TOKEN)
		if err != nil {
			return err
		}
		session.Values["token"] = cookie.Value
		session.Options.MaxAge = 60 * 60 * 8
	default:
		return errors.New("no correct cookie type has been supplied, should be of type: Nonce | State | Token")
	}

	session.Options.Path = "/"
	session.Options.Secure = ginContext.Request.TLS != nil
	session.Options.SameSite = http.SameSiteLaxMode

	return session.Save(ginContext.Request, ginContext.Writer)
}

func (jar *CookieJar) Get(ginContext *gin.Context, cookieType CookieType) (value string, isNew bool, err error) {
	var sessionName string
	var keyName string
	switch cookieType {
	case Nonce:
		sessionName = CALLBACK_NONCE
		keyName = "nonce"
	case State:
		sessionName = CALLBACK_STATE
		keyName = "state"
	case Token:
		sessionName = USER_TOKEN
		keyName = "token"
	default:
		return "", false, errors.New("no correct cookie type has been supplied, should be of type: Nonce | State | Token")
	}

	session, err := jar.store.Get(ginContext.Request, sessionName)
	if err != nil {
		return "", true, nil
	}

	val, ok := session.Values[keyName]
	if !ok {
		return "", true, nil
	}

	value, ok = val.(string)
	if !ok {
		return "", false, errors.New("stored value is not a string")
	}

	return value, false, nil
}
