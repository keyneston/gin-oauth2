// Package discord provides you access to Discord's OAuth2
// infrastructure.
package generic

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/gob"
	"fmt"
	"net/http"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/golang/glog"

	"github.com/google/go-github/github"
	"golang.org/x/oauth2"
)

type Endpoint struct {
	conf    *oauth2.Config
	state   string // TODO: replace this with a signed token
	store   sessions.Store
	authKey string
}

type SetupInput struct {
	OAuthConfig  *oauth2.Config
	SessionStore sessions.Store

	// AuthKey is the key used to store the auth information in the session. Defaults to: "auth"
	AuthKey string
}

func randToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		glog.Fatalf("[Gin-OAuth] Failed to read rand: %v\n", err)
	}
	return base64.StdEncoding.EncodeToString(b)
}

func Setup(input SetupInput) *Endpoint {
	if input.AuthKey == "" {
		input.AuthKey = "auth"
	}

	return &Endpoint{
		conf:    input.OAuthConfig,
		store:   input.SessionStore,
		authKey: input.AuthKey,
	}
}

func (e *Endpoint) Session(name string) gin.HandlerFunc {
	return sessions.Sessions(name, e.store)
}

func (e *Endpoint) LoginHandler(ctx *gin.Context) {
	state := randToken()
	session := sessions.Default(ctx)
	session.Set("state", state)
	session.Save()
	ctx.Writer.Write([]byte("<html><title>Golang Github</title> <body> <a href='" + e.GetLoginURL(state) + "'><button>Login with GitHub!</button> </a> </body></html>"))
}

func (e *Endpoint) GetLoginURL(state string) string {
	return e.conf.AuthCodeURL(state)
}

type AuthUser struct {
	Login   string `json:"login"`
	Name    string `json:"name"`
	Email   string `json:"email"`
	Company string `json:"company"`
	URL     string `json:"url"`
}

func init() {
	gob.Register(AuthUser{})
}

func (e *Endpoint) Auth() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		var (
			ok       bool
			authUser AuthUser
			user     *github.User
		)

		// Handle the exchange code to initiate a transport.
		session := sessions.Default(ctx)
		mysession := session.Get(e.authKey)
		if authUser, ok = mysession.(AuthUser); ok {
			ctx.Set("user", authUser)
			ctx.Next()
			return
		}

		retrievedState := session.Get("state")
		if retrievedState != ctx.Query("state") {
			ctx.AbortWithError(http.StatusUnauthorized, fmt.Errorf("Invalid session state: %s", retrievedState))
			return
		}

		// TODO: oauth2.NoContext -> context.Context from stdlib
		tok, err := e.conf.Exchange(oauth2.NoContext, ctx.Query("code"))
		if err != nil {
			ctx.AbortWithError(http.StatusBadRequest, fmt.Errorf("Failed to do exchange: %v", err))
			return
		}
		client := github.NewClient(e.conf.Client(oauth2.NoContext, tok))
		user, _, err = client.Users.Get(oauth2.NoContext, "")
		if err != nil {
			ctx.AbortWithError(http.StatusBadRequest, fmt.Errorf("Failed to get user: %v", err))
			return
		}

		// save userinfo, which could be used in Handlers
		authUser = AuthUser{
			Login: *user.Login,
			Name:  *user.Name,
			URL:   *user.URL,
		}
		ctx.Set("user", authUser)

		// populate cookie
		session.Set(e.authKey, authUser)
		if err := session.Save(); err != nil {
			glog.Errorf("Failed to save session: %v", err)
		}
	}
}
