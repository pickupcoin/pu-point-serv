package google

import (
	"crypto/rand"
	"encoding/base64"
	"github.com/pickupcoin/pu-point-serv/auth"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

var (
	OAuthConf *oauth2.Config
)

func InitAuth(ClientID string,ClientSecret string ) {
	OAuthConf = &oauth2.Config{
		ClientID:     ClientID,
		ClientSecret: ClientSecret,
		RedirectURL:  auth.CallBackURL,
		Scopes:       []string{auth.ScopeEmail, auth.ScopeProfile},
		Endpoint:     google.Endpoint,
	}
}

// state 값과 함께 Google 로그인 링크 생성
func GetLoginURL(state string) string {
	return OAuthConf.AuthCodeURL(state)
}

// 랜덤 state 생성기
func RandToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.StdEncoding.EncodeToString(b)
}