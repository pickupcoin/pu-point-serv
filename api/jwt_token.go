package api

import (
	"github.com/dgrijalva/jwt-go"
	"net/http"
)


func (s *ApiServer) VerifyToken(accessToken string) (*jwt.Token, error) {
	return nil, nil
}

func (s *ApiServer) TokenValid(accessToken string) (*jwt.Token,error) {
	return nil, nil
}


func (s *ApiServer) CheckAPIJwtToken(r *http.Request, requestURI string) (bool,string) {
	return true, ""
}

func (s *ApiServer) CheckJwtToken(r *http.Request, requestURI string) (bool,string) {
	return true, ""
}

func (s *ApiServer) CreateToken(userName, access string, expirationSec int64) (string, error) {
	return "token", nil
}

func (s *ApiServer) CreateCorpToken(id, gameId, access string, expirationMin int64) (string, error) {
	return "token", nil
}


func (s *ApiServer) CreateJwtToken(userId int64, access string, expirationSec int64) (string, string, error) {
	return "token", "refreshToken", nil
}
