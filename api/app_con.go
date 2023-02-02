package api

import (
	"encoding/json"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/pickupcoin/pu-point-serv/util"
	"log"
	"net/http"
	"strconv"
	"strings"
)

func (s *ApiServer) ActionCreateAccount(w http.ResponseWriter, r *http.Request) {
	userId, _ := strconv.ParseInt(r.Header.Get("user_id"), 10, 64)

	var (
		account string
		pass    string
	)

	switch r.Method {
	case "GET":
		account = r.FormValue("account")
		pass = r.FormValue("password")
	case "POST":
		var valueAuthGoogle ValueAuthGoogleParam
		if err := json.NewDecoder(r.Body).Decode(&valueAuthGoogle); err != nil {
			log.Printf("failed to Decode: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		account = valueAuthGoogle.Account
		pass = valueAuthGoogle.Password
	default:
		fmt.Fprintf(w, "Sorry, only GET and POST methods are supported.")
		return
	}

	// The account format is incorrect
	if util.IsValidUsername(account) == false {
		s.ServerApiError(w, r, http.StatusOK, ResultCodeIncorrectAccount, "The account format is incorrect")
		return
	}

	if len(pass) <= 0 {
		s.ServerApiError(w, r, http.StatusOK, ResultCodeIncorrectPassword, "The password format is incorrect")
		return
	}


	// 유저 아이디가 이미 있다면 생성 할수 없다.
	flag, tmpAccount, _, _ := s.db.GetUser(userId)
	if flag == false {
		//
		activateCode := util.RandStringBytesMaskImprSrc(24)
		println(activateCode)
		byPass, _ := util.AesEncrypt([]byte(activateCode),[]byte(pass))
		// 유저 id를
		createFlag, err := s.db.CreateUser(userId, account, string(byPass), activateCode)
		if err != nil || createFlag == false {
			// 만드는데 실패 하였다.
			s.ServerApiError(w, r, http.StatusOK, ResultCodeExistName, "id already exists")
			return
		}
	} else {
		s.ServerApiError(w, r, http.StatusOK, ResultCodeExistAccount, "You have already created an account: " + tmpAccount)
		return
	}

	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Headers", "*")
	w.Header().Set("Cache-Control", "no-cache")

	w.WriteHeader(http.StatusOK)
	err := json.NewEncoder(w).Encode(map[string]interface{} {
		"status":    "1",
		"account": account,
	})
	if err != nil {
		log.Println("Error serializing API response: ", err)
	}
}



func (s *ApiServer) ActionUserLogout(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Headers", "*")
	w.Header().Set("Cache-Control", "no-cache")

	userId, err := strconv.ParseInt(r.Header.Get("user_id"), 10, 64)
	if err != nil {
		s.ServerError(w, r, "invalid token")
		return
	}

	// 유저의 refresh 토큰을 전부 못쓰게 만든다.
	s.db.DeleteUserTokenAll(userId)

	reply := make(map[string]interface{})
	reply["status"] = "1"
	w.WriteHeader(http.StatusOK)
	err = json.NewEncoder(w).Encode(reply)
	if err != nil {
		log.Println("Error serializing API response: ", err)
	}
}



func (s *ApiServer) ActionUserRefreshToken(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Headers", "*")
	w.Header().Set("Cache-Control", "no-cache")

	userId, err := strconv.ParseInt(r.Header.Get("user_id"), 10, 64)
	if err != nil {
		s.ServerError(w, r, "invalid token")
		return
	}

	idToken := r.URL.Query().Get("api_key")

	if idToken == "" {
		cookie := r.Header.Get("Authorization")

		if len(cookie) <= 0 {
			// 올수 없다.
			return
		}
		splitAuth := strings.Split(cookie, " ")
		lastIndex := len(splitAuth) - 1
		if lastIndex < 0 || len(splitAuth[lastIndex]) <= 0 {
			return
		}
		idToken = splitAuth[lastIndex]

		//idToken, err = s.backend.GetAPIToken(idToken)
		//if err != nil || idToken == ""{
		//	return false, "unauthorized: none api key"
		//}
	}

	var refresh_token string
	switch r.Method {
	case "GET":
		return
	case "POST":
		var valueTokenParam ValueTokenParam
		if err := json.NewDecoder(r.Body).Decode(&valueTokenParam); err != nil {
			log.Printf("failed to Decode: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		refresh_token = valueTokenParam.RefreshToken
	default:
		fmt.Fprintf(w, "Sorry, only GET and POST methods are supported.")
		return
	}

	// 유저가 보낸 리프레쉬 토큰이 현재의 리프레쉬 토큰과 같은지 확인 한다.
	refreshToken, _, err := s.db.GetUserToken(userId, idToken)
	if err != nil {
		s.ServerError(w, r, "invalid token")
		return
	}

	if refreshToken != refresh_token {
		s.ServerError(w, r, "invalid token")
		return
	}

	// 리프레쉬 토큰의 유효성 검사를 한다.
	token, err := s.TokenValid(idToken)
	if err != nil {
		s.ServerError(w, r, "unauthorized: " + err.Error())
		return
	}

	access, ok := token.Claims.(jwt.MapClaims)["access"]
	if !ok {
		s.ServerError(w, r, "unauthorized: nothing access")
		return
	}

	var tokenExp = basicDayTokenExpiration
	// 토큰 재발급
	jwtToken, refreshToken, _ := s.CreateJwtToken(userId, access.(string), tokenExp)

	// 기존 리프레쉬 토큰을 삭제 한다. (옵션)
	// 기존 것도 살려 준다.
	// s.db.DeleteUserToken(userId, idToken)

	// 재발급 토큰을 디비에 접어 넣는다.
	s.db.InsertUserToken(userId, jwtToken, refreshToken)

	reply := make(map[string]interface{})
	reply["status"] = "1"
	reply["token"] = jwtToken
	reply["refresh_token"] = refreshToken
	w.WriteHeader(http.StatusOK)
	err = json.NewEncoder(w).Encode(reply)
	if err != nil {
		log.Println("Error serializing API response: ", err)
	}
}



func (s *ApiServer) ActionWalletEth(w http.ResponseWriter, r *http.Request) {
	userId, err := strconv.ParseInt(r.Header.Get("user_id"), 10, 64)
	if err != nil {
		s.ServerError(w, r, "invalid token")
		return
	}

	var valueUserData ValueUserDataParam
	switch r.Method {
	case "GET":
		return
	case "POST":

		if err := json.NewDecoder(r.Body).Decode(&valueUserData); err != nil {
			log.Printf("failed to Decode: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
	default:
		fmt.Fprintf(w, "Sorry, only GET and POST methods are supported.")
		return
	}

	// 유저의 주소를 얻어 온다
	ethWalletAddress := valueUserData.WalletAddress
	if ethWalletAddress == "" {
		_, _, tmpEthWalletAddress, _, _, _ := s.db.GetUserData(userId)
		ethWalletAddress = tmpEthWalletAddress
	}

	balance, err := s.rpc().GetBalanceTag(ethWalletAddress,"latest")
	if err != nil {
		return
	}

	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Headers", "*")
	w.Header().Set("Cache-Control", "no-cache")

	reply := make(map[string]interface{})
	reply["status"] = "1"
	reply["eth_address"] = ethWalletAddress
	reply["eth_balance"] = balance
	w.WriteHeader(http.StatusOK)
	err = json.NewEncoder(w).Encode(reply)
	if err != nil {
		log.Println("Error serializing API response: ", err)
	}
}
