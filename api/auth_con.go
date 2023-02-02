package api

import (
	"encoding/json"
	"fmt"
	"github.com/pickupcoin/pu-point-serv/auth"
	gauth "github.com/pickupcoin/pu-point-serv/auth/google"
	"github.com/pickupcoin/pu-point-serv/storage/mysql"
	"github.com/pickupcoin/pu-point-serv/util"
	"golang.org/x/oauth2"
	"io/ioutil"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"
)

func (s *ApiServer) AuthenticateIndex(w http.ResponseWriter, r *http.Request) {
	var (
		code string
		acc_flag bool
	)
	switch r.Method {
	case "GET":
		code = r.FormValue("code")
	case "POST":
		var valueAuthGoogle ValueAuthGoogleParam
		if err := json.NewDecoder(r.Body).Decode(&valueAuthGoogle); err != nil {
			log.Printf("failed to Decode: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		code = valueAuthGoogle.Code
	default:
		fmt.Fprintf(w, "Sorry, only GET and POST methods are supported.")
		return
	}

	if code == "" {
		s.ServerApiError(w, r,http.StatusOK, 21001, "code not found!")
		return
	}

	// account가 널이 아니라면 있는지 검사 한다.

	token, err := gauth.OAuthConf.Exchange(oauth2.NoContext, code)
	if err != nil {
		fmt.Println(code)
		s.ServerApiError(w, r,http.StatusOK, 21002, err.Error())
		return
	}

	client := gauth.OAuthConf.Client(oauth2.NoContext, token)
	userInfoResp, err := client.Get(auth.UserInfoAPIEndpoint)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	defer userInfoResp.Body.Close()
	userInfo, err := ioutil.ReadAll(userInfoResp.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	var authUser GUser
	json.Unmarshal(userInfo, &authUser)

	// 디비 입력
	userId, rowsAffected := s.dbAuth.CreatePlatData(authUser.Sub, "google", "id")
	if rowsAffected == 0 || userId <= 0 {
		// 입력 실패. 데이타 확인 필요
		fmt.Printf("CreatePlatData Failed: rowsAffected:%v userId:%v\n", rowsAffected, userId)
		return
	}

	var tokenExp = basicDayTokenExpiration
	// Token Issuance
	jwtToken, refreshToken, _ := s.CreateJwtToken(userId, "app", tokenExp)	// api로 고정함.

	var (
		WalletAddr, PrivateKey, PickUpId, Email string
		byPrivateKey []byte
	)

	if rowsAffected == 1 {
		// 키값과 지값을 생성해야 된다.
		// 지갑 주소를 만들자
		start := time.Now()

		PrivateKey, WalletAddr = s.CreateWallet()
		byPrivateKey, _ = util.AesEncrypt([]byte("01234567890123456789012345678912"), []byte(PrivateKey))
		fmt.Printf("%v %v %v\n",PrivateKey, WalletAddr, byPrivateKey)
		fmt.Println(time.Since(start))

		// 개인 키값 생성.
		bytePickUpId, _ := util.AesEncrypt([]byte("01234567890123456789012345678912"), []byte(strconv.FormatInt(userId, 10)))
		PickUpId = string(bytePickUpId)
		Email = authUser.Email

		//// account가 널이면 안됨
		//// account가 이미 들어가 있는지 검사해야된다.
		//if util.IsValidUsername(account) {
		//	// account가 제대로 안들어가 있다
		//	fmt.Printf("IsValidUsername Failed: Account is not properly entered account:%v\n", account)
		//	return
		//}

		// 지값 주소와 개인 키값을 디비에 넣는다.
		err = s.dbAuth.CreateUserData(userId, PickUpId, WalletAddr, byPrivateKey, authUser.Email)
		if err != nil {
			fmt.Printf("CreateUserData Failed: insert failure userId:%v PickUpId:%v WalletAddr:%v PrivateKey:%v authUser.Email:%v\n", userId, PickUpId, WalletAddr, PrivateKey, authUser.Email)
			return
		}
	} else {
		// 유저의 데이타를 읽어 와야 한다.
		_, PickUpId, WalletAddr, byPrivateKey, Email, err = s.dbAuth.GetUserData(userId)
		if err != nil {
			// No user data?
			fmt.Printf("GetUserData Failed: user_data not found. userId:%v\n", userId)
			return
		}

		acc_flag, _, _, err = s.dbAuth.GetUser(userId)
		if err != nil {
			// No user data?
			fmt.Printf("GetUser Failed: user not found. userId:%v\n", userId)
			return
		}

		// byPrivateKey, _ = util.AesDecrypt([]byte("01234567890123456789012345678912"), byPrivateKey)
	}

	// 토큰을 저장 한다.
	err = s.dbAuth.InsertUserToken(userId, jwtToken, refreshToken)
	if err != nil {
		fmt.Printf("InsertUserToken Failed: update failure userId:%v jwtToken:%v refreshToken:%v\n", userId, jwtToken, refreshToken)
		return
	}

	cookie := new(http.Cookie)
	cookie.Name = "access-token"
	cookie.Value = jwtToken
	cookie.HttpOnly = false
	cookie.Expires = time.Now().Add(time.Duration(tokenExp))

	http.SetCookie(w, cookie)

	w.WriteHeader(http.StatusOK)
	err = json.NewEncoder(w).Encode(map[string]interface{} {
		"status":      "1",
		"sub":         authUser.Sub,
		"picture":     authUser.Picture,
		"email":       Email,
		"locale":      authUser.Locale,
		"code":        code,
		"token":       jwtToken,
		"refresh_token": refreshToken,
		"user_id":     userId,
		"pick_id":     PickUpId,
		"wallet_addr": WalletAddr,
		"exist_acc": acc_flag,
	})
	if err != nil {
		log.Println("Error serializing API response: ", err)
	}
}



var mapVersion []*mysql.VersionInfo

func (s *ApiServer) GetVersionIndex(w http.ResponseWriter, r *http.Request) {
	if mapVersion == nil {
		tmpVersion, err := s.dbAuth.GetVersion()
		if err != nil {
			return
		}
		mapVersion = tmpVersion
	}

	w.WriteHeader(http.StatusOK)
	err := json.NewEncoder(w).Encode(map[string]interface{}{
		"status": "1",
		"list":   mapVersion,
	})
	if err != nil {
		log.Println("Error serializing API response: ", err)
	}
}

var mapServerStatus []*mysql.ServerStatus

func (s *ApiServer) GetServStatusIndex(w http.ResponseWriter, r *http.Request) {
	if mapServerStatus == nil {
		tmpServerStatus, err := s.dbAuth.GetServerStatus()
		if err != nil {
			return
		}
		mapServerStatus = tmpServerStatus
	}

	w.WriteHeader(http.StatusOK)
	err := json.NewEncoder(w).Encode(map[string]interface{}{
		"status": "1",
		"list":   mapServerStatus,
	})
	if err != nil {
		log.Println("Error serializing API response: ", err)
	}
}



// 게임에 유저의 정보(로그인)를 얻어 온다.
func (s *ApiServer) CorpUserGetPointIndex(w http.ResponseWriter, r *http.Request) {

	var (
		valueCorp ValueUserDataParam
	)
	switch r.Method {
	case "GET":
		return
	case "POST":
		if err := json.NewDecoder(r.Body).Decode(&valueCorp); err != nil {
			log.Printf("failed to Decode: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
	default:
		fmt.Fprintf(w, "Sorry, only GET and POST methods are supported.")
		return
	}

	// validation data
	strCorpId := r.Header.Get("user_id")
	corpId, _ := strconv.ParseInt(strCorpId, 10, 64)

	//strGameId := r.Header.Get("game_id")
	//gameId, _ := strconv.ParseInt(strGameId, 10, 64)

	// pick_id를 풀어서 user_id를 얻어 낸다.

	decryptUserKey, err := util.AesDecrypt([]byte("01234567890123456789012345678912"), []byte(valueCorp.UserKey))
	if err != nil {
		log.Println("user_key:AesDecrypt is wrong: ", err)
		s.ServerApiError(w, r, http.StatusOK, ResultCodeUserKeyErr, "user_key is wrong")
		return
	}
	strUserKey := string(decryptUserKey)
	splitUserKey := strings.Split(strUserKey,":")
	if len(splitUserKey) != 2 {
		// user_key is invalid.
		log.Println("user_key:splitUserKey is wrong: ", err)
		s.ServerApiError(w, r, http.StatusOK, ResultCodeUserKeyErr, "user_key is wrong")
		return
	}

	corpIdByKey, err := strconv.ParseInt(splitUserKey[0], 10, 64)
	if err != nil {
		// user_key is invalid.
		log.Println("user_key:corpIdByKey is wrong: ", err)
		s.ServerApiError(w, r, http.StatusOK, ResultCodeUserKeyErr, "user_key is wrong")
		return
	}

	// corpId가 유저 키값의 corpId랑 같아야 한다.
	if corpId != corpIdByKey {
		// The company key values are different.
		log.Println("The company key values are different.: ", err)
		s.ServerApiError(w, r, http.StatusOK, ResultCodeUserKeyErr, "The company key values are different.")
		return
	}

	strUserId := splitUserKey[1]
	userIdByKey, err := strconv.ParseInt(splitUserKey[1], 10, 64)
	if err != nil {
		log.Println("user_key is not a number: ", err)
		s.ServerApiError(w, r, http.StatusOK, ResultCodeUserKeyErr, "user_key is wrong")
		return
	}

	// 조회
	currentPoint, _, _, _, _, _ := s.db.GetUserGamePoint(userIdByKey, corpId)

	w.WriteHeader(http.StatusOK)
	err = json.NewEncoder(w).Encode(map[string]interface{} {
		"status":   "1",
		"user_id":  strUserId,
		"points": []interface{} {
			map[string]interface{}{
				"current_point": currentPoint,
			},
		},
	})
	if err != nil {
		log.Println("Error serializing API response: ", err)
	}
}



// 게임에 유저의 정보(로그인)를 얻어 온다.
func (s *ApiServer) CorpUserLoginIndex(w http.ResponseWriter, r *http.Request) {

	var (
		valueCorp ValueCorpParam
	)
	switch r.Method {
	case "GET":
		return
	case "POST":
		if err := json.NewDecoder(r.Body).Decode(&valueCorp); err != nil {
			log.Printf("failed to Decode: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
	default:
		fmt.Fprintf(w, "Sorry, only GET and POST methods are supported.")
		return
	}

	// validation data
	strCorpId := r.Header.Get("user_id")
	corpId, _ := strconv.ParseInt(strCorpId, 10, 64)

	// pick_id를 풀어서 user_id를 얻어 낸다.

	decryptPickUpId, err := util.AesDecrypt([]byte("01234567890123456789012345678912"), []byte(valueCorp.PickId))
	if err != nil {
		log.Println("UserId가 잘못 되어있다: ", err)
		return
	}
	strUserId := string(decryptPickUpId)
	userId, err := strconv.ParseInt(strUserId, 10, 64)
	if err != nil {
		log.Println("UserId가 잘못 되어있다: ", err)
		return
	}
	fmt.Println(userId)

	// UserId로 user_data를 찾아서 pickid가 같은지 비교 하자.
	_,dbPickId,_,_,_,err := s.db.GetUserData(userId)
	if valueCorp.PickId != dbPickId {
		log.Println("PickId가 잘못되어 있다: ", err)
		return
	}

	// UserId로 유저 데이타에 토큰을 0으로 설정 한다.
	point, _, _, _, _, err := s.db.GetUserGamePoint(userId, corpId)
	if err != nil {
		// db 에러
		return
	}

	if point == "" {
		s.db.InitGamePoint(strUserId, strCorpId, 0)
		point = "0"
	}

	userKey := strCorpId+":"+strUserId
	byteUserKey, err := util.AesEncrypt([]byte("01234567890123456789012345678912"), []byte(userKey))
	if err != nil {
		log.Println("UserId가 잘못 되어있다: ", err)
		return
	}
	userKey = string(byteUserKey)

	w.WriteHeader(http.StatusOK)
	err = json.NewEncoder(w).Encode(map[string]interface{} {
		"status":   "1",
		"user_id":  strUserId,
		"user_key": userKey,
		"points": []interface{} {
			map[string]interface{}{
				"1": 11,
				"point": point,
			},
		},
	})
	if err != nil {
		log.Println("Error serializing API response: ", err)
	}
}
