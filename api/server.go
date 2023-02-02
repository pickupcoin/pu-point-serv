package api

import (
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	gauth "github.com/pickupcoin/pu-point-serv/auth/google"
	"github.com/pickupcoin/pu-point-serv/hook"
	"github.com/pickupcoin/pu-point-serv/rpc"
	"github.com/pickupcoin/pu-point-serv/storage/mysql"
	"github.com/pickupcoin/pu-point-serv/storage/redis"
	"github.com/pickupcoin/pu-point-serv/types"
	"github.com/pickupcoin/pu-point-serv/types/config"
	"github.com/pickupcoin/pu-point-serv/util"
	"github.com/pickupcoin/pu-point-serv/util/plogger"
	"golang.org/x/crypto/sha3"
	"html/template"
	"log"
	"math/rand"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"github.com/rs/cors"
)

type ApiServer struct {
	config              *config.ApiConfig
	backend             *redis.RedisClient
	stats               atomic.Value
	apiModule	        map[string]*EntryActions
	db                  *mysql.Database
	dbAuth				*mysql.Database
	//rpc     			*rpc.RPCClient
	minersMu            sync.RWMutex
	apiMinersMu         sync.RWMutex
	statsIntv           time.Duration
	minerPoolTimeout    time.Duration
	minerPoolChartIntv  int64
	allowedOrigins      []string

	upstream           int32
	upstreams          []*rpc.RPCClient

	//poolChartIntv       time.Duration
	//minerChartIntv      time.Duration
}

type ActionFn func(http.ResponseWriter, *http.Request)

type Entry struct {
	actionFnName	string
	actionFn		ActionFn
	actionDesc		string
	updatedAt 		int64
}

type EntryActions struct {
	actionList map[string]*Entry
}

const (
	basicTokenExpiration = int64(900)	// 15min
	basicDayTokenExpiration = int64(86400)	// 1day
	basicMonthTokenExpiration = int64(86400*30)	// 1day
	unLimitTokenExpiration = int64(1576800000) // 50 yesr
)

func NewApiServer(cfg *config.ApiConfig, name string, backend *redis.RedisClient, db *mysql.Database, dbAuth *mysql.Database) *ApiServer {
	apiServ := &ApiServer{
		config:              cfg,
		apiModule:           make(map[string]*EntryActions),
		db:					db,
		dbAuth: 			dbAuth,
		backend:			backend,
	}

	apiServ.upstreams = make([]*rpc.RPCClient, len(cfg.Upstream))
	for i, v := range cfg.Upstream {
		apiServ.upstreams[i] = rpc.NewRPCClient(v.Name, v.Url, v.Timeout, cfg.NetId)
		log.Printf("Upstream: %s => %s", v.Name, v.Url)
	}

	actionUser := &EntryActions{
		actionList: make(map[string]*Entry),
	}
	actionUser.actionList["create"] = &Entry{
		actionFnName: "ActionCreateAccount",
		actionFn:     apiServ.ActionCreateAccount,
		updatedAt:    0,
	}
	actionUser.actionList["logout"] = &Entry{
		actionFnName: "ActionUserLogout",
		actionFn:     apiServ.ActionUserLogout,
		updatedAt:    0,
	}
	actionUser.actionList["token"] = &Entry{
		actionFnName: "ActionUserRefreshToken",
		actionFn:     apiServ.ActionUserRefreshToken,
		actionDesc: "re-issuance of expired access_tokens",
		updatedAt:    0,
	}
	actionUser.actionList["wallet/eth"] = &Entry{
		actionFnName: "ActionWalletEth",
		actionFn:     apiServ.ActionWalletEth,
		actionDesc: "Gets the balance of the Ethereum wallet.",
		updatedAt:    0,
	}

	apiServ.apiModule["user"] = actionUser

	return apiServ
}

func (s *ApiServer) Start() {
	log.Printf("Starting API on %v", s.config.Listen)

	quit := make(chan struct{})
	hooks := make(chan struct{})

	plogger.InsertLog("START API SERVER", plogger.LogTypeSystem, plogger.LogErrorNothing, 0, 0, "", "")
	hook.RegistryHook("server.go", func(name string) {
		plogger.InsertLog("SHUTDOWN API SERVER", plogger.LogTypeSystem, plogger.LogErrorNothing, 0, 0, "", "")
		close(quit)
		<- hooks
	})

	// 서버 런닝 타입에 따라 레디스에 등록한다.
	tmpServerType := strings.Split(s.config.ServerType,",")
	for _, serverTypeName := range tmpServerType {
		s.backend.InitPubSub(serverTypeName,s)
	}


	go func() {
		for {
			select {
			case <-quit:
				hooks <- struct{}{}
				return
			}
		}
	}()

	s.listen()
}

func (s *ApiServer) rpc() *rpc.RPCClient {
	i := atomic.LoadInt32(&s.upstream)
	return s.upstreams[i]
}

func (s *ApiServer) checkUpstreams() {
	candidate := int32(0)
	backup := false

	for i, v := range s.upstreams {
		if v.Check() && !backup {
			candidate = int32(i)
			backup = true
		}
	}

	if s.upstream != candidate {
		log.Printf("Switching to %v upstream", s.upstreams[candidate].Name)
		atomic.StoreInt32(&s.upstream, candidate)
	}
}

func (s *ApiServer) authenticationMiddleware (next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		//token := r.Header.Get("access-token")

		requestURL := strings.Split(r.RequestURI,"/")
		if len(requestURL) > 1 {
			//requestURL = strings.Split(requestURL[1],"?")
			switch requestURL[1] {
			case "signup","signin","token","health":
				fmt.Println(requestURL[0])
				next.ServeHTTP(w, r)
				return
			case "api","app","web","mgr":
				passed, errStr := s.CheckAPIJwtToken(r, requestURL[1])
				if !passed {
					fmt.Println("CheckJwtToken Error:",errStr)
					s.ServerError(w, r, errStr)
					return
				}
				next.ServeHTTP(w, r)
				return
			default:
				//fmt.Println(requestURL[0])
				next.ServeHTTP(w, r)
				return
			}
			passed, errStr := s.CheckJwtToken(r, requestURL[1])
			if !passed {
				fmt.Println("CheckJwtToken Error:",errStr)
				s.ServerError(w, r, errStr)
				return
			}
		} else {
			s.ServerError(w, r, "nothing page URI")
			return
		}

		origin := r.Header.Get("Origin")
		if origin == "" {
			w.Header().Set("Access-Control-Allow-Origin", "*")
		} else {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		}
		next.ServeHTTP(w, r)
	})
}


func (s *ApiServer) ServerError(w http.ResponseWriter, r *http.Request, errMsg string) {
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	origin := r.Header.Get("Origin")
	if origin == "" {
		w.Header().Set("Access-Control-Allow-Origin", "*")
	} else {
		w.Header().Set("Access-Control-Allow-Origin", origin)
		w.Header().Set("Access-Control-Allow-Credentials", "true")
	}
	//w.Header().Set("Access-Control-Allow-Header", "access-token")
	w.Header().Set("Cache-Control", "no-cache")

	w.WriteHeader(http.StatusUnauthorized)
	//w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"status": "0",
		"message": errMsg,
	})
	return
}

func (s *ApiServer) ServerApiError(w http.ResponseWriter, r *http.Request,statusCode int,status int, errMsg string) {
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	origin := r.Header.Get("Origin")
	if origin == "" {
		w.Header().Set("Access-Control-Allow-Origin", "*")
	} else {
		w.Header().Set("Access-Control-Allow-Origin", origin)
		w.Header().Set("Access-Control-Allow-Credentials", "true")
	}
	//w.Header().Set("Access-Control-Allow-Header", "access-token")
	w.Header().Set("Cache-Control", "no-cache")

	w.WriteHeader(statusCode)
	//w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"status": strconv.Itoa(status),
		"message": errMsg,
	})

	fmt.Printf("status: %v errMsg: %v\n", status, errMsg)
	return
}


func (s *ApiServer) listen() {
	r := mux.NewRouter()
	//apiRouter := r.GetRoute("api")
	//apiRouter.

	r.HandleFunc("/", s.RenderMainView)
	r.HandleFunc("/auth", s.RenderAuthView)
	r.HandleFunc("/auth/callback", s.AuthenticateIndex)
	r.HandleFunc("/auth/status", s.GetServStatusIndex)
	r.HandleFunc("/testauth", s.TestAuthenticate)

	r.HandleFunc("/corp/create", s.CreateCorp)

	r.HandleFunc("/corp/login", s.CorpLoginIndex)
	r.HandleFunc("/corp/logout", s.CorpLogOutIndex)
	r.HandleFunc("/corp/signup", s.CreateCorpIndex)
	r.HandleFunc("/api/corp/add_game", s.CorpAddGameIndex)
	r.HandleFunc("/api/corp/user/login", s.CorpUserLoginIndex)
	r.HandleFunc("/api/corp/user/logout", s.CorpUserLoginIndex)
	r.HandleFunc("/api/corp/user/addpoint", s.CorpUserAddPointIndex)
	r.HandleFunc("/api/corp/user/point", s.CorpUserGetPointIndex)

	r.HandleFunc("/token", s.GetTokenIndex).Methods("POST")

	r.HandleFunc("/app/*/*/", s.ModuleIndex)
	r.HandleFunc("/app/user/*/", s.ModuleIndex)
	r.HandleFunc("/app/user/create", s.ModuleIndex)
	r.HandleFunc("/app/user/logout", s.ModuleIndex)
	r.HandleFunc("/app/user/token", s.ModuleIndex)
	r.HandleFunc("/app/user/wallet/eth", s.ModuleIndex)

	//r.HandleFunc("/api/",)

	r.HandleFunc("/auth/google", s.AuthenticateIndex).Methods("POST")
	r.HandleFunc("/auth/version", s.GetVersionIndex).Methods("GET")

	r.HandleFunc("/health", s.Health)

	var c *cors.Cors
	s.allowedOrigins = make([]string, len(s.config.AllowedOrigins))
	if len(s.config.AllowedOrigins) > 0 {
		for i, v := range s.config.AllowedOrigins {
			s.allowedOrigins[i] = v
		}

		c = cors.New(cors.Options{
			AllowedOrigins: s.allowedOrigins,
			AllowCredentials: true,
			AllowedHeaders: []string{"access_token"},
			AllowedMethods: []string{"get","post","options"},
		})
	}

	//r.HandleFunc("/api/accounts/{login:0x[0-9a-fA-F]{40}}/{personal:0x[0-9a-fA-F]{40}}", s.AccountIndexEx)
	r.NotFoundHandler = http.HandlerFunc(notFound)
	r.Use(s.authenticationMiddleware )

	var err error
	if c != nil {
		err = http.ListenAndServe(s.config.Listen, c.Handler(r))
	} else {
		err = http.ListenAndServe(s.config.Listen, r)
	}

	if err != nil {
		log.Fatalf("Failed to start API: %v", err)
	}
}

func notFound(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	//w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Cache-Control", "no-cache")
	w.WriteHeader(http.StatusNotFound)
}

var store = sessions.NewCookieStore([]byte("secret"))

func RenderTemplate(w http.ResponseWriter, name string, data interface{}) {
	tmpl, _ := template.ParseFiles(name)
	tmpl.Execute(w, data)
}

func (s *ApiServer) RenderMainView(w http.ResponseWriter, r *http.Request) {

	RenderTemplate(w, "main.html", nil)
}

func (s *ApiServer) RenderAuthView(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "session")
	session.Options = &sessions.Options{
		Path:   "/auth",
		MaxAge: 300,
	}
	state := gauth.RandToken()
	session.Values["state"] = state
	session.Save(r, w)
	RenderTemplate(w, "auth.html", gauth.GetLoginURL(state))
}


func (s *ApiServer) CreateWallet() (privateKey, walletAddr string) {
	key, err := crypto.GenerateKey()
	if err != nil {
		log.Fatal(err)
	}

	privateKeyBytes := crypto.FromECDSA(key)
	privateKey = hexutil.Encode(privateKeyBytes)[2:]

	publicKey := key.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		log.Fatal("error casting public key to ECDSA")
	}

	publicKeyBytes := crypto.FromECDSAPub(publicKeyECDSA)
	//log.Println(hexutil.Encode(publicKeyBytes)[4:])

	//address := crypto.PubkeyToAddress(*publicKeyECDSA).Hex()
	hash := sha3.NewLegacyKeccak256()
	hash.Write(publicKeyBytes[1:])
	walletAddr = hexutil.Encode(hash.Sum(nil)[12:])
	return
}

func (s *ApiServer) TestAuthenticate(w http.ResponseWriter, r *http.Request) {


	var tokenExp = basicDayTokenExpiration
	// Token Issuance
	jwtToken, refreshToken,_ := s.CreateJwtToken(1000001, "app", tokenExp)	// api로 고정함.

	cookie := new(http.Cookie)
	cookie.Name = "access-token"
	cookie.Value = jwtToken
	cookie.HttpOnly = true
	cookie.Expires = time.Now().Add(time.Duration(tokenExp))

	http.SetCookie(w, cookie)

	w.WriteHeader(http.StatusOK)
	err := json.NewEncoder(w).Encode(map[string]interface{} {
		"status":      		"ok",
		"token":         	jwtToken,
		"refresh_token":	refreshToken,
		//"picture":     authUser.Picture,
		//"email":       Email,
		//"locale":      authUser.Locale,
		//"code":        code,
		//"token":       jwtToken,
		//"user_id":     userId,
		//"pick_id":     PickUpId,
		//"wallet_addr": WalletAddr,
	})
	if err != nil {
		log.Println("Error serializing API response: ", err)
	}
}




func (s *ApiServer) CreateCorp(w http.ResponseWriter, r *http.Request) {
	var (
		corpName string
		gameName string
	)
	switch r.Method {
	case "GET":
		corpName = r.FormValue("corp_name")
		gameName = r.FormValue("game_name")
	case "POST":
		var valueCreateCorp ValueCorpParam
		if err := json.NewDecoder(r.Body).Decode(&valueCreateCorp); err != nil {
			log.Printf("failed to Decode: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		corpName = valueCreateCorp.CorpName
		gameName = valueCreateCorp.GameName
	default:
		fmt.Fprintf(w, "Sorry, only GET and POST methods are supported.")
		return
	}


	// 회사 코드를 생성한다.
	// 개인 키값 생성.
	key, err := crypto.GenerateKey()
	if err != nil {
		fmt.Printf("CreateCorp:GenerateKey() Failed\n")
		return
	}
	byKey := crypto.FromECDSA(key)
	corpCode := hexutil.Encode(byKey)[2:]
	// 회사이름 게임 이름 입력 하자.
	// 회사 id 생성
	// 게임 id 생성
	var (
		corpId int64
		gameId int64
	)
	for true {
		corpId = rand.Int63n(time.Now().UnixNano())
		gameId = rand.Int63n(time.Now().UnixNano())
		err := s.db.CreateCorp(corpName,gameName,corpId,gameId,corpCode)
		if err != nil {
			continue
		}
		break
	}

	w.WriteHeader(http.StatusOK)
	err = json.NewEncoder(w).Encode(map[string]interface{} {
		"status":"1",
		"corp_name":corpName,
		"game_name":gameName,
		"corp_id":corpId,
		"game_id":gameId,
		"corp_code":corpCode,
	})
	if err != nil {
		log.Println("Error serializing API response: ", err)
	}
}

func (s *ApiServer) Health(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	//w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Cache-Control", "no-cache")
	//http.SetCookie(w, &http.Cookie{
	//	Name: "name of cookie",
	//	Value: "value of cookie",
	//	Path: "/",
	//})

	w.WriteHeader(http.StatusOK)
	err := json.NewEncoder(w).Encode(map[string]string {
		"status":"ok",
	})
	if err != nil {
		log.Println("Error serializing API response: ", err)
	}
}

func (s *ApiServer) GetTokenIndex(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Cache-Control", "no-cache")

	switch r.Method {
	case "GET":
		http.ServeFile(w, r, "#/login")
		return
	case "POST":
	default:
		fmt.Fprintf(w, "Sorry, only GET and POST methods are supported.")
		return
	}

	var userToken UserToken
	if err := json.NewDecoder(r.Body).Decode(&userToken); err != nil {
		log.Printf("failed to Decode: %v", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	var tokenExp = basicTokenExpiration
	if userToken.ExpireTime > 0 {
		tokenExp = userToken.ExpireTime	// sec
	} else if userToken.ExpireTime < 0 {
		tokenExp = unLimitTokenExpiration
	}

	expireTime := time.Now().Add(time.Second * time.Duration(tokenExp))
	unixExpireTime := expireTime.Unix()
	strExpireTime := expireTime.String()

	passDb, _, apiKey, _, _, _, actived, err := s.db.GetCorpAccountPassword(userToken.Username) // api_full_key, api_expire_time, 필요 없음.
	if err != nil {
		log.Printf("failed to DB Connected: %v", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if actived != "1" {
		log.Printf("failed to Not Actived(username: %v actived: %v)", userToken.Username, actived)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	if !util.CheckPasswordHash(passDb, userToken.Password) {
		log.Printf("failed to password is different: %v", err)
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string {
			"error": fmt.Sprintf("password is different: %v", err),
		})
		return
	}

	// Permission Check

	// Token Issuance
	token, _ := s.CreateToken(userToken.Username, "api", tokenExp)	// api로 고정함.

	tokenSplit := strings.Split(token,".")
	if len(tokenSplit) != 3 {
		return
	}

	// 먼저 디비에 유저에 api-key를 저장 한다.
	// 이미 있다면 기존것은 삭제 된다.
	if len(apiKey) > 0 {
		// 레디스에서 삭제된다.
		s.backend.DelAPIToken(apiKey)
	}

	// 디비 저장
	s.db.UpdateAccountApiKey(userToken.Username,tokenSplit[2],token, expireTime)

	// Register token as devid in Redis.
	s.backend.SetAPIToken( tokenSplit[2], token, tokenExp)

	cookie := new(http.Cookie)
	cookie.Name = "access-token"
	cookie.Value = token
	cookie.HttpOnly = true
	cookie.Expires = time.Now().Add(time.Hour * 24)

	http.SetCookie(w, cookie)
	respData := map[string]interface{}{
		"token":            tokenSplit[2],
		"access-token":     token,
		"unix-expire-time": unixExpireTime,
		"expire-time":      strExpireTime,
	}
	s.WriteHttpResponseOK(w, respData)
}

func (s *ApiServer) WriteHttpResponseOK(w http.ResponseWriter, result map[string]interface{}) {
	reply := make(map[string]interface{})
	reply["status"] = "1"
	reply["message"] = "OK"
	if result != nil {
		reply["result"] = result
	}
	w.WriteHeader(http.StatusOK)
	err := json.NewEncoder(w).Encode(reply)
	if err != nil {
		log.Println("Error serializing API response: ", err)
	}
}


func (s *ApiServer) CorpLoginIndex(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Headers", "*")
	w.Header().Set("Cache-Control", "no-cache")

	var user User

	switch r.Method {
	case "GET":
		http.ServeFile(w, r, "#/login")
		return
	case "POST":
		if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
			log.Printf("failed to Decode: %v", err)
			s.ServerApiError(w, r, http.StatusOK, ResultCodeServerErr, "failed to Decode: "+ err.Error())
			return
		}
	default:
		fmt.Fprintf(w, "Sorry, only GET and POST methods are supported.")
		return
	}

	passDb, access, strCorpId, tokenName, tokenSymbol, tokenImgUrl, actived, err := s.db.GetCorpAccountPassword(user.Username)
	if err != nil {
		log.Printf("failed to DB Connected: %v", err)
		s.ServerApiError(w, r, http.StatusOK, ResultCodeServerErr, "failed to DB Connected: "+ err.Error())
		return
	}



	cookie := new(http.Cookie)
	cookie.Name = "access-token"
	cookie.Value = token
	cookie.HttpOnly = true
	cookie.Expires = time.Now().Add( time.Second * time.Duration(basicMonthTokenExpiration))

	http.SetCookie(w, cookie)

	w.WriteHeader(http.StatusOK)
	err = json.NewEncoder(w).Encode(map[string]interface{} {
		"status":        "1",
		"token":         token,
		"corp_id":       strCorpId,
		"game_id":		strGameId,
		"game_name":	gameName,
		"token_name":    tokenName,
		"token_symbol":  tokenSymbol,
		"token_img_url": tokenImgUrl,
	})
	if err != nil {
		log.Println("Error serializing API response: ", err)
	}
}



func (s *ApiServer) CorpLogOutIndex(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Headers", "*")
	w.Header().Set("Cache-Control", "no-cache")

	switch r.Method {
	case "GET":
		http.ServeFile(w, r, "#/login")
		return
	case "POST":
	default:
		fmt.Fprintf(w, "Sorry, only GET and POST methods are supported.")
		return
	}

	var user User
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		log.Printf("failed to Decode: %v", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}



	cookie := new(http.Cookie)
	cookie.Name = "access-token"
	cookie.Value = "token"
	cookie.HttpOnly = true
	cookie.Expires = time.Now().Add(time.Hour * 24)

	http.SetCookie(w, cookie)

	reply := make(map[string]interface{})
	reply["status"] = "1"
	reply["result"] = "token"
	w.WriteHeader(http.StatusOK)
	err := json.NewEncoder(w).Encode(reply)
	if err != nil {
		log.Println("Error serializing API response: ", err)
	}
}

type User struct {
	Username string `json:"user_name"`
	Password string `json:"password"`
	Access	string `json:"access"`
	GameCode string `json:"game_code"`
}

type GUser struct {
	Name  string `json:"name"`
	Email string `json:"email"`
	EmailVerify bool `json:"email_verified"`
	Locale string `json:"locale"`
	Sub string `json:"sub"`
	Picture string `json:"picture"`
}

type ValueAuthGoogleParam struct {
	Code string `json:"code"`
	Account string `json:"account"`
	Password string `json:"password"`
}

type ValueTokenParam struct {
	token 			string `json:"token"`
	RefreshToken 	string `json:"refresh_token"`
}

type ValueCorpParam struct {
	UserName string `json:"user_name"`
	Password string `json:"password"`
	CorpName string `json:"corp_name"`
	GameName string `json:"game_name"`
	PickId	string `json:"pick_id"`
	UserKey string `json:"user_key"`
}

type ValueUserDataParam struct {
	UserKey string `json:"user_key"`
	PreviousPoint string `json:"previous_point"`
	AdjustPoint string `json:"adjust_point"`
	WalletAddress string `json:"wallet_address"`
}



type UserToken struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Access    string `json:"access"`
	ExpireTime int64 `json:"expire-time"`
}

type DbIPInbound struct {
	Ip string `json:"ip"`
	Rule string `json:"rule"`
	Alarm string `json:"alarm"`
	Desc    string `json:"desc"`
}

type DevSubList struct {
	DevId 	string `json:"devid"`
	SubId 	string `json:"subid"`
	Amount  string `json:"amount"`
	AllowId bool `json:"allowid"`
}

func (s *ApiServer) CreateCorpIndex(w http.ResponseWriter, r *http.Request) {

	var (
		valueCreateCorp ValueCorpParam
	)
	switch r.Method {
	case "GET":
		return
	case "POST":
		if err := json.NewDecoder(r.Body).Decode(&valueCreateCorp); err != nil {
			log.Printf("failed to Decode: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
	default:
		fmt.Fprintf(w, "Sorry, only GET and POST methods are supported.")
		return
	}

	// validation data
	if !util.IsValidUsername(valueCreateCorp.UserName) {
		log.Printf("failed to Username: %v", valueCreateCorp.UserName)
		s.ServerApiError(w, r, http.StatusOK, ResultCodeCorpIncorrectAccount, "Invalid id creation rule")
		return
	}
	hashedPassword, err := util.HashPassword(valueCreateCorp.Password)
	if err != nil {
		log.Printf("failed to GenerateFromPassword: %v", err)
		s.ServerApiError(w, r, http.StatusOK, ResultCodeCorpIncorrectPassword, "Invalid password creation rule")
		return
	}

	if s.db.IsCorpAccount(valueCreateCorp.UserName) {
		// 이미 존재하는 이름이다.
		s.ServerApiError(w, r, http.StatusOK, ResultCodeCorpExistCorpAccount, "Existing company account name")
		return
	}



	w.WriteHeader(http.StatusOK)
	err = json.NewEncoder(w).Encode(map[string]interface{} {
		"status":"1",
		"corp_name": valueCreateCorp.CorpName,
		"corp_id":"corpId",
		"corp_code":"corpCode",
	})
	if err != nil {
		log.Println("Error serializing API response: ", err)
	}
}


// 게임에 유저의 정보(로그인)를 얻어 온다.
func (s *ApiServer) CorpUserAddPointIndex(w http.ResponseWriter, r *http.Request) {

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




	w.WriteHeader(http.StatusOK)
	err = json.NewEncoder(w).Encode(map[string]interface{} {
		"status":   "1",
		"user_id":  "strUserId",
		"points": []interface{} {
			map[string]interface{}{
				"adjust_point": "adjustPoint",
				"current_point": "previousPoint" + "adjustPoint",
			},
		},
	})
	if err != nil {
		log.Println("Error serializing API response: ", err)
	}
}


// 회사에 게임을 추가 한다.
func (s *ApiServer) CorpAddGameIndex(w http.ResponseWriter, r *http.Request) {

	var (
		valueCreateCorp ValueCorpParam
		gameId          int64
		gameCode string
	)
	switch r.Method {
	case "GET":
		return
	case "POST":
		if err := json.NewDecoder(r.Body).Decode(&valueCreateCorp); err != nil {
			log.Printf("failed to Decode: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
	default:
		fmt.Fprintf(w, "Sorry, only GET and POST methods are supported.")
		return
	}

	// validation data
	// 게임 이름
	corpId, _ := strconv.ParseInt(r.Header.Get("user_id"), 10, 64)



	w.WriteHeader(http.StatusOK)
	err = json.NewEncoder(w).Encode(map[string]interface{} {
		"status":"1",
		"corp_name": "corpName",
		"game_name": valueCreateCorp.GameName,
		"corp_id":corpId,
		"game_id": gameId,
		"game_code":gameCode,
	})
	if err != nil {
		log.Println("Error serializing API response: ", err)
	}
}


func (s *ApiServer) ModuleIndex(w http.ResponseWriter, r *http.Request) {
	splitPath := strings.Split(r.URL.Path,"/")
	if len(splitPath) <= 3 {
		return
	}

	moduleName := splitPath[2]
	actionName := r.URL.Path[len(splitPath[1]) + len(splitPath[2]) + 3:]

	moduleName = strings.ToLower(moduleName)
	actionName = strings.ToLower(actionName)

	queryStr := string("ModuleName:" + moduleName + " ActionName:" + actionName)
	for name, query := range r.URL.Query() {
		if name != "module" && name != "action" {
			queryStr += fmt.Sprintf(" %v:%v " , name , query)
		}
	}

	if module,ok :=s.apiModule[moduleName]; ok == true {
		if actionFn, ok := module.actionList[actionName]; ok == true {
			actionFn.actionFn(w, r)
			fmt.Printf("%v %v\n",actionFn.actionFnName,queryStr)
		} else {
			fmt.Printf("%v does not exist :\n%v\n", actionName, queryStr)
		}
	} else {
		fmt.Println("No Module API:" + queryStr)
	}
}




func (s *ApiServer) ActionCropWalletEth(w http.ResponseWriter, r *http.Request) {
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

	decryptUserKey, err := util.AesDecrypt([]byte("01234567890123456789012345678912"), []byte(valueUserData.UserKey))
	if err != nil {
		log.Println("ActionWalletEth:AesDecrypt:user_key:AesDecrypt is wrong: ", err)
		s.ServerApiError(w, r, http.StatusOK, ResultCodeUserKeyErr, "user_key is wrong")
		return
	}

	strUserKey := string(decryptUserKey)
	splitUserKey := strings.Split(strUserKey,":")
	if len(splitUserKey) != 2 {
		// user_key is invalid.
		log.Println("ActionWalletEth:Split:user_key:splitUserKey is wrong: ", err)
		s.ServerApiError(w, r, http.StatusOK, ResultCodeUserKeyErr, "user_key is wrong")
		return
	}

	//strUserId := splitUserKey[1]
	userIdByKey, err := strconv.ParseInt(splitUserKey[1], 10, 64)
	if err != nil {
		log.Println("ActionWalletEth:ParseInt:user_key is not a number: ", err)
		s.ServerApiError(w, r, http.StatusOK, ResultCodeUserKeyErr, "user_key is wrong")
		return
	}

	// 유저의 주소를 얻어 온다
	ethWalletAddress := valueUserData.WalletAddress
	if ethWalletAddress == "" {
		_, _, tmpEthWalletAddress, _, _, _ := s.db.GetUserData(userIdByKey)
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

func (s *ApiServer) ActionBalanceMulti(w http.ResponseWriter, r *http.Request) {
	addressList := r.URL.Query().Get("address")
	tag 		:= r.URL.Query().Get("tag")

	splitAddressList := strings.Split(addressList,",")

	list := make(map[string]interface{})

	for _,address := range splitAddressList {
		balance, err := s.rpc().GetBalanceTag(address,tag)
		if err != nil {
			list[address] = err.Error()
			continue
		}

		list[address] = balance
	}



	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Headers", "*")
	w.Header().Set("Cache-Control", "no-cache")

	reply := make(map[string]interface{})
	reply["status"] = "1"
	reply["message"] = "OK"
	reply["result"] = list
	w.WriteHeader(http.StatusOK)
	err := json.NewEncoder(w).Encode(reply)
	if err != nil {
		log.Println("Error serializing API response: ", err)
	}
}


