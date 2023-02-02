// +build go1.9

package main

import (
	"encoding/json"
	"github.com/pickupcoin/pu-point-serv/api"
	auth "github.com/pickupcoin/pu-point-serv/auth/google"
	"github.com/pickupcoin/pu-point-serv/hook"
	"github.com/pickupcoin/pu-point-serv/storage/mysql"
	"github.com/pickupcoin/pu-point-serv/storage/redis"
	"github.com/pickupcoin/pu-point-serv/types/config"
	"github.com/pickupcoin/pu-point-serv/util"
	"github.com/pickupcoin/pu-point-serv/util/plogger"
	"log"
	"math/rand"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const (
	CallBackURL = "http://localhost:8080/auth/callback"

	UserInfoAPIEndpoint = "https://www.googleapis.com/oauth2/v3/userinfo"
	ScopeEmail          = "https://www.googleapis.com/auth/userinfo.email"
	ScopeProfile        = "https://www.googleapis.com/auth/userinfo.profile"
)

var (
	//var backend *redis.RedisClient
	cfg     config.Config
	backend *redis.RedisClient
	db     *mysql.Database
	dbAuth *mysql.Database
	logger *plogger.Logger
)

func startApi() {
	s := api.NewApiServer(&cfg.Api, cfg.Name, backend, db, dbAuth)
	s.Start()
}


func readConfig(cfg *config.Config) {
	configFileName := "config.json"
	if len(os.Args) > 1 {
		configFileName = os.Args[1]
	}
	configFileName, _ = filepath.Abs(configFileName)
	log.Printf("Loading config: %v", configFileName)

	configFile, err := os.Open(configFileName)
	if err != nil {
		log.Fatal("File error: ", err.Error())
	}
	defer configFile.Close()
	jsonParser := json.NewDecoder(configFile)
	if err := jsonParser.Decode(&cfg); err != nil {
		log.Fatal("Config error: ", err.Error())
	}

	cfg.Api.Name = cfg.Name
}

func init()  {
	readConfig(&cfg)
	rand.Seed(time.Now().UnixNano())

	auth.InitAuth(cfg.Auth.ClientID, cfg.Auth.ClientSecret)
}

func main() {
	if cfg.Threads > 0 {
		runtime.GOMAXPROCS(cfg.Threads)
		log.Printf("Running with %v threads", cfg.Threads)
	}

	var err  error
	backend = redis.NewRedisClient(&cfg.Redis)
	pong, err := backend.Check()
	if err != nil {
		log.Printf("Can't establish connection to backend: %v", err)
	} else {
		log.Printf("Backend check reply: %v", pong)
	}

	if db, err = mysql.New(&cfg.Mysql); err != nil {
		log.Printf("Can't establish connection to mysql: %v", err)
		os.Exit(1)
	}

	log.Printf("connected mysql host:%v database:%v",cfg.Mysql.Endpoint, cfg.Mysql.Database)

	if dbAuth, err = mysql.New(&cfg.MysqlAuth); err != nil {
		log.Printf("Can't establish connection to mysql-auth: %v", err)
		os.Exit(1)
	}

	log.Printf("connected auth mysql host:%v database:%v",cfg.MysqlAuth.Endpoint, cfg.MysqlAuth.Database)

	hook.RegistryMainHook(func() {
		logger.Close()	// Save all logs.
	})

	// logger is pooling
	logger = plogger.New(db, cfg.Mysql.LogTableName)

	tmpServerType := strings.Split(cfg.Api.ServerType,",")
	for _, serverTypeName := range tmpServerType {
		ret := util.StringInSlice(serverTypeName,[]string{"auth", "point","web","mgr"})
		if ret == false {
			log.Printf("Config is wrong. ServerType: %v", serverTypeName)
			os.Exit(1)
		}
	}

	if cfg.Api.Enabled {
		go startApi()
	}

	hook.Listen()
}
