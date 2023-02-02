package mysql

import (
	"database/sql"
	"errors"
	"fmt"
	_ "github.com/go-sql-driver/mysql"
	"github.com/pickupcoin/pu-point-serv/types"
	"log"
	"time"
)

type Config struct {
	Endpoint string `json:"endpoint"`
	UserName string `json:"user"`
	Password string `json:"password"`
	Database string    `json:"database"`
	Port	 int	`json:"port"`
	PoolSize int    `json:"poolSize"`

	Coin 	string  `json:"coin"`
	Threshold int64 `json:"threshold"`
	LogTableName string `json:"logTableName"`
}

type Database struct {
	Conn *sql.DB

	Config *Config
	DiffByShareValue int64

	ConnWallet *sql.DB
}

type Payees struct {
	Coin string
	Addr string
	Balance int64
	Payout_limit int64
}

type MinerChartSelect struct {
	Coin			string
	Addr 			string
	Share			int
	ShareCheckTime 	int64
}

type VersionInfo struct {
	Version string 	`json:"version"`
	SnsType string 	`json:"sns_type"`
	Used string		`json:"used"`
	Force string	`json:"force"`
	Url string		`json:"url"`
}


type ServerStatus struct {
	Name string 	`json:"name"`
	ServType string 	`json:"serv_type"`
	ServStatus string		`json:"serv_status"`
}



type LogEntrie struct {
	Entries string
	Addr string
}

type ImmaturedState string
const (
	eMaturedBlock = ImmaturedState("MaturedBlock")
	eOrphanBlock  = ImmaturedState("OrphanBlock")
	eLostBlock		= ImmaturedState("LostBlock")
)

const constInsertCountSqlMax = 2000


func New(cfg *Config) (*Database, error) {
	url := fmt.Sprintf("%s:%s@tcp(%s:%d)/%s",
		cfg.UserName, cfg.Password, cfg.Endpoint, cfg.Port, cfg.Database)
	conn, err := sql.Open("mysql", url)
	if err != nil {
		println(err)
		return nil, err
	}

	db := &Database{
		Conn:       conn,
		Config : cfg,
	}

	conn.SetMaxIdleConns(50)
	conn.SetMaxOpenConns(50)

	err = conn.Ping()
	if err != nil {
		return nil, err
	}

	return db, nil
}


func (d *Database) InsertSqlLog(sql *string) {
	conn := d.Conn

	_, err := conn.Exec(*sql)
	if err != nil {
		log.Fatal(err)
	}
	return
}


func (d *Database) GetVersion() ([]*VersionInfo, error) {

	return nil, nil
}




func (d *Database) GetUserGamePoint(userId int64, corpId int64) (string,string,string,string,string,error) {
	return "", "", "", "", "", nil
}

func (d *Database) InitGamePoint(corpId string, userId string, initPoint int64) (int64,int64) {

	return 1, 1
}

func (d *Database) AddGamePoint(userId int64,corpId int64, updatePoint int64, previousPoint int64) error {

	return nil
}


func (d *Database) AddGamePointList(userId int64,corpId int64, gameId int64, dateDt int64, updatePoint int64, currentPoint int64) error {

	return nil
}

func (d *Database) CreatePlatData(subID string, platType string, access string) (int64,int64) {

	return 1, 1
}

func (d *Database) CreateUserData(uuid int64, pickId string, walletAddr string,privateKey []byte,email string) error {

	return nil
}

func (d *Database) GetUserData(uuid int64) (string, string, string, []byte, string, error) {


	return "", "", "", nil, "", errors.New("sql: Can't find user")
}

func (d *Database) GetUserToken(uuid int64,token string) (string, string, error) {

	return "", "", errors.New("sql: Can't find user")
}



func (d *Database) InsertUserToken(uuid int64,token string, refreshToken string) error {

	return nil
}

func (d *Database) DeleteUserTokenAll(uuid int64) error {

	return nil
}

func (d *Database) DeleteUserToken(uuid int64, token string) error {

	return nil
}


func (d *Database) GetUser(uuid int64) (bool, string, string, error) {


	return false, "", "", nil
}


func (d *Database) CreateUser(uuid int64, account string, pass string, activateCode string) (bool,error) {

	return true, nil
}



//
func (d *Database) CreateCorp(corpName string, gameName string, corpId int64, gameId int64, corpCode string) error {

	return nil
}



func (d *Database) CreateCorpAccount(user string,pass []byte, access string, corpName string, corpId int64, corpCode string) bool {

	return true
}

func (d *Database) IsCorpAccount(id string) bool {

	return false
}

func (d *Database) GetCorpAccountPassword(id string) (string, string, string, string, string, string, string, error) {

	return "", "", "", "", "", "", "", errors.New("sql: Can't find user")
}

func (d *Database) GetCorpUserByCorpId(corpId int64) (string, string, string, error) {

	return "", "", "", errors.New("sql: Can't find corp_id")
}

func (d *Database) AddCorpGame(corpId int64,gameId int64, corpName string, gameName string, gameCode string) bool {

	return true
}

func (d *Database) GetCorpGameByCorpId(corpId int64, gameId int64) (string, string, error) {


	return "", "", errors.New("sql: Can't find corp_game")
}

func (d *Database) UpdateAccountApiKey(id string, apiKey string, apiFullKey string, expireTime time.Time) bool {


	return true
}


func (d *Database) GetTxList(address string, startblock string, endblock string, page int64, offset int64, sort string) ([]*types.TransactionData, error){


	return result, nil
}