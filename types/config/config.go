package config

import (
	"github.com/pickupcoin/pu-point-serv/storage/mysql"
	"github.com/pickupcoin/pu-point-serv/storage/redis"
)

type Config struct {
	Name string    `json:"name"`
	Api  ApiConfig `json:"api"`

	Threads int `json:"threads"`

	Redis redis.Config `json:"redis"`
	Mysql mysql.Config `json:"mysql"`
	MysqlAuth mysql.Config `json:"mysql-auth"`
	Auth AuthConfig `json:"auth"`
}


type AuthConfig struct {
	ClientID string `json:"ClientID"`
	ClientSecret string `json:"ClientSecret"`
}

type ApiConfig struct {
	Enabled         bool   `json:"enabled"`
	Listen          string `json:"listen"`

	NetId			int64	`json:"netId"`
	AllowedOrigins 	[]string `json:"AllowedOrigins"`
	Name            string

	ServerType		string `json:"ServerType"`

	// In Shannon
	Threshold      int64  `json:"threshold"`
	AccessSecret   string `json:"AccessSecret"`

	Upstream []Upstream `json:"rpcUrl"`
}


type Upstream struct {
	Name    string `json:"name"`
	Url     string `json:"url"`
	Timeout string `json:"timeout"`
}
