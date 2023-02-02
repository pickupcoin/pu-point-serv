package redis

import (
	"fmt"
	"github.com/pickupcoin/pu-point-serv/util"
	"math"
	"math/big"
	"strconv"
	"strings"
	"time"

	"gopkg.in/redis.v3"
)

type Config struct {
	Endpoint string `json:"endpoint"`
	Password string `json:"password"`
	Database int64  `json:"database"`
	PoolSize int    `json:"poolSize"`
}

type RedisClient struct {
	client *redis.Client
}

type PoolCharts struct {
	Timestamp  int64  `json:"x"`
	TimeFormat string `json:"timeFormat"`
	PoolHash   int64  `json:"y"`
}

type PaymentCharts struct {
	Timestamp  int64  `json:"x"`
	TimeFormat string `json:"timeFormat"`
	Amount     int64  `json:"amount"`
}

type SumRewardData struct {
	Interval int64  `json:"inverval"`
	Reward   int64  `json:"reward"`
	Name     string `json:"name"`
	Offset   int64  `json:"offset"`
}

type Miner struct {
	LastBeat  int64 `json:"lastBeat"`
	HR        int64 `json:"hr"`
	Offline   bool  `json:"offline"`
	startedAt int64
}

type Worker struct {
	Miner
	TotalHR int64 `json:"hr2"`
	WorkerDiff     int64  `json:"difficulty"`
	WorkerHostname string `json:"hostname"`
	Size  			int64 `json:"size"`
	RoundShare		float32 `json:"rshare"`
	Reported		int64 `json:"reported"`
	DevId			string `json:"devid"`
}


func NewRedisClient(cfg *Config) *RedisClient {
	client := redis.NewClient(&redis.Options{
		Addr:     cfg.Endpoint,
		Password: cfg.Password,
		DB:       cfg.Database,
		PoolSize: cfg.PoolSize,
	})
	return &RedisClient{client: client}
}

func (r *RedisClient) Client() *redis.Client {
	return r.client
}

func (r *RedisClient) Check() (string, error) {
	return r.client.Ping().Result()
}

func (r *RedisClient) BgSave() (string, error) {
	return r.client.BgSave().Result()
}

// Always returns list of addresses. If Redis fails it will return empty list.
func (r *RedisClient) GetBlacklist() ([]string, error) {
	cmd := r.client.SMembers(r.formatKey("blacklist"))
	if cmd.Err() != nil {
		return []string{}, cmd.Err()
	}
	return cmd.Val(), nil
}

// Always returns list of IPs. If Redis fails it will return empty list.
func (r *RedisClient) GetWhitelist() ([]string, error) {
	cmd := r.client.SMembers(r.formatKey("whitelist"))
	if cmd.Err() != nil {
		return []string{}, cmd.Err()
	}
	return cmd.Val(), nil
}

// WritePoolCharts is pool charts
func (r *RedisClient) WritePoolCharts(time1 int64, time2 string, poolHash string) error {
	s := util.Join(time1, time2, poolHash)
	cmd := r.client.ZAdd(r.formatKey("charts", "pool"), redis.Z{Score: float64(time1), Member: s})
	return cmd.Err()
}

func (r *RedisClient) WriteMinerCharts(time1 int64, time2, k string, hash, largeHash, workerOnline int64, share int64, report int64) error {
	s := util.Join(time1, time2, hash, largeHash, workerOnline, share, report)
	cmd := r.client.ZAdd(r.formatKey("charts", "miner", k), redis.Z{Score: float64(time1), Member: s})
	return cmd.Err()
}

func (r *RedisClient) GetPoolCharts(poolHashLen int64) (stats []*PoolCharts, err error) {

	tx := r.client.Multi()
	defer tx.Close()

	now := util.MakeTimestamp() / 1000

	cmds, err := tx.Exec(func() error {
		tx.ZRemRangeByScore(r.formatKey("charts", "pool"), "-inf", fmt.Sprint("(", now-172800))
		tx.ZRevRangeWithScores(r.formatKey("charts", "pool"), 0, poolHashLen)
		return nil
	})

	if err != nil {
		return nil, err
	}

	stats = convertPoolChartsResults(cmds[1].(*redis.ZSliceCmd))
	return stats, nil
}

func convertPoolChartsResults(raw *redis.ZSliceCmd) []*PoolCharts {
	var result []*PoolCharts
	for _, v := range raw.Val() {
		// "Timestamp:TimeFormat:Hash"
		pc := PoolCharts{}
		pc.Timestamp = int64(v.Score)
		str := v.Member.(string)
		pc.TimeFormat = str[strings.Index(str, ":")+1 : strings.LastIndex(str, ":")]
		pc.PoolHash, _ = strconv.ParseInt(str[strings.LastIndex(str, ":")+1:], 10, 64)
		result = append(result, &pc)
	}
	return result
}

func (r *RedisClient) GetAllMinerAccount() (account []string, err error) {
	var c int64
	for {
		now := util.MakeTimestamp() / 1000
		c, keys, err := r.client.Scan(c, r.formatKey("miners", "*"), now).Result()

		if err != nil {
			return account, err
		}
		for _, key := range keys {
			m := strings.Split(key, ":")
			//if ( len(m) >= 2 && strings.Index(strings.ToLower(m[2]), "0x") == 0) {
			if len(m) >= 2 {
				account = append(account, m[2])
			}
		}
		if c == 0 {
			break
		}
	}
	return account, nil
}

func (r *RedisClient) GetPaymentCharts(login string) (stats []*PaymentCharts, err error) {

	tx := r.client.Multi()
	defer tx.Close()
	cmds, err := tx.Exec(func() error {
		tx.ZRevRangeWithScores(r.formatKey("payments", login), 0, 360)
		return nil
	})
	if err != nil {
		return nil, err
	}
	stats = convertPaymentChartsResults(cmds[0].(*redis.ZSliceCmd))
	//fmt.Println(stats)
	return stats, nil
}



func (r *RedisClient) WriteNodeState(id string, height uint64, diff *big.Int) error {
	tx := r.client.Multi()
	defer tx.Close()

	now := util.MakeTimestamp() / 1000

	_, err := tx.Exec(func() error {
		tx.HSet(r.formatKey("nodes"), util.Join(id, "name"), id)
		tx.HSet(r.formatKey("nodes"), util.Join(id, "height"), strconv.FormatUint(height, 10))
		tx.HSet(r.formatKey("nodes"), util.Join(id, "difficulty"), diff.String())
		tx.HSet(r.formatKey("nodes"), util.Join(id, "lastBeat"), strconv.FormatInt(now, 10))
		return nil
	})
	return err
}


func (r *RedisClient) GetNodeHeight(id string) (int64, error) {
	cmd := r.client.HGet(r.formatKey("nodes"), util.Join(id, "height"))
	if cmd.Err() == redis.Nil {
		return 0, nil
	} else if cmd.Err() != nil {
		return 0, cmd.Err()
	}
	return cmd.Int64()
}

func (r *RedisClient) GetNodeStates() ([]map[string]interface{}, error) {
	cmd := r.client.HGetAllMap(r.formatKey("nodes"))
	if cmd.Err() != nil {
		return nil, cmd.Err()
	}
	m := make(map[string]map[string]interface{})
	for key, value := range cmd.Val() {
		parts := strings.Split(key, ":")
		if val, ok := m[parts[0]]; ok {
			val[parts[1]] = value
		} else {
			node := make(map[string]interface{})
			node[parts[1]] = value
			m[parts[0]] = node
		}
	}
	v := make([]map[string]interface{}, len(m), len(m))
	i := 0
	for _, value := range m {
		v[i] = value
		i++
	}
	return v, nil
}

func (r *RedisClient) CheckPoWExist(height uint64, params []string) (bool, error) {
	// Sweep PoW backlog for previous blocks, we have 3 templates back in RAM
	r.client.ZRemRangeByScore(r.formatKey("pow"), "-inf", fmt.Sprint("(", height-8))
	val, err := r.client.ZAdd(r.formatKey("pow"), redis.Z{Score: float64(height), Member: strings.Join(params, ":")}).Result()
	return val == 0, err
}


func (r *RedisClient) formatKey(args ...interface{}) string {
	return util.Join("prefix", util.Join(args...))
}

func (r *RedisClient) formatRound(height int64, nonce string) string {
	return r.formatKey("shares", "round"+strconv.FormatInt(height, 10), nonce)
}


func (r *RedisClient) GetBalance(login string) (int64, error) {
	cmd := r.client.HGet(r.formatKey("miners", login), "balance")
	if cmd.Err() == redis.Nil {
		return 0, nil
	} else if cmd.Err() != nil {
		return 0, cmd.Err()
	}
	return cmd.Int64()
}

func (r *RedisClient) LockPayouts(login string, amount int64) error {
	key := r.formatKey("payments", "lock")
	result := r.client.SetNX(key, util.Join(login, amount), 0).Val()
	if !result {
		return fmt.Errorf("unable to acquire lock '%s'", key)
	}
	return nil
}

func (r *RedisClient) UnlockPayouts() error {
	key := r.formatKey("payments", "lock")
	_, err := r.client.Del(key).Result()
	return err
}

func (r *RedisClient) IsPayoutsLocked() (bool, error) {
	_, err := r.client.Get(r.formatKey("payments", "lock")).Result()
	if err == redis.Nil {
		return false, nil
	} else if err != nil {
		return false, err
	} else {
		return true, nil
	}
}


/*
Timestamp  int64  `json:"x"`
TimeFormat string `json:"timeFormat"`
Amount     int64  `json:"amount"`
*/
func convertPaymentChartsResults(raw *redis.ZSliceCmd) []*PaymentCharts {
	var result []*PaymentCharts
	for _, v := range raw.Val() {
		pc := PaymentCharts{}
		pc.Timestamp = int64(v.Score)
		tm := time.Unix(pc.Timestamp, 0)
		pc.TimeFormat = tm.Format("2006-01-02") + " 00_00"
		fields := strings.Split(v.Member.(string), ":")
		pc.Amount, _ = strconv.ParseInt(fields[1], 10, 64)
		//fmt.Printf("%d : %s : %d \n", pc.Timestamp, pc.TimeFormat, pc.Amount)

		var chkAppend bool
		for _, pcc := range result {
			if pcc.TimeFormat == pc.TimeFormat {
				pcc.Amount += pc.Amount
				chkAppend = true
			}
		}
		if !chkAppend {
			pc.Timestamp -= int64(math.Mod(float64(v.Score), float64(86400)))
			result = append(result, &pc)
		}
	}
	return result
}

func (r *RedisClient) GetReportedtHashrate(login string) (map[string]int64, error) {
	var result map[string]int64
	reportedRate := r.client.HGetAllMap(r.formatKey("report", login))
	if reportedRate.Err() == redis.Nil {
		return nil, nil
	} else if reportedRate.Err() != nil {
		return nil, reportedRate.Err()
	}

	now := util.MakeTimestamp() / 1000
	reportedMap, _ := reportedRate.Result()
	for workerId, rateStr := range reportedMap {
		val := strings.Split(rateStr,":")
		rate, _ := strconv.ParseInt(val[0], 10, 64)
		ts, _ := strconv.ParseInt(val[1], 10, 64)

		if ts + 600 > now {
			if result == nil { result = make(map[string]int64) }
			result[workerId] = rate
		}
	}
	return result, nil
}

func (r *RedisClient) GetAllReportedtHashrate(login string) (int64, error) {
	reportedRate := r.client.HGetAllMap(r.formatKey("report", login))
	if reportedRate.Err() == redis.Nil {
		return -1, nil
	} else if reportedRate.Err() != nil {
		return 0, reportedRate.Err()
	}

	var result int64
	now := util.MakeTimestamp() / 1000

	reportedMap, _ := reportedRate.Result()
	for _, rateStr := range reportedMap {
		val := strings.Split(rateStr,":")
		rate, _ := strconv.ParseInt(val[0], 10, 64)
		ts, _ := strconv.ParseInt(val[1], 10, 64)
		size, _ := strconv.ParseInt(val[2], 10, 64)

		if ts + 600 > now {
			result += rate * size
		}
	}
	return result, nil
}

func (r *RedisClient) SetReportedtHashrates(logins map[string]string, WorkerId string) error {
	tx := r.client.Multi()
	defer tx.Close()

	_, err := tx.Exec(func() error {
		for login, rateStr := range logins {
			r.client.HSet(r.formatKey("report", login), WorkerId, rateStr)
		}
		return nil
	})

	if err != nil {
		return err
	}
	return nil
}

func (r *RedisClient) DelAPIToken(jstSign string) error {
	key := "api:" + jstSign
	result := r.client.Del(key)
	if result.Err() == redis.Nil {
		return nil
	} else if result.Err() != nil {
		return result.Err()
	}
	return nil
}

func (r *RedisClient) SetAPIToken(jstSign string, jwtFullStr string, expirationMin int64) error {
	key := "api:" + jstSign
	result := r.client.Set(key, jwtFullStr, time.Minute * time.Duration(expirationMin))
	if result.Err() == redis.Nil {
		return nil
	} else if result.Err() != nil {
		return result.Err()
	}
	return nil
}


func (r *RedisClient) GetAPIToken(jstSign string) (string, error) {
	key := "api:" + jstSign
	result := r.client.Get(key)
	if result.Err() == redis.Nil {
		return "", nil
	} else if result.Err() != nil {
		return "", result.Err()
	}
	resultVal, _ := result.Result()
	return resultVal, nil
}



func (r *RedisClient) SetToken(userName string, jwtSign string, expirationMin int64) error {
	lowerDevId := strings.ToLower(userName)
	key := "acc:" + lowerDevId
	result := r.client.Set(key, jwtSign, time.Minute * time.Duration(expirationMin))
	if result.Err() == redis.Nil {
		return nil
	} else if result.Err() != nil {
		return result.Err()
	}
	return nil
}


func (r *RedisClient) GetToken(userName string) (string, error) {
	key := "acc:" + userName
	result := r.client.Get(key)
	if result.Err() == redis.Nil {
		return "", nil
	} else if result.Err() != nil {
		return "", result.Err()
	}
	resultVal, _ := result.Result()
	return resultVal, nil
}

func (r *RedisClient) InitAlarmBeat(alarmList []string, exp time.Duration) error {
	tx := r.client.Multi()
	defer tx.Close()
	ts := util.MakeTimestamp() / 1000
	_, err := tx.Exec(func() error {
		for _, login := range alarmList {
			r.client.Set(r.formatKey("beat", login), ts, exp)
		}
		return nil
	})

	if err != nil {
		return err
	}
	return nil
}

func (r *RedisClient) WriteAlarmBeat(login string, exp time.Duration) error {
	tx := r.client.Multi()
	defer tx.Close()
	ts := util.MakeTimestamp() / 1000
	_, err := tx.Exec(func() error {
		r.client.Set(r.formatKey("beat", login), ts, exp)
		return nil
	})

	if err != nil {
		return err
	}
	return nil
}


func (r *RedisClient) GetAlarmBeat(login string) (bool, error) {
	result := r.client.Get(r.formatKey("beat", login))
	if result.Err() == redis.Nil {
		return false, nil
	} else if result.Err() != nil {
		return false, result.Err()
	}

	return true, nil
}