package util

import (
	"golang.org/x/crypto/bcrypt"
	"math/big"
	"math/rand"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/math"
)

var Ether = math.BigPow(10, 18)
var Shannon = math.BigPow(10, 9)

var pow256 = math.BigPow(2, 256)
var addressPattern = regexp.MustCompile("^0x[0-9a-fA-F]{40}$")
var zeroHash = regexp.MustCompile("^0?x?0+$")
var usernamePattern = regexp.MustCompile("^[0-9a-zA-Z-_]{3,20}$")

func IsValidHexAddress(s string) bool {
	if IsZeroHash(s) || !addressPattern.MatchString(s) {
		return false
	}
	return true
}

func IsValidUsername(s string) bool {
	if len(s) == 0 || !usernamePattern.MatchString(s) {
		return false
	}
	return true
}

func CheckValidHexAddress(s string) (string, bool) {
	if strings.HasPrefix(s,"0x") == false {
		s = "0x" + s
	}

	if IsValidHexAddress(s) {
		return s, true
	}
	return s, false
}


func IsZeroHash(s string) bool {
	return zeroHash.MatchString(s)
}

func MakeTimestamp() int64 {
	return time.Now().UnixNano() / int64(time.Millisecond)
}

func MakeTimestampDB(dbTimestamp string) int64 {
	const layout = "2006-01-02 15:04:05.000"
	t, _ := time.Parse(layout, dbTimestamp)

	return t.UnixNano() / int64(time.Millisecond)
}

func MakeTimestampDB2(dbTimestamp string) int64 {
	const layout = "2006-01-02 15:04:05"
	t, _ := time.Parse(layout, dbTimestamp)

	return t.UnixNano() / int64(time.Millisecond)
}
//
//func GetTargetHex(diff int64) string {
//	difficulty := big.NewInt(diff)
//	diff1 := new(big.Int).Div(pow256, difficulty)
//	return string(common.ToHex(diff1.Bytes()))
//}

func TargetHexToDiff(targetHex string) *big.Int {
	targetBytes := common.FromHex(targetHex)
	return new(big.Int).Div(pow256, new(big.Int).SetBytes(targetBytes))
}

func ToHex(n int64) string {
	return "0x0" + strconv.FormatInt(n, 16)
}

func FormatReward(reward *big.Int) string {
	return reward.String()
}

func FormatRatReward(reward *big.Rat) string {
	wei := new(big.Rat).SetInt(Ether)
	reward = reward.Quo(reward, wei)
	return reward.FloatString(8)
}

func StringInSlice(a string, list []string) bool {
	for _, b := range list {
		if b == a {
			return true
		}
	}
	return false
}

func MustParseDuration(s string) time.Duration {
	value, err := time.ParseDuration(s)
	if err != nil {
		panic("util: Can't parse duration `" + s + "`: " + err.Error())
	}
	return value
}

func String2Big(num string) *big.Int {
	n := new(big.Int)
	n.SetString(num, 0)
	return n
}

func Join(args ...interface{}) string {
	s := make([]string, len(args))
	for i, v := range args {
		switch v.(type) {
		case string:
			s[i] = v.(string)
		case int:
			s[i] = strconv.Itoa( v.(int))
		case int64:
			s[i] = strconv.FormatInt(v.(int64), 10)
		case uint64:
			s[i] = strconv.FormatUint(v.(uint64), 10)
		case float64:
			s[i] = strconv.FormatFloat(v.(float64), 'f', 0, 64)
		case bool:
			if v.(bool) {
				s[i] = "1"
			} else {
				s[i] = "0"
			}
		case *big.Int:
			n := v.(*big.Int)
			if n != nil {
				s[i] = n.String()
			} else {
				s[i] = "0"
			}
		case *big.Rat:
			x := v.(*big.Rat)
			if x != nil {
				s[i] = x.FloatString(9)
			} else {
				s[i] = "0"
			}
		default:
			panic("Invalid type specified for conversion")
		}
	}
	return strings.Join(s, ":")
}

func HashPassword(password string) ([]byte, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return bytes, err
}

func CheckPasswordHash(hashVal, userPw string) bool {
	if userPw == "" {
		return false
	}
	err := bcrypt.CompareHashAndPassword([]byte(hashVal), []byte(userPw))
	if err != nil {
		return false
	} else {
		return true
	}
}

const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
const (
	letterIdxMax = 30
	letterIdxBits = 6                    // 6 bits to represent a letter index
	letterIdxMask = 1<<letterIdxBits - 1 // All 1-bits, as many as letterIdxBits
)
var src = rand.NewSource(time.Now().UnixNano())

func RandStringBytesMaskImprSrc(n int) string {
	b := make([]byte, n)
	// A src.Int63() generates 63 random bits, enough for letterIdxMax characters!
	for i, cache, remain := n-1, src.Int63(), letterIdxMax; i >= 0; {
		if remain == 0 {
			cache, remain = src.Int63(), letterIdxMax
		}
		if idx := int(cache & letterIdxMask); idx < len(letterBytes) {
			b[i] = letterBytes[idx]
			i--
		}
		cache >>= letterIdxBits
		remain--
	}

	return string(b)
}