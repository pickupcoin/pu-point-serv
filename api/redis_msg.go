package api

import (
	"encoding/json"
	"fmt"
	"github.com/pickupcoin/pu-point-serv/storage/redis"
	"log"
	"net/http"
	"strings"
)

func (s *ApiServer) RedisMessage(payload string) {
	splitData := strings.Split(payload,":")
	if len(splitData) != 3 {
		return
	}
	opcode := splitData[0]
	from := splitData[1]
	msg := splitData[2]
	switch opcode {
	case redis.OpcodeChangeServStatus:
		//if s.alarm != nil {
		//	s.alarm.MakeAlarmList()	// can process it right away.
		//}
	case redis.OpcodeLoadIP:
	case redis.OpcodeWhiteList:
	case redis.OpcodeMinerSub:
	default:
		log.Printf("not defined opcode: %v", opcode)
	}

	fmt.Printf("(opcode:%v from:%s)RedisMessage: %s\n", opcode, from, msg)
}

func (s *ApiServer) ChangeServerStatusIndex(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	//w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Cache-Control", "no-cache")


	_, err := s.backend.Publish(redis.ChannelPoint,redis.OpcodeChangeServStatus, "", redis.ChannelManager)
	if err != nil {
		w.WriteHeader(http.StatusOK)
		err = json.NewEncoder(w).Encode(map[string]string {
			"status":"fail",
			"msg":"Failed to send to proxy server",
		})
		return
	}

	w.WriteHeader(http.StatusOK)
	err = json.NewEncoder(w).Encode(map[string]string {
		"status":"ok",
	})
	if err != nil {
		log.Println("Error serializing API response: ", err)
	}
}