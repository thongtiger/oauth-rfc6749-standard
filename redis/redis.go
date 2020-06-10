package redis

import (
	"errors"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/go-redis/redis"
)

var host, port = "localhost", "6379" // default

// RedisClient connector
func RedisClient() *redis.Client {
	if val, ok := os.LookupEnv("REDIS_HOST"); ok {
		host = strings.TrimSpace(val)
	}
	if val, ok := os.LookupEnv("REDIS_PORT"); ok {
		port = strings.TrimSpace(val)
	}

	client := redis.NewClient(&redis.Options{
		Addr:     host + ":" + port,
		Password: "", // no password set
		DB:       0,  // use default DB
	})

	pong, err := client.Ping().Result()
	fmt.Println(pong, err)
	// Output: PONG <nil>
	return client
}

func Exists(ClientID, RefreshToken string) bool {
	client := RedisClient()
	defer client.Close()

	dbValue, err := client.Get(ClientID).Result()
	if err == redis.Nil {
		log.Println("redis: refresh_token does not exist or expired")
		return false
	}
	if dbValue == "" {
		log.Println("redis: refresh_token is expired")
		return false
	}
	// check value
	if dbValue == RefreshToken {
		return true
	}
	log.Println("redis: refresh_token does not exist")
	return false
}

func SetRefreshToken(ClientID, RefreshToken string, ExpireIn time.Duration) (bool, error) {
	client := RedisClient()
	defer client.Close()

	err := client.Set(ClientID, RefreshToken, ExpireIn).Err()
	if err != nil {
		log.Println("redis: error set new refresh_token")
		return false, fmt.Errorf("redis: error set new refresh_token")
	}
	return true, nil
}

func DelClientID(ClientID string) error {
	client := RedisClient()
	defer client.Close()

	err := client.Del(ClientID).Err()
	if err != nil {
		return errors.New("redis: error del clientID")
	}
	return nil

}
