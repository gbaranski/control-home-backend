package main

import (
	"context"
	"fmt"
	"time"

	"github.com/gbaranski/houseflow/internal/actions"
	"github.com/gbaranski/houseflow/pkg/database"
	"github.com/gbaranski/houseflow/pkg/mqtt"
	"github.com/gbaranski/houseflow/pkg/utils"
)

var (
	mongoUsername = utils.MustGetEnv("MONGO_INITDB_ROOT_USERNAME")
	mongoPassword = utils.MustGetEnv("MONGO_INITDB_ROOT_PASSWORD")
	privateKey    = utils.MustGetEnv("SERVER_PRIVATE_KEY")
	serviceName   = utils.MustGetEnv("SERVICE_NAME")
	serviceID     = utils.MustGetEnv("SERVICE_ID")
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	mongo, err := database.NewMongo(ctx, database.MongoOptions{
		Username:     mongoUsername,
		Password:     mongoPassword,
		DatabaseName: "houseflowDB",
	})

	mqtt, err := mqtt.NewMQTT(mqtt.Options{
		ClientID:    fmt.Sprintf("%s-%s", serviceName, serviceID),
		BrokerURL:   "tcp://emqx:1883/mqtt",
		KeepAlive:   time.Second * 30,
		PingTimeout: time.Second * 5,
		PrivateKey:  []byte(privateKey),
	})
  if err != nil {
    panic(err)
  }

	s := actions.NewServer(mongo, mqtt)
	err = s.Router.Run(":80")
	if err != nil {
		panic(err)
	}
}