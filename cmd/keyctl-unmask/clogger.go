package main

import (
	"context"
	"log"
	"os"

	"cloud.google.com/go/logging"
	"github.com/golang/glog"
)

var (
	Info    *log.Logger // Info logger
	Warning *log.Logger // Warning logger
	Error   *log.Logger // Error logger
	Fatal   *log.Logger // Fatal logger
)

//Info    //*log.Logger // Info logger

// type Logger struct {
// 	Info    *log.Logger // Info logger
// 	Warning *log.Logger // Warning logger
// 	Error   *log.Logger // Error logger
// 	Fatal   *log.Logger // Fatal logger
// }

// type Mlog struct {
// 	*log.Logger
// }

// func init() {
// 	Info =
// }

func LogInit() {
	//projID := "antitree-admin"
	projID := os.Getenv("GOOGLE_PROJECT_ID")
	//fmt.Printf("This is it %T", log.Logger

	// baselogger := log.Logger()
	// newlogger := &MLog{baselogger}
	// return newlogger

	if projID == "" {
		glog.Warning("Need to set the GOOGLE_PROJECT_ID if you want cloud logging")
		//setup_local()
		//log.Logger{}
		//return log.logger{}
	} else if os.Getenv("GOOGLE_APPLICATION_CREDENTIALS") == "" {
		glog.Warning("Missing GCP logging credentials. Set GOOGLE_APPLICATION_CREDENTIALS")
		//setup_local()
		//return &glog.Infoln
	} else {
		setup_cloud(projID)
	}
	//return nil
	//glog.Fatalln("SHUT IT DOWN")
}

func setup_local() error {
	//Info = log.Logger()
	// TODO figure out how to return the same formatted logger in glog or log
	return nil
}

func setup_cloud(projID string) error {
	ctx := context.Background()
	client, err := logging.NewClient(ctx, projID)
	if err != nil {
		glog.Fatalf("Failed to create logging client: %v", err)
	}

	client.OnError = func(err error) {
		glog.Fatalf("client.OnError: %v", err)
	}

	logger := client.Logger("keyctl-unmask-name")
	defer logger.Flush()

	Info = logger.StandardLogger(logging.Info)
	Warning = logger.StandardLogger(logging.Warning)
	Error = logger.StandardLogger(logging.Error)
	Fatal = logger.StandardLogger(logging.Critical) // I guess no fatal?

	//Info.Println("Cloud logging enabled")

	// logger.Log(logging.Entry{
	// 	Payload: struct{ Anything string }{
	// 		Anything: "the payload is shit!",
	// 	},
	// 	Severity: logging.Debug,
	// })

	//fmt.Printf("%T", Info)

	//glog := client.Logger("keyctl-unmask-name")
	return nil
}
