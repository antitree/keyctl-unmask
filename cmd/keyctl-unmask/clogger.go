package main

import (
	"context"
	"io"
	"log"
	"os"

	"cloud.google.com/go/logging"
)

var (
	Info    *log.Logger // Info logger
	Warning *log.Logger // Warning logger
	Error   *log.Logger // Error logger
	Fatal   *log.Logger // Fatal logger
)

func Clogger(i io.Writer, w io.Writer, e io.Writer) {
	setup_local(i, w, e)

	projID := os.Getenv("GOOGLE_PROJECT_ID")
	//projID = ""

	if projID == "" {
		Info.Println("Need to set the GOOGLE_PROJECT_ID if you want cloud logging")
	} else if os.Getenv("GOOGLE_APPLICATION_CREDENTIALS") == "" {
		Info.Println("Missing GCP logging credentials. Set GOOGLE_APPLICATION_CREDENTIALS")
	} else {

		setup_cloud(projID)
	}

}

func setup_local(
	infoHandle io.Writer,
	warningHandle io.Writer,
	errorHandle io.Writer) {

	Info = log.New(infoHandle,
		"INFO: ",
		log.Ldate|log.Ltime|log.Lshortfile)

	Warning = log.New(warningHandle,
		"WARNING: ",
		log.Ldate|log.Ltime|log.Lshortfile)

	Error = log.New(errorHandle,
		"ERROR: ",
		log.Ldate|log.Ltime|log.Lshortfile)
}

func setup_cloud(projID string) error {
	ctx := context.Background()
	client, err := logging.NewClient(ctx, projID)
	if err != nil {
		Fatal.Panicf("Failed to create logging client: %v", err)
		return err
	}

	client.OnError = func(err error) {
		Fatal.Panicf("client.OnError: %v", err)
	}

	logger := client.Logger("keyctl-unmask-name")
	defer logger.Flush()

	Info.Println("Cloud logging enabled")

	Info = logger.StandardLogger(logging.Info)
	Warning = logger.StandardLogger(logging.Warning)
	Error = logger.StandardLogger(logging.Error)
	Fatal = logger.StandardLogger(logging.Critical)

	return nil
}
