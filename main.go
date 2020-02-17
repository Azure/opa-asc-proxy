package main

import (
	"context"
	"encoding/json"
	//"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	//"os/exec"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/pflag"
)

var (
	debug      = pflag.Bool("debug", true, "sets log to debug level")
	server *Server
	ctx      context.Context
)
// LogHook is used to setup custom hooks
type LogHook struct {
	Writer    io.Writer
	Loglevels []log.Level
}

func main() {
	//pflag.Parse()

	var err error

	setupLogger()

	ctx = context.Background()
	server, err = NewServer()
	if err != nil {
		log.Fatalf("[error] : %v", err)
	}
	http.HandleFunc("/", handle)
	http.ListenAndServe(":8090", nil)

	os.Exit(0)
}

func handle(w http.ResponseWriter, req *http.Request) { 
	w.Header().Set("Content-Type", "application/json")
	data, err := server.Process(ctx, req)
	if err != nil {
		log.Infof("[error] : %s", err)
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(data)
	} else {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(data)
	}
}

// setupLogger sets up hooks to redirect stdout and stderr
func setupLogger() {
	log.SetOutput(ioutil.Discard)

	// set log level
	log.SetLevel(log.InfoLevel)
	if *debug {
		log.SetLevel(log.DebugLevel)
	}

	// add hook to send info, debug, warn level logs to stdout
	log.AddHook(&LogHook{
		Writer: os.Stdout,
		Loglevels: []log.Level{
			log.InfoLevel,
			log.DebugLevel,
			log.WarnLevel,
		},
	})

	// add hook to send panic, fatal, error logs to stderr
	log.AddHook(&LogHook{
		Writer: os.Stderr,
		Loglevels: []log.Level{
			log.PanicLevel,
			log.FatalLevel,
			log.ErrorLevel,
		},
	})
}

// Fire is called when logging function with current hook is called
// write to appropriate writer based on log level
func (hook *LogHook) Fire(entry *log.Entry) error {
	line, err := entry.String()
	if err != nil {
		return err
	}
	_, err = hook.Writer.Write([]byte(line))
	return err
}

// Levels defines log levels at which hook is triggered
func (hook *LogHook) Levels() []log.Level {
	return hook.Loglevels
}
