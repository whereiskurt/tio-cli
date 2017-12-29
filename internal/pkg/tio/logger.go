package tio

import (
	"fmt"
	"os"
	"strconv"
	"time"
)

type Logger struct {
	MirrorStdout bool
	IsDebugLevel bool
	IsInfoLevel  bool
	IsWarnLevel  bool
	IsErrorLevel bool

	Log *os.File
}

func NewLogger(config *BaseConfig) *Logger {
	cmdVerbosityMode := config.VerbosityMode

	verbose, verboseErr := strconv.Atoi(cmdVerbosityMode)
	if verboseErr != nil {
		panic(fmt.Sprintf("Invalid verbose setting: %v", verboseErr))
	} else if verbose < 0 || verbose > 5 {
		panic(fmt.Sprintf("Invalid verbose setting. Must be between 1 and 5."))
	}

	l := new(Logger)

	l.IsDebugLevel = false
	l.IsInfoLevel = false
	l.IsWarnLevel = false
	l.IsErrorLevel = false

	switch verbose {
	case 0:
		config.QuietMode = true
		break
	case 1:
		l.IsErrorLevel = true
		break
	case 2:
		l.IsErrorLevel = true
		l.IsWarnLevel = true
		break
	case 3:
		l.IsErrorLevel = true
		l.IsWarnLevel = true
		l.IsInfoLevel = true
		break
	case 4:
		l.IsErrorLevel = true
		l.IsWarnLevel = true
		l.IsInfoLevel = true
		l.IsDebugLevel = true
		break
	case 5:
		l.IsErrorLevel = true
		l.IsWarnLevel = true
		l.IsInfoLevel = true
		l.IsDebugLevel = true
		config.QuietMode = false
		break
	}

	l.MirrorStdout = !config.QuietMode
	l.Log = config.Log

	return l
}

func (log *Logger) Write(level string, line string) {
	lineout := time.Now().Local().Format("2006-01-02T15:04:05.999Z") + " [" + level + "] " + line
	fmt.Fprintf(log.Log, lineout)
	if log.MirrorStdout {
		fmt.Fprintf(os.Stdout, lineout)
	}

}

func (log *Logger) Debug(line string) {
	if log.IsDebugLevel {
		log.Write("DEBUG", line)
	}
	return
}

func (log *Logger) Info(line string) {
	if log.IsInfoLevel {
		log.Write("INFO", line)
	}
	return
}

func (log *Logger) Warn(line string) {
	if log.IsWarnLevel {
		log.Write("WARN", line)
	}
	return
}

func (log *Logger) Error(line string) {
	if log.IsErrorLevel {
		log.Write("ERROR", line)
	}
	return
}
