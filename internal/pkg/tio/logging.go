package tio

import (
	"fmt"
	"os"
	"strconv"
	"sync"
	"time"
)

type Loggable interface {
	Debug(line string)
	Info(line string)
	Warn(line string)
	Error(line string)
	Debugf(fmt string, args ...interface{})
	Infof(fmt string, args ...interface{})
	Warnf(fmt string, args ...interface{})
	Errorf(fmt string, args ...interface{})
}

type Logger struct {
	LogFileHandle *os.File
	MirrorStdout  bool
	IsDebugLevel  bool
	IsInfoLevel   bool
	IsWarnLevel   bool
	IsErrorLevel  bool
	ThreadSafe    *sync.Mutex
}

func NewLogger(config *BaseConfig) *Logger {
	cmdVerbose := config.Verbose

	verbose, verboseErr := strconv.Atoi(cmdVerbose)
	if verboseErr != nil {
		panic(fmt.Sprintf("Invalid verbose setting: %v", verboseErr))
	} else if verbose < 0 || verbose > 5 {
		panic(fmt.Sprintf("Invalid verbose setting. Must be between 1 and 5."))
	}

	l := new(Logger)
	l.ThreadSafe = new(sync.Mutex)

	//Set to all to false
	l.IsDebugLevel = false
	l.IsInfoLevel = false
	l.IsWarnLevel = false
	l.IsErrorLevel = false

	//Set to true based on verbose level (1:ERROR,2:WARN,3:INFO,3:DEBUG)
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

	//Unless we are 'quietmode' we echo to STDOUT
	l.MirrorStdout = !config.QuietMode
	l.LogFileHandle = config.LogFileHandle

	return l
}

func (logger *Logger) Write(level string, line string) {
	lineout := time.Now().UTC().Format("2006-01-02T15:04:05.999Z") + " [" + level + "] " + line

	logger.ThreadSafe.Lock()
	fmt.Fprintln(logger.LogFileHandle, lineout)
	if logger.MirrorStdout {
		fmt.Fprintln(os.Stdout, lineout)
	}
	logger.ThreadSafe.Unlock()
}

func (log *Logger) Debugf(format string, args ...interface{}) {
	if log.IsDebugLevel {
		line := fmt.Sprintf(format, args...)
		log.Debug(line)
	}
	return
}

func (log *Logger) Debug(line string) {
	if log.IsDebugLevel {
		// pc := make([]uintptr, 10) // at least 1 entry needed
		// runtime.Callers(3, pc)
		// f := runtime.FuncForPC(pc[0])
		// file, codeline := f.FileLine(pc[0])
		// v := fmt.Sprintf("%s\n%s:%d", line, file, codeline)
		//
		// log.Write("DEBUG", v)
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
func (log *Logger) Infof(format string, args ...interface{}) {
	if log.IsInfoLevel {
		line := fmt.Sprintf(format, args...)
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
func (log *Logger) Warnf(format string, args ...interface{}) {
	if log.IsWarnLevel {
		line := fmt.Sprintf(format, args...)
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
func (log *Logger) Errorf(format string, args ...interface{}) {
	if log.IsErrorLevel {
		line := fmt.Sprintf(format, args...)
		log.Write("ERROR", line)
	}
	return
}
