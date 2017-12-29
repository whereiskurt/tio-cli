package tio

import (
  "strconv"
  "fmt"
)
type Logger struct {
	MirrorStdout bool
	IsDebugLevel bool
	IsInfoLevel bool
	IsWarnLevel bool
	IsErrorLevel bool
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

  switch {
    case verbose == 0:
      config.QuietMode = true
      break
    case verbose > 0:
      l.IsErrorLevel = true
    case verbose > 1: 
      l.IsWarnLevel = true
    case verbose > 2: 
      l.IsInfoLevel = true
    case verbose > 3: 
      l.IsDebugLevel = true
  }

  l.MirrorStdout = !config.QuietMode

	return l
}