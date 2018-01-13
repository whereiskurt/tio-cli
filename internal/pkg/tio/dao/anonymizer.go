package dao

import (
  "encoding/json"
  "github.com/whereiskurt/tio-cli/internal/pkg/tio"
  "github.com/whereiskurt/tio-cli/internal/pkg/tio/api/tenable"
  "sync"
  "fmt"
)

type Anonymizer struct {
  Worker *sync.WaitGroup

  Debug func(string)
  Info  func(string)
  Warn  func(string)
  Error func(string)

  Debugf func(string, ...interface{})
  Infof  func(string, ...interface{})
  Warnf  func(string, ...interface{})
  Errorf func(string, ...interface{})

  RemappedId map[string]map[string]string

  CountScanId int
  CountHistoryId int
  CountHostId int
}

func NewAnonymizer(config *tio.VulnerabilityConfig) (a *Anonymizer) {
	a = new(Anonymizer)

  a.Debug = config.Base.Logger.Debug
  a.Debugf = config.Base.Logger.Debugf
  a.Info = config.Base.Logger.Info
  a.Infof = config.Base.Logger.Infof
  a.Warn = config.Base.Logger.Warn
  a.Warnf = config.Base.Logger.Warnf
  a.Error = config.Base.Logger.Error
  a.Errorf = config.Base.Logger.Errorf

  a.RemappedId = make(map[string]map[string]string)

  a.CountScanId = 696968
  a.CountHistoryId = 0
  a.CountHostId = 0

  a.RemappedId["scanId.real"] = make(map[string]string)
  a.RemappedId["scanId.obfu"] = make(map[string]string)

  a.RemappedId["hostId.real"] = make(map[string]string)
  a.RemappedId["hostId.obfu"] = make(map[string]string)
  a.RemappedId["historyId.real"] = make(map[string]string)
  a.RemappedId["historyId.obfu"] = make(map[string]string)

	return a
}

func (a *Anonymizer) AnonScanId(key string) (value string) {
  a.CountScanId = a.CountScanId + 1
  value = fmt.Sprintf("%d", a.CountScanId)
  a.RemappedId["scanId.real"][key]  = value
  a.RemappedId["scanId.obfu"][value]  = key
  return value
}
func (a *Anonymizer) DeAnonScanId(key string) (value string) {
  value, ok := a.RemappedId["scanId.obfu"][key]
  if !ok {
    a.Warnf("Failed lookup for: %v", key)
    return key
  }
  return value
}

func (a *Anonymizer) AnonHistoryId(key string) (value string) {

  //Already mapped! Give same scanID same OBFU value
  value, ok := a.RemappedId["historyId.real"][key]
  if ok {
    return value
  } 

  a.CountHistoryId = a.CountHistoryId + 1
  value = fmt.Sprintf("%d", a.CountHistoryId)
  a.RemappedId["historyId.real"][key]  = value
  a.RemappedId["historyId.obfu"][value]  = key

  return value
}

func (a *Anonymizer) DeAnonHistoryId(key string) (value string) {
  value, ok := a.RemappedId["historyId.obfu"][key]
  if !ok {
    a.Warnf("Failed lookup for: %v", key)
    return key
  }
  return value
}


func (a *Anonymizer) AnonymizeScanList(scans tenable.ScanList) {
  for i, _ := range scans.Scans  {
    scans.Scans[i].Id = json.Number(a.AnonScanId(string(scans.Scans[i].Id)))
  }
  return
}

func (a *Anonymizer) AnonymizeScanDetail(sd tenable.ScanDetail) {

  sd.Info.Id = json.Number(a.AnonScanId(string(sd.Info.Id)))
  for i, _ := range sd.History {
    historyId := fmt.Sprintf("%v", sd.History[i].HistoryId)
    sd.History[i].HistoryId = json.Number( a.AnonHistoryId( historyId ))
    a.Errorf("History id overwritten: %v with %v", historyId, sd.History[i].HistoryId )
  }

  return
}
