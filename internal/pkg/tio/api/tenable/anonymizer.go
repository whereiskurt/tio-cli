package tenable

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"strings"
	"sync"

	"github.com/whereiskurt/tio-cli/internal/pkg/tio"
	"github.com/whereiskurt/tio-cli/internal/pkg/tio/obfu"
)

type Anonymizer struct {
	Workers *sync.WaitGroup
 	ThreadSafe map[string]*sync.Mutex
  
	Debug func(string)
	Info  func(string)
	Warn  func(string)
	Error func(string)

	Debugf func(string, ...interface{})
	Infof  func(string, ...interface{})
	Warnf  func(string, ...interface{})
	Errorf func(string, ...interface{})

	RemappedId map[string]map[string]string

	CacheFolderWrite string

	CountScanId    int
	CountHistoryId int
	CountHostId    int
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

	a.CacheFolderWrite = config.CacheFolderWrite

	a.RemappedId = make(map[string]map[string]string)

	a.CountScanId = 0
	a.CountHistoryId = 0
	a.CountHostId = 0

	a.RemappedId["scanId.real"] = make(map[string]string)
	a.RemappedId["scanId.obfu"] = make(map[string]string)
	a.RemappedId["hostId.real"] = make(map[string]string)
	a.RemappedId["hostId.obfu"] = make(map[string]string)
	a.RemappedId["historyId.real"] = make(map[string]string)
	a.RemappedId["historyId.obfu"] = make(map[string]string)

	a.ThreadSafe = make(map[string]*sync.Mutex)
	a.ThreadSafe["scan"] = new(sync.Mutex)
	a.ThreadSafe["hist"] = new(sync.Mutex)
	a.ThreadSafe["host"] = new(sync.Mutex)

	a.Workers = new(sync.WaitGroup)

	return a
}

func (a *Anonymizer) RewriteCacheFilename(cacheFilename string) (newCacheFilename string) {
	parts := strings.Split(cacheFilename, string(os.PathSeparator))

	newCacheFilename = strings.Join(parts[1:], string(os.PathSeparator))
	newCacheFilename = a.CacheFolderWrite + string(os.PathSeparator) + newCacheFilename

	return newCacheFilename
}

func (a *Anonymizer) AnonHostId(scanId string, historyId string, hostId string) (value string) {
	a.ThreadSafe["host"].Lock()
	defer a.ThreadSafe["host"].Unlock()

	key := fmt.Sprintf("%v|%v|%v", scanId, historyId, hostId)
	value, ok := a.RemappedId["hostId.real"][key]

	if ok {
		return value
	}
	a.CountHostId = a.CountHostId + 1
	value = fmt.Sprintf("%d", a.CountHostId)
	a.RemappedId["hostId.real"][key] = value
	a.RemappedId["hostId.obfu"][value] = hostId
	
	return value
}
func (a *Anonymizer) DeAnonHostId(hostId string) (value string) {
	a.ThreadSafe["host"].Lock()
	defer a.ThreadSafe["host"].Unlock()

	key := fmt.Sprintf("%v", hostId)
	value, ok := a.RemappedId["hostId.obfu"][key]
	if !ok {
		value = hostId
	}
	return value
}

func (a *Anonymizer) AnonScanId(key string) (value string) {
	a.ThreadSafe["scan"].Lock()
	defer a.ThreadSafe["scan"].Unlock()

	value, ok := a.RemappedId["scanId.real"][key]
	if ok {
		return value
	}

	a.CountScanId = a.CountScanId + 1
	value = fmt.Sprintf("%d", a.CountScanId)
	a.RemappedId["scanId.real"][key] = value
	a.RemappedId["scanId.obfu"][value] = key

	return value
}
func (a *Anonymizer) DeAnonScanId(key string) (value string) {
	a.ThreadSafe["scan"].Lock()
	defer a.ThreadSafe["scan"].Unlock()

	value, ok := a.RemappedId["scanId.obfu"][key]
	if !ok {
		value = key
	}
	return value
}

func (a *Anonymizer) AnonHistoryId(key string) (value string) {
	a.ThreadSafe["hist"].Lock()
	defer a.ThreadSafe["hist"].Unlock()

	//If already mapped return same scanID same OBFU value
	value, ok := a.RemappedId["historyId.real"][key]
	if ok {
		return value
	}

	a.CountHistoryId = a.CountHistoryId + 1
	value = fmt.Sprintf("%d", a.CountHistoryId)
	a.RemappedId["historyId.real"][key] = value
	a.RemappedId["historyId.obfu"][value] = key

	return value
}
func (a *Anonymizer) DeAnonHistoryId(key string) (value string) {
	a.ThreadSafe["hist"].Lock()
	defer a.ThreadSafe["hist"].Unlock()

	value, ok := a.RemappedId["historyId.obfu"][key]
	if !ok {
		value = key
	}
	return value
}

func (a *Anonymizer) AnonymizeScanList(scans *ScanList) {
	for i := range scans.Scans {
		scans.Scans[i].Id = json.Number(a.AnonScanId(string(scans.Scans[i].Id)))
		scans.Scans[i].Name = obfu.PopularEnglishAnimalPhrase()
		scans.Scans[i].Owner = "someowner@example.com"
	}
	return
}

func (a *Anonymizer) AnonymizeScanDetail(scanId string, sd *ScanDetail) {
	sd.Info.Id = json.Number(a.AnonScanId(scanId))
	sd.Info.UUID = obfu.NewUUID()

	sd.Info.ScannerName = fmt.Sprintf("Scanner '%s'", strings.Title(obfu.Word()))
	sd.Info.PolicyName = fmt.Sprintf("Policy '%s'", strings.Title(obfu.Word()))
	sd.Info.Owner = fmt.Sprintf("ScanOwner@%s", obfu.Hostname("example.com"))

	t := []string{}
	for range strings.Split(sd.Info.Targets, ",") {
		t = append(t, obfu.FakeIpv4())
	}
	sd.Info.Targets = strings.Join(t, ",")

	if len(sd.History) == 0 {
		return
	}
	for i := range sd.History {
		historyId := fmt.Sprintf("%v", sd.History[i].HistoryId)
		sd.History[i].HistoryId = json.Number(a.AnonHistoryId(historyId))
		sd.History[i].UUID = obfu.NewUUID()
	}

	for i := range sd.Hosts {
		historyId := a.AnonHistoryId(string(sd.History[0].HistoryId))
		hostId := a.AnonHostId(scanId, historyId, fmt.Sprintf("%v", sd.Hosts[i].Id))

		sd.Hosts[i].Id = json.Number(hostId)
		sd.Hosts[i].HostIP = obfu.FakeIpv4()

		crit := rand.Intn(50)
		high := rand.Intn(50)
		med := rand.Intn(50)
		low := rand.Intn(50)

		sd.Hosts[i].SeverityCritical = json.Number(fmt.Sprintf("%d", crit))
		sd.Hosts[i].SeverityHigh = json.Number(fmt.Sprintf("%d", high))
		sd.Hosts[i].SeverityMedium = json.Number(fmt.Sprintf("%d", med))
		sd.Hosts[i].SeverityLow = json.Number(fmt.Sprintf("%d", low))

		sd.Hosts[i].SeverityTotal = json.Number(json.Number(fmt.Sprintf("%d", crit+high+med+low)))
	}

	for i := range sd.Vulnerabilities {
		sd.Vulnerabilities[i].Count = json.Number(fmt.Sprintf("%d", rand.Intn(200)))
		sd.Vulnerabilities[i].HostName = obfu.FakeIpv4()
	}

	return
}

func (a *Anonymizer) AnonymizeHostDetail(scanId string, historyId string, hd *HostDetail) {
	hd.Info.FQDN = obfu.Hostname("example.com")
	hd.Info.NetBIOS = hd.Info.FQDN
	hd.Info.HostIP = obfu.FakeIpv4()
	hd.Info.MACAddress = obfu.FakeMACAddress()

	for i := range hd.Vulnerabilities {
		hostId := fmt.Sprintf("%v", hd.Vulnerabilities[i].HostId)
		hd.Vulnerabilities[i].HostId = json.Number(a.AnonHostId(scanId, historyId, hostId))
		hd.Vulnerabilities[i].Count = json.Number(fmt.Sprintf("%d", rand.Intn(50)))
		hd.Vulnerabilities[i].HostName = hd.Info.HostIP //as per the Tenable output!
	}

	if len(hd.Info.OperatingSystem) == 0 {
		hd.Info.OperatingSystem = []string{"Windows 2020"}
	}
	return
}
