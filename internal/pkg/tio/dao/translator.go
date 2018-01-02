package dao

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/karlseguin/ccache"
	"github.com/whereiskurt/tio-cli/internal/pkg/tio"
	"github.com/whereiskurt/tio-cli/internal/pkg/tio/api/tenable"
	"github.com/whereiskurt/tio-cli/internal/pkg/tio/cache"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Translator struct {
	Config *tio.VulnerabilityConfig

  TranslatorCache  *cache.TranslatorCache
  PortalCache      *cache.PortalCache
  Memcache         *ccache.Cache
  ThreadSafe       *sync.Mutex
  Workers           *sync.WaitGroup
	IgnoreScanId     map[string]bool
	IncludeScanId    map[string]bool
	IgnoreHistoryId  map[string]bool
	IncludeHistoryId map[string]bool
	IgnoreAssetId    map[string]bool
	IncludeAssetId   map[string]bool

	Debug func(string)
	Info  func(string)
	Warn  func(string)
	Error func(string)

	Debugf func(string, ...interface{})
	Infof  func(string, ...interface{})
	Warnf  func(string, ...interface{})
	Errorf func(string, ...interface{})

	Stats *tio.Statistics
}

func NewTranslator(config *tio.VulnerabilityConfig) *Translator {
	t := new(Translator)

	t.ThreadSafe = new(sync.Mutex)
	t.Config = config
	t.TranslatorCache = cache.NewTranslatorCache(config.Base) //NOTE: Not implemented yet.
	t.PortalCache = cache.NewPortalCache(config.Base)
	t.Memcache = ccache.New(ccache.Configure().MaxSize(500000).ItemsToPrune(50))
  t.Workers = new(sync.WaitGroup)

	t.Stats = tio.NewStatistics()

	t.Debug = config.Base.Logger.Debug
	t.Debugf = config.Base.Logger.Debugf
	t.Info = config.Base.Logger.Info
	t.Infof = config.Base.Logger.Infof
	t.Warn = config.Base.Logger.Warn
	t.Warnf = config.Base.Logger.Warnf
	t.Error = config.Base.Logger.Error
	t.Errorf = config.Base.Logger.Errorf

	t.IncludeScanId = make(map[string]bool)
	t.IgnoreScanId = make(map[string]bool)
	t.IncludeHistoryId = make(map[string]bool)
	t.IgnoreHistoryId = make(map[string]bool)
	t.IncludeAssetId = make(map[string]bool)
	t.IgnoreAssetId = make(map[string]bool)

	for _, id := range strings.Split(t.Config.ScanId, ",") {
		t.IncludeScanId[id] = true
	}
	for _, id := range strings.Split(t.Config.IgnoreScanId, ",") {
		t.IgnoreScanId[id] = true
	}
	for _, id := range strings.Split(t.Config.HistoryId, ",") {
		t.IncludeHistoryId[id] = true
	}
	for _, id := range strings.Split(t.Config.IgnoreHistoryId, ",") {
		t.IgnoreHistoryId[id] = true
	}
	for _, id := range strings.Split(t.Config.AssetId, ",") {
		t.IncludeAssetId[id] = true
	}
	for _, id := range strings.Split(t.Config.IgnoreAssetId, ",") {
		t.IgnoreAssetId[id] = true
	}

	return t
}
func (trans *Translator) ShouldSkipScanId(scanId string) bool {
	var retSkip = false

	_, ignore := trans.IgnoreScanId[scanId]
	if ignore {
		retSkip = true
	}

	if len(trans.IncludeScanId) > 0 {
		_, include := trans.IncludeScanId[scanId]
		if !include {
			retSkip = true
		}
	}
	return retSkip
}

func (trans *Translator) GetScan(scanId string) (*Scan, error) {
	var memcacheKey = "translator:GetScan:" + scanId

	item := trans.Memcache.Get(memcacheKey)
	if item != nil {
		scan := item.Value().(Scan)
		return &scan, nil
	}

	scans, scanErr := trans.GetScans()
	if scanErr != nil {
		return nil, scanErr
	}

	for _, s := range scans {
		if s.ScanId == scanId {
			trans.Memcache.Set(memcacheKey, s, time.Minute*60)
			return &s, nil
		}
	}

	err := errors.New(fmt.Sprintf("Cannot find scanId %s", scanId))
	return nil, err
}

func (trans *Translator) GetScans() ([]Scan, error) {
	var scans []Scan
	var memcacheKey = "translator:GetScans"

	item := trans.Memcache.Get(memcacheKey)
	if item != nil {
		trans.Stats.Count("GetScans.Memcached")

		scans = item.Value().([]Scan)
		return scans, nil
	}
	trans.Stats.Count("GetScans")

	tenableScans, err := trans.getTenableScanList()
	if err != nil {
		trans.Errorf("GetScans: Cannot retrieve Tenable ScanList: '%s'", err)
		return nil, err
	}

	scans = trans.transformTenableScanList(*tenableScans)
	trans.Memcache.Set(memcacheKey, scans, time.Minute*60)

	return scans, nil
}

func (trans *Translator) getTenableScanList() (*tenable.ScanList, error) {
	var retScanList tenable.ScanList

	var portalUrl = trans.Config.Base.BaseUrl + "/scans"
	var memcacheKey = portalUrl
	item := trans.Memcache.Get(memcacheKey)
	if item != nil {
		trans.Stats.Count("GetTenableScanList.Memcached")

		retScanList = item.Value().(tenable.ScanList)
		return &retScanList, nil
	}

	trans.Stats.Count("GetTenableScanList.Memcached")

	raw, err := trans.PortalCache.Get(portalUrl)
	if err != nil {
		trans.Errorf("Couldn't get tenable.ScanList from PortalCache: %s", err)
		return nil, err
	}
	err = json.Unmarshal([]byte(string(raw)), &retScanList)
	if err != nil {
		trans.Errorf("Couldn't unmarshal tenable.ScanList: %s", err)
		return nil, err
	}

	trans.Memcache.Set(memcacheKey, retScanList, time.Minute*60)

	return &retScanList, nil
}
func (trans *Translator) transformTenableScanList(scanList tenable.ScanList) []Scan {
	var retScans []Scan

	for _, scan := range scanList.Scans {
		scanId := string(scan.Id)

		if trans.ShouldSkipScanId(scanId) {
			continue
		}

		r := new(Scan)
		r.ScanId = scanId
		r.UUID = scan.UUID
		r.Name = scan.Name
		r.Status = scan.Status
		r.Owner = scan.Owner
		r.UserPermissions = string(scan.UserPermissions)
		r.Enabled = fmt.Sprintf("%v", scan.Enabled)
		r.RRules = scan.RRules
		r.Timezone = scan.Timezone
		r.StartTime = scan.StartTime
		r.CreationDate = string(scan.CreationDate)
		r.LastModifiedDate = string(scan.LastModifiedDate)
		r.Timestamp = string(scanList.Timestamp)

		retScans = append(retScans, *r)

	}
	return retScans
}

func (trans *Translator) GoGetScanDetails(out chan ScanDetailRecord, concurrentWorkers int) (error) {
  var previousOffset, _ = strconv.Atoi(trans.Config.Previous)

  var scansChan = make(chan Scan)

  scans, err := trans.GetScans()
  if err != nil {
    trans.Errorf("Failed to get scans: %s", err) 
    return err
  }
  
  go func() {
    for _, s := range scans {
      scansChan <- s
    }
    close(scansChan)
  }()
  
  for i := 0; i < concurrentWorkers; i++ {
    trans.Workers.Add(1)
  
    go func() {
      for s := range scansChan {
        record, _ := trans.GetScanDetail(s.ScanId, previousOffset)
        if record != nil {
          out <- *record
        }
      }
      trans.Workers.Done()
    }()
  }
  
  trans.Workers.Wait()
  
  close(out)
  return nil
}

func (trans *Translator) GetScanDetail(scanId string, previousOffset int) (*ScanDetailRecord, error) {
	trans.Stats.Count("GetScanDetail")

	historyId, histErr := trans.getTenableHistoryId(scanId, previousOffset)
	if histErr != nil {
		trans.Errorf("GetScanDetail: Cannot retrieve Tenable Scan History Id: id:%s,offset:%s - %s", scanId, previousOffset, histErr)
		return nil, histErr
	}

	scanDetail, sdErr := trans.getTenableScanDetail(scanId, *historyId)
	if sdErr != nil {
		trans.Errorf("GetScanDetail: Cannot retrieve Tenable Scan Detail: id:%s, histid:%s, offset:%d - %s", scanId, *historyId, previousOffset, sdErr)
		return nil, sdErr
	}

	scanDetailRecord, transErr := trans.transformTenableScanDetail(scanId, *scanDetail)

	return scanDetailRecord, transErr
}

func (trans *Translator) transformTenableScanDetail(scanId string, detail tenable.ScanDetail) (*ScanDetailRecord, error) {
	var ret ScanDetailRecord

	var previousOffset, _ = strconv.Atoi(trans.Config.Previous)
	var depth, _ = strconv.Atoi(trans.Config.Depth)

	scan, scanErr := trans.GetScan(scanId)
	if scanErr != nil {
		trans.Errorf("%s", scanErr)
		return nil, scanErr
	}

	ret.ScanId = scanId
	ret.UUID = scan.UUID
	ret.Name = scan.Name
	ret.PolicyName = detail.Info.PolicyName
	ret.CreationDate = string(scan.CreationDate)
	ret.LastModifiedDate = string(scan.LastModifiedDate)
	ret.Status = scan.Status
	ret.Enabled = fmt.Sprintf("%t", scan.Enabled)
	ret.RRules = scan.RRules
	ret.Timezone = scan.Timezone
	ret.StartTime = scan.StartTime
	ret.PolicyName = detail.Info.PolicyName
	ret.TotalHistoryCount = fmt.Sprintf("%v", len(detail.History))

	for i := previousOffset; i < len(detail.History) && i < depth+previousOffset; i++ {
		historyId, histErr := trans.getTenableHistoryId(scanId, i)
		if histErr != nil {
			trans.Errorf("%s", histErr)
			return nil, histErr
		}

		histDetails, _ := trans.getTenableScanDetail(scanId, *historyId)

		hist := new(ScanDetailHistoryRecord)

		hist.HistoryId = fmt.Sprintf("%v", histDetails.History[i].HistoryId)
		hist.HostCount = fmt.Sprintf("%v", len(histDetails.Hosts))
		hist.LastModifiedDate = string(histDetails.History[i].LastModifiedDate)
		hist.CreationDate = string(histDetails.History[i].CreationDate)
		hist.Status = histDetails.History[i].Status

		for _, host := range histDetails.Hosts {
			var retHost HostScanPluginRecord

			var hostId = string(host.Id)
			retHost.HostId = hostId
			retHost.ScanId = scanId
			retHost.HistoryId = *historyId
			retHost.HistoryIndex = fmt.Sprintf("%v", i)

			trans.ThreadSafe.Lock()
			critsHist, _ := strconv.Atoi(hist.PluginCriticalCount)
			critsHost, _ := strconv.Atoi(string(host.SeverityCritical))
			hist.PluginCriticalCount = fmt.Sprintf("%v", critsHist+critsHost)
			highHist, _ := strconv.Atoi(hist.PluginHighCount)
			highHost, _ := strconv.Atoi(string(host.SeverityHigh))
			hist.PluginHighCount = fmt.Sprintf("%v", highHist+highHost)
			mediumHist, _ := strconv.Atoi(hist.PluginMediumCount)
			mediumHost, _ := strconv.Atoi(string(host.SeverityMedium))
			hist.PluginMediumCount = fmt.Sprintf("%v", mediumHist+mediumHost)
			lowHist, _ := strconv.Atoi(hist.PluginLowCount)
			lowHost, _ := strconv.Atoi(string(host.SeverityLow))
			hist.PluginLowCount = fmt.Sprintf("%v", lowHist+lowHost)
			hist.PluginTotalCount = fmt.Sprintf("%v", lowHist+lowHost+mediumHist+mediumHost+highHist+highHost+critsHist+critsHost)
			trans.ThreadSafe.Unlock()

			// hostDetailV1, detailErrV1 := trans.getTenableHostDetailV1(scanId, hostId, *historyId)
			// if detailErrV1 != nil {
			//   hostDetailV2, detailErrV2 := trans.getTenableHostDetailV2(scanId, hostId, *historyId)
			//   if detailErrV2 != nil {
			//     trans.Errorf("%s", detailErrV1)
			//     trans.Errorf("%s", detailErrV2)
			//     return nil, detailErrV2
			//   }
			// }

			hist.Hosts = append(hist.Hosts, retHost)
		}

		for _, vuln := range histDetails.Vulnerabilities {
			var retPlugin PluginRecord

			retPlugin.PluginId = string(vuln.PluginId)
			retPlugin.Name = vuln.Name
			retPlugin.Family = vuln.Family
			retPlugin.Count = string(vuln.Count)
			retPlugin.Severity = string(vuln.Severity)

			hist.Plugins = append(hist.Plugins, retPlugin)
		}

		ret.HistoryRecords = append(ret.HistoryRecords, *hist)
	}

	return &ret, nil
}

func (trans *Translator) getTenableHostDetailV1(scanId string, hostId string, historyId string) (*tenable.HostDetailV1, error) {
	return nil, nil
}
func (trans *Translator) getTenableHostDetailV2(scanId string, hostId string, historyId string) (*tenable.HostDetailV1, error) {
	return nil, nil
}

func (trans *Translator) getTenableScanDetail(scanId string, historyId string) (*tenable.ScanDetail, error) {
	var scanDetail tenable.ScanDetail

	var portalUrl = trans.Config.Base.BaseUrl + "/scans/" + scanId + "?history_id=" + historyId

	trans.Stats.Count("GetTenableScanDetail")

	var memcacheKey = portalUrl
	item := trans.Memcache.Get(memcacheKey)
	if item != nil {
		trans.Stats.Count("GetTenableScanDetail.Memcached")

		scanDetail = item.Value().(tenable.ScanDetail)
		return &scanDetail, nil
	}

	raw, err := trans.PortalCache.Get(portalUrl)
	if err != nil {
		trans.Errorf("Couldn't get tenable.ScanDetail from PortalCache: %s", err)
		return nil, err
	}
	err = json.Unmarshal([]byte(string(raw)), &scanDetail)
	if err != nil {
		trans.Errorf("Couldn't unmarshal tenable.ScanList: %s", err)
		return nil, err
	}

	return &scanDetail, nil
}
func (trans *Translator) getTenableHistoryId(scanId string, previousOffset int) (*string, error) {
	var retHistoryId string
	var scanDetail tenable.ScanDetail

	if trans.ShouldSkipScanId(scanId) {
		return nil, nil
	}

	var memcacheKey = fmt.Sprintf("%s:%s", scanId, previousOffset)
	item := trans.Memcache.Get(memcacheKey)
	if item != nil {

		trans.Stats.Count("GetTenableHistoryId.Memcached")

		retHistoryId = item.Value().(string)
		return &retHistoryId, nil
	}

	trans.Stats.Count("GetTenableHistoryId")

	var portalUrl = trans.Config.Base.BaseUrl + "/scans/" + scanId
	raw, err := trans.PortalCache.Get(portalUrl)
	if err != nil {
		trans.Errorf("Couldn't get tenable.ScanDetail from PortalCache: %s", err)
		return nil, err
	}
	err = json.Unmarshal([]byte(string(raw)), &scanDetail)
	if err != nil {
		trans.Errorf("Couldn't unmarshal tenable.ScanList: %s", err)
		return nil, err
	}

	if previousOffset > len(scanDetail.History)-1 {
		err := errors.New(fmt.Sprintf("Cannot get history id for offset - %d bigger than %d", previousOffset, len(scanDetail.History)-1))
		trans.Errorf("%s", err)
		return nil, err
	}

	//Sort histories by creation date DESC, to get offset history_id
	sort.Slice(scanDetail.History, func(i, j int) bool {
		iv, iverr := strconv.ParseInt(string(scanDetail.History[i].CreationDate), 10, 64)
		if iverr != nil {
			panic(iverr)
		}
		jv, jverr := strconv.ParseInt(string(scanDetail.History[j].CreationDate), 10, 64)
		if jverr != nil {
			panic(jverr)
		}
		return iv > jv
	})
	
	retHistoryId = string(scanDetail.History[previousOffset].HistoryId)

	trans.Memcache.Set(memcacheKey, retHistoryId, time.Minute*60)
	return &retHistoryId, nil
}
