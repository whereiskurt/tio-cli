package dao

import (
	"errors"
	"fmt"
	"github.com/karlseguin/ccache"
	"github.com/whereiskurt/tio-cli/internal/pkg/tio"
	"github.com/whereiskurt/tio-cli/internal/pkg/tio/api/tenable"
	"github.com/whereiskurt/tio-cli/internal/pkg/tio/cache"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Translator struct {
	Config *tio.VulnerabilityConfig

	TranslatorCache *cache.TranslatorCache
	PortalCache     *cache.PortalCache
	Memcache        *ccache.Cache
	ThreadSafe      *sync.Mutex

	Workers          map[string]*sync.WaitGroup
	IgnoreScanId     map[string]bool
	IncludeScanId    map[string]bool
	IgnorePluginId   map[string]bool
	IncludePluginId  map[string]bool
	IgnoreHistoryId  map[string]bool
	IncludeHistoryId map[string]bool
	IgnoreAssetId    map[string]bool
	IncludeAssetId   map[string]bool

	Anonymizer *tenable.Anonymizer 

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

func NewTranslator(config *tio.VulnerabilityConfig) (t *Translator) {
	t = new(Translator)

	t.ThreadSafe = new(sync.Mutex)
	t.Config = config
	t.TranslatorCache = cache.NewTranslatorCache(config.Base) //NOTE: Not implemented yet.
	t.PortalCache = cache.NewPortalCache(config.Base)
	t.Memcache = ccache.New(ccache.Configure().MaxSize(500000).ItemsToPrune(50))
	t.Workers = make(map[string]*sync.WaitGroup)
	t.Workers["host"] = new(sync.WaitGroup)
	t.Workers["detail"] = new(sync.WaitGroup)
	t.Workers["plugin"] = new(sync.WaitGroup)

	t.Stats = tio.NewStatistics()
	t.Anonymizer = nil
	
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
	t.IncludePluginId = make(map[string]bool)
	t.IgnorePluginId = make(map[string]bool)

	for _, id := range strings.Split(t.Config.ScanId, ",") {
		if id != "" {
			t.IncludeScanId[id] = true
		}
	}
	for _, id := range strings.Split(t.Config.IgnoreScanId, ",") {
		if id != "" {
			t.IgnoreScanId[id] = true
		}
	}
	for _, id := range strings.Split(t.Config.HistoryId, ",") {
		if id != "" {
			t.IncludeHistoryId[id] = true
		}
	}
	for _, id := range strings.Split(t.Config.IgnoreHistoryId, ",") {
		if id != "" {
			t.IgnoreHistoryId[id] = true
		}
	}
	for _, id := range strings.Split(t.Config.AssetId, ",") {
		if id != "" {
			t.IncludeAssetId[id] = true
		}
	}
	for _, id := range strings.Split(t.Config.IgnoreAssetId, ",") {
		if id != "" {
			t.IgnoreAssetId[id] = true
		}
	}
	for _, id := range strings.Split(t.Config.IgnorePluginId, ",") {
		if id != "" {
			t.IgnorePluginId[id] = true
		}
	}
	for _, id := range strings.Split(t.Config.PluginId, ",") {
		if id != "" {
			t.IncludePluginId[id] = true
		}
	}

	return t
}

func (trans *Translator) ShouldSkipScanId(scanId string) (skip bool) {
	skip = false

	if trans.Anonymizer != nil {
		scanId = trans.Anonymizer.DeAnonScanId(scanId)
	}

	_, ignore := trans.IgnoreScanId[scanId]
	if ignore {
		skip = true
	}

	if len(trans.IncludeScanId) > 0 {
		_, include := trans.IncludeScanId[scanId]
		if !include {
			skip = true
		}
	}
	return skip
}

func (trans *Translator) ShouldSkipAssetId(AssetId string) (skip bool) {
	skip = false

	_, ignore := trans.IgnoreAssetId[AssetId]
	if ignore {
		skip = true
	}

	if len(trans.IncludeAssetId) > 0 {
		_, include := trans.IncludeAssetId[AssetId]
		if !include {
			skip = true
		}
	}
	return skip
}

func (trans *Translator) ShouldSkipPluginId(pluginId string) (skip bool) {
	skip = false

	_, ignore := trans.IgnorePluginId[pluginId]
	if ignore {
		skip = true
	}

	if len(trans.IncludePluginId) > 0 {
		_, include := trans.IncludePluginId[pluginId]
		if !include {
			skip = true
		}
	}
	return skip
}

func (trans *Translator) ShouldSkipHistoryId(historyId string) (skip bool) {
	skip = false

	_, ignore := trans.IgnoreHistoryId[historyId]
	if ignore {
		skip = true
	}

	if len(trans.IgnoreHistoryId) > 0 {
		_, include := trans.IgnoreHistoryId[historyId]
		if !include {
			skip = true
		}
	}
	return skip
}

func (trans *Translator) GetScans() (scans []Scan, err error) {
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
		return scans, err
	}

	scans = trans.fromScanList(tenableScans)
	trans.Memcache.Set(memcacheKey, scans, time.Minute*60)

	return scans, nil
}

func (trans *Translator) GetScan(scanId string) (scan Scan, err error) {

	var memcacheKey = "translator:GetScan:" + scanId

	item := trans.Memcache.Get(memcacheKey)
	if item != nil {
		scan = item.Value().(Scan)
		return scan, nil
	}

	scans, err := trans.GetScans()
	if err != nil {
		return scan, err
	}

	var found bool = false
	for _, s := range scans {
		if s.ScanId == scanId {
			found = true
			scan = s
			break
		}
	}

	if found {
		trans.Memcache.Set(memcacheKey, scan, time.Minute*60)
	} else {
		err = errors.New(fmt.Sprintf("Cannot find scanId %s", scanId))
		trans.Errorf("%s", err)
	}

	return scan, err
}

func (trans *Translator) GoGetHostDetails(out chan ScanHistory, concurrentWorkers int) (err error) {
	var chanScanDetails = make(chan ScanHistory, 2)

	defer close(out)

	for i := 0; i < concurrentWorkers; i++ {
		trans.Workers["host"].Add(1)

		go func() {
			for sd := range chanScanDetails {

				if len(sd.ScanHistoryDetails) < 1 {
					continue
				}

				//For each history in the scan
				for h, hist := range sd.ScanHistoryDetails {
					if len(hist.Host) < 1 {
						continue
					}

					//For each host in the history
					for hostKey, host := range hist.Host {
						record, err := trans.GetHostDetail(sd.Scan, host, host.ScanDetail)
						if err != nil {
							trans.Warnf("Couldn't retrieve host details. Removing host from list: %s", err)
							delete(sd.ScanHistoryDetails[h].Host, hostKey)
							continue
						}

						if trans.ShouldSkipAssetId(host.HostId) {
							delete(sd.ScanHistoryDetails[h].Host, hostKey)
							continue
						}

						skipPlugin := false
						for k, p := range record.Plugin {
							if trans.ShouldSkipPluginId(string(p.PluginId)) {
								delete(record.Plugin, k)
								delete(hist.HostPlugin, k)
								skipPlugin = true
								continue
							}
						}
						if skipPlugin && len(record.Plugin) == 0 {
							delete(sd.ScanHistoryDetails[h].Host, hostKey)
							continue
						}

						host.HostDetail = record
						sd.ScanHistoryDetails[h].Host[hostKey] = host
					}
				}
				out <- sd
			}

			trans.Workers["host"].Done()

			return
		}()
	}

	err = trans.GoGetScanHistoryDetails(chanScanDetails, concurrentWorkers)

	trans.Workers["host"].Wait()

	return err
}
func (trans *Translator) GetHostDetail(scan Scan, hsd HostScanDetailSummary, scanDetail ScanHistoryDetail) (record HostScanDetail, err error) {

	scanId := scan.ScanId
	hostId := hsd.HostId
	historyId := scanDetail.HistoryId

	hd, err := trans.getTenableHostDetail(scanId, hostId, historyId)
	if err != nil {
		trans.Warnf("Couldn't unmarshal tenable.HostDetails for scan id:%s:host%s:histId:%s: %s", scanId, hostId, historyId, err)
		return record, err
	}

	record, err = trans.fromHostDetailSummary(hsd, hd)

	hsd.HostDetail = record

	return record, err
}

func (trans *Translator) GoGetScanHistoryDetails(out chan ScanHistory, concurrentWorkers int) (err error) {
	var previousOffset, _ = strconv.Atoi(trans.Config.Previous)

	var scansChan = make(chan Scan)

	defer close(out)

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
		trans.Workers["detail"].Add(1)
		go func() {
			for s := range scansChan {
				record, err := trans.GetScanHistory(s.ScanId, previousOffset)
				if err == nil {
					out <- record
				}
			}
			trans.Workers["detail"].Done()
		}()
	}
	trans.Workers["detail"].Wait()

	return nil
}
func (trans *Translator) GetScanHistory(scanId string, previousOffset int) (record ScanHistory, err error) {
	trans.Stats.Count("GetScanHistory")

	historyId, err := trans.getTenableHistoryId(scanId, previousOffset)
	if err != nil {
		trans.Errorf("GetScanHistory: Cannot retrieve historyid for scanid '%s' at offset '%s': %s", scanId, previousOffset, err)
		return record, err
	}
	scanDetail, err := trans.getTenableScanDetail(scanId, historyId)

	if err != nil {
		trans.Errorf("GetScanHistory: Cannot retrieve Tenable Scan Detail: id:%s, histid:%s, offset:%d - %s", scanId, historyId, previousOffset, err)
		return record, err
	}

	record, err = trans.fromScanDetail(scanId, scanDetail)

	return record, err
}

func (trans *Translator) GetScannerTZ(scan Scan) (scannerTZ string) {
	//TODO: Actually do the look-up and it is fails return defaultTZ
	//scan.ScannerName
	scannerTZ = trans.Config.Base.DefaultTimezone
	return scannerTZ
}
