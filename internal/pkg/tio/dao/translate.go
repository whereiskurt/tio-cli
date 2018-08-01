package dao

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/karlseguin/ccache"
	"github.com/whereiskurt/tio-cli/internal/pkg/tio"
	"github.com/whereiskurt/tio-cli/internal/pkg/tio/api/tenable"
	"github.com/whereiskurt/tio-cli/internal/pkg/tio/cache"
)

const (
	STAT_GETSCANS_MEMCACHE tio.StatType = "tio.dao.GetScans.Memcached"
	STAT_GETSCANS          tio.StatType = "tio.dao.GetScans.CallCount"

	STAT_GETASCAN_MEMCACHE tio.StatType = "tio.dao.GetScan.Memcached"
	STAT_GETASCAN          tio.StatType = "tio.dao.GetScan.CallCount"
	STAT_GETTAGS_MEMCACHE  tio.StatType = "tio.dao.GetTags.Memcached"
	STAT_GETTAGS           tio.StatType = "tio.dao.GetTags.CallCount"

	STAT_GETHOSTDETAIL          tio.StatType = "tio.dao.GetHostDetail.CallCount"
	STAT_GETHOSTDETAIL_MEMCACHE tio.StatType = "tio.dao.GetHostDetail.Memcached"
	STAT_GETHOSTDETAIL_ERROR    tio.StatType = "tio.dao.GetHostDetail.ErrorBadData"

	STAT_GETSCANHISTORY          tio.StatType = "tio.dao.GetScanHistory.CallCount"
	STAT_GETSCANHISTORY_MEMCACHE tio.StatType = "tio.dao.GetScanHistory.Memcached"
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

	IgnoreAssetId  map[string]bool
	IncludeAssetId map[string]bool

	IgnoreHostId  map[string]bool
	IncludeHostId map[string]bool

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
	t.IncludeHostId = make(map[string]bool)
	t.IgnoreHostId = make(map[string]bool)

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
	for _, id := range strings.Split(t.Config.AssetUUID, ",") {
		if id != "" {
			t.IncludeAssetId[id] = true
		}
	}
	for _, id := range strings.Split(t.Config.IgnoreAssetUUID, ",") {
		if id != "" {
			t.IgnoreAssetId[id] = true
		}
	}
	for _, id := range strings.Split(t.Config.HostId, ",") {
		if id != "" {
			t.IncludeHostId[id] = true
		}
	}
	for _, id := range strings.Split(t.Config.IgnoreHostId, ",") {
		if id != "" {
			t.IgnoreHostId[id] = true
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

func (trans *Translator) GetTagValues() (tags tenable.TagValues, err error) {

	var memcacheKey = "translator:GetTagValue:ALL"

	item := trans.Memcache.Get(memcacheKey)
	if item != nil {
		tags = item.Value().(tenable.TagValues)
		return tags, nil
	}

	tags, err = trans.getTenableTagValues()
	if err != nil {
		return tags, err
	}

	trans.Memcache.Set(memcacheKey, tags, time.Minute*60)

	return tags, err
}

func (trans *Translator) GetTagUUID(categoryName string, value string) (tagUUID string, err error) {
	var memcacheKey = categoryName + ":" + value
	item := trans.Memcache.Get(memcacheKey)
	if item != nil {
		tagUUID = item.Value().(string)
		return tagUUID, nil
	}

	tags, err := trans.getTenableTagValues()
	for _, v := range tags.Values {
		if categoryName == v.CategoryName && v.Value == value {
			tagUUID = v.UUID
			break
		}
	}

	if tagUUID == "" {
		err = errors.New(fmt.Sprintf("Couldn't find tag UUID for catgeory '%s' and value '%s'", categoryName, value))
		return tagUUID, err
	}

	trans.Memcache.Set(memcacheKey, tagUUID, time.Minute*60)

	return tagUUID, nil
}

func (trans *Translator) GetTagCategories() (tags tenable.TagCategories, err error) {
	trans.Stats.Count(STAT_GETTAGS)

	var memcacheKey = "translator:GetTagCategory:ALL"

	item := trans.Memcache.Get(memcacheKey)
	if item != nil {
		trans.Stats.Count(STAT_GETTAGS_MEMCACHE)
		tags = item.Value().(tenable.TagCategories)
		return tags, nil
	}

	tags, err = trans.getTenableTagCategories()
	if err != nil {
		return tags, err
	}

	trans.Memcache.Set(memcacheKey, tags, time.Minute*60)

	return tags, err
}

func (trans *Translator) GetScans() (scans []Scan, err error) {
	trans.Stats.Count(STAT_GETSCANS)

	var memcacheKey = "translator:GetScans"
	item := trans.Memcache.Get(memcacheKey)
	if item != nil {
		trans.Stats.Count(STAT_GETSCANS_MEMCACHE)

		scans = item.Value().([]Scan)
		return scans, nil
	}

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
	trans.Stats.Count(STAT_GETASCAN)

	var memcacheKey = "translator:GetScan:" + scanId

	item := trans.Memcache.Get(memcacheKey)
	if item != nil {
		trans.Stats.Count(STAT_GETASCAN_MEMCACHE)
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

func (trans *Translator) GetAsset(assetUUID string) (asset AssetDetail, err error) {
	tenableAsset, err := trans.getTenableAsset(assetUUID)

	asset.UUID = tenableAsset.UUID

	for _, t := range tenableAsset.Tags {
		var tag AssetTagDetail
		tag.UUID = t.UUID
		tag.CategoryName = t.CategoryName
		tag.Value = t.Value
		tag.AddedBy = t.AddedBy
		tag.AddedAt = t.AddedAt
		tag.Source = t.Source

		asset.Tags = append(asset.Tags, tag)
	}

	return asset, err
}

func (trans *Translator) GoGetHostDetails(out chan ScanHistory, concurrentWorkers int) (err error) {
	var chanScanDetails = make(chan ScanHistory, 2)

	defer close(out)

	for i := 0; i < concurrentWorkers; i++ {
		trans.Workers["host"].Add(1)

		go func() {
			for sd := range chanScanDetails {

				//if len(sd.ScanHistoryDetails) < 1 {
				//  continue
				//}

				//For each history in the scan
				for h, hist := range sd.ScanHistoryDetails {
					if len(hist.Host) < 1 {
						continue
					}

					//For each host in the history
					for hostKey, host := range hist.Host {
						record, err := trans.GetHostDetail(host)
						if err != nil {
							if !trans.Config.Base.OfflineMode {
								trans.Warnf("Couldn't retrieve host details. Removing host from list: %s", err)
							}
							delete(sd.ScanHistoryDetails[h].Host, hostKey)
							continue
						}

						if trans.ShouldSkipAssetId(host.Asset.UUID) || trans.ShouldSkipHostId(host.HostId) {
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
func (trans *Translator) GetHostDetail(host HostScanSummary) (record HostScanDetail, err error) {
	trans.Stats.Count(STAT_GETHOSTDETAIL)

	scan := host.ScanDetail.Scan
	scanDetail := host.ScanDetail
	scanId := scan.ScanId
	historyId := scanDetail.HistoryId
	hostId := host.HostId

	var memcacheKey = fmt.Sprintf("translator:GetHostDetail:%s%s%s", scanId, historyId, hostId)
	item := trans.Memcache.Get(memcacheKey)
	if item != nil {
		trans.Stats.Count(STAT_GETHOSTDETAIL_MEMCACHE)
		record = item.Value().(HostScanDetail)
		return record, nil
	}

	hd, err := trans.getTenableHostDetail(scanId, hostId, historyId)
	if err != nil {
		trans.Stats.Count(STAT_GETHOSTDETAIL_ERROR)
		if !trans.Config.Base.OfflineMode {
			trans.Warnf("Couldn't unmarshal tenable.HostDetails for scan id:%s:host%s:histId:%s: %s", scanId, hostId, historyId, err)
		}
		return record, err
	}

	record, err = trans.fromHostDetailSummary(host, hd)

	host.HostDetail = record

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
				record, _ := trans.GetScanHistory(s.ScanId, previousOffset)
				out <- record
			}
			trans.Workers["detail"].Done()
		}()
	}
	trans.Workers["detail"].Wait()

	return nil
}
func (trans *Translator) GetScanHistory(scanId string, previousOffset int) (record ScanHistory, err error) {
	trans.Stats.Count(STAT_GETSCANHISTORY)

	var memcacheKey = fmt.Sprintf("translator:GetScanHistory:%s:%d", scanId, previousOffset)

	item := trans.Memcache.Get(memcacheKey)
	if item != nil {
		trans.Stats.Count(STAT_GETSCANHISTORY_MEMCACHE)
		record = item.Value().(ScanHistory)
		return record, nil
	}

	historyId, err := trans.getTenableHistoryId(scanId, previousOffset)
	if err != nil {
		trans.Errorf("GetScanHistory: Cannot retrieve historyid for scanid '%s' at offset '%d': %s", scanId, previousOffset, err)
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

func (trans *Translator) fromHostDetailSummary(hsd HostScanSummary, hd tenable.HostDetail) (host HostScanDetail, err error) {

	tz := trans.GetScannerTZ(hsd.ScanDetail.Scan)

	host.IP = hd.Info.HostIP
	host.FQDN = hd.Info.FQDN
	host.NetBIOS = hd.Info.NetBIOS
	host.MACAddresses = strings.Replace(hd.Info.MACAddress, "\n", ",", -1)
	host.OperatingSystems = strings.Join(hd.Info.OperatingSystem, ",")

	start, tmStart, err := trans.FromNoTZ(string(hd.Info.HostStart), tz)
	host.ScanStartUnix = fmt.Sprintf("%v", tmStart.In(time.Local).Unix())
	host.ScanStart = start

	end, tmEnd, err := trans.FromNoTZ(string(hd.Info.HostEnd), tz)
	host.ScanEndUnix = fmt.Sprintf("%v", tmEnd.In(time.Local).Unix())
	host.ScanEnd = end

	host.ScanDuration = fmt.Sprintf("%v", tmEnd.Sub(tmStart))

	host.Plugin = make(map[string]PluginDetailSummary)

	for _, v := range hd.Vulnerabilities {
		var p PluginDetailSummary
		p.PluginId = string(v.PluginId)
		p.Name = v.PluginName
		p.Family = v.PluginFamily
		p.Count = string(v.Count)
		p.Severity = string(v.Severity)
		host.Plugin[p.PluginId] = p
	}

	return host, nil
}

func (trans *Translator) fromScanList(scanList tenable.ScanList) []Scan {
	var scans []Scan

	for _, s := range scanList.Scans {

		if trans.ShouldSkipScanId(string(s.Id)) {
			continue
		}

		scanId := string(s.Id)
		scan := new(Scan)
		scan.ScanId = scanId
		scan.UUID = s.UUID
		scan.Name = s.Name
		scan.Status = s.Status
		scan.Owner = s.Owner
		scan.UserPermissions = string(s.UserPermissions)
		scan.Enabled = fmt.Sprintf("%v", s.Enabled)
		scan.RRules = s.RRules
		scan.Timezone = s.Timezone
		scan.StartTime = s.StartTime
		scan.CreationDate = string(s.CreationDate)
		scan.LastModifiedDate = string(s.LastModifiedDate)
		scan.Timestamp = string(scanList.Timestamp)

		scans = append(scans, *scan)
	}

	return scans
}

func (trans *Translator) fromScanDetail(scanId string, detail tenable.ScanDetail) (record ScanHistory, err error) {
	var previousOffset, _ = strconv.Atoi(trans.Config.Previous)
	var depth, _ = strconv.Atoi(trans.Config.Depth)

	scan, err := trans.GetScan(scanId)
	if err != nil {
		trans.Errorf("%s", err)
		return record, err
	}

	record.Scan.ScanId = scanId
	record.Scan.UUID = scan.UUID
	record.Scan.Name = scan.Name
	record.Scan.PolicyName = detail.Info.PolicyName
	record.Scan.Owner = detail.Info.Owner
	record.Scan.Targets = detail.Info.Targets
	record.Scan.CreationDate = string(scan.CreationDate)
	record.Scan.LastModifiedDate = string(scan.LastModifiedDate)
	record.Scan.Status = scan.Status
	record.Scan.Enabled = fmt.Sprintf("%s", scan.Enabled)
	record.Scan.RRules = scan.RRules
	record.Scan.Timezone = scan.Timezone
	record.Scan.StartTime = scan.StartTime
	record.Scan.PolicyName = detail.Info.PolicyName
	record.ScanHistoryCount = fmt.Sprintf("%v", len(detail.History))
	record.Scan.ScannerName = detail.Info.ScannerName

	for i := previousOffset; i < len(detail.History) && i < depth+previousOffset; i++ {
		var hist = new(ScanHistoryDetail)

		hist.Scan = record.Scan

		historyId, err := trans.getTenableHistoryId(scanId, i)
		if err != nil {
			trans.Errorf("HistoryID not available for scan '%s' offset '%d' - %s", scanId, i, err)
			return record, err
		}

		if trans.ShouldSkipHistoryId(historyId) {
			continue
		}

		histDetails, err := trans.getTenableScanDetail(scanId, historyId)
		if err != nil {
			trans.Errorf("%s", err)
			return record, err
		}

		//AssetId lookup and mapping
		amap, err := trans.getTenableAssetHostMap(scanId, historyId)
		if err != nil {
			trans.Errorf("Cannot map hostid to assetids: %s", err)
			return record, err
		}

		hist.HostAssetMap = make(map[string]string)
		for _, value := range amap.Assets {
			hist.HostAssetMap[string(value.HostId)] = value.UUID
		}

		hist.HistoryId = fmt.Sprintf("%v", histDetails.History[i].HistoryId)
		hist.HostCount = fmt.Sprintf("%v", len(histDetails.Hosts))
		hist.LastModifiedDate = string(histDetails.History[i].LastModifiedDate)
		hist.CreationDate = string(histDetails.History[i].CreationDate)
		hist.Status = histDetails.History[i].Status

		start := histDetails.Info.Start
		end := histDetails.Info.End

		rawScanStart, errParseStart := strconv.ParseInt(string(start), 10, 64)
		if errParseStart != nil {
			rawScanStart = int64(0)
			trans.Warnf("hist.Start: Failed to parse value '%s' for scan '%s':id:%s:histid:%s (status: %s). Setting to zero.", string(start), record.Scan.Name, record.Scan.ScanId, historyId, hist.Status)
		}

		rawScanEnd, errParseEnd := strconv.ParseInt(string(end), 10, 64)
		if errParseEnd != nil {
			rawScanEnd = rawScanStart
			trans.Warnf("hist.End: Failed to parse value '%s' for scan name:'%s':id:%s:histid:%s (status: %s). Setting to %s", string(end), record.Scan.Name, record.Scan.ScanId, historyId, hist.Status, string(start))
		}

		unixScanStart := time.Unix(rawScanStart, 0)
		unixScanEnd := time.Unix(rawScanEnd, 0)

		hist.ScanStart = fmt.Sprintf("%v", unixScanStart)
		hist.ScanStartUnix = fmt.Sprintf("%s", string(start))
		hist.ScanEnd = fmt.Sprintf("%v", unixScanEnd)
		hist.ScanEndUnix = fmt.Sprintf("%s", string(end))
		hist.ScanDuration = fmt.Sprintf("%v", unixScanEnd.Sub(unixScanStart))

		hist.Host = make(map[string]HostScanSummary)

		for _, host := range histDetails.Hosts {
			var retHost HostScanSummary
			var hostId = string(host.Id)

			critsHist, _ := strconv.Atoi(hist.PluginCriticalCount)
			critsHost, _ := strconv.Atoi(string(host.SeverityCritical))
			highHist, _ := strconv.Atoi(hist.PluginHighCount)
			highHost, _ := strconv.Atoi(string(host.SeverityHigh))
			mediumHist, _ := strconv.Atoi(hist.PluginMediumCount)
			mediumHost, _ := strconv.Atoi(string(host.SeverityMedium))
			lowHist, _ := strconv.Atoi(hist.PluginLowCount)
			lowHost, _ := strconv.Atoi(string(host.SeverityLow))

			retHost.HostId = hostId
			retHost.ScanDetail.Scan.ScanId = scanId
			retHost.ScanDetail.HistoryId = historyId
			retHost.ScanDetail.HistoryIndex = fmt.Sprintf("%v", i)

			retHost.PluginCriticalCount = fmt.Sprintf("%v", critsHost)
			retHost.PluginHighCount = fmt.Sprintf("%v", highHost)
			retHost.PluginMediumCount = fmt.Sprintf("%v", mediumHost)
			retHost.PluginLowCount = fmt.Sprintf("%v", lowHost)
			retHost.PluginTotalCount = fmt.Sprintf("%v", lowHost+mediumHost+highHost+critsHost)

			retHost.Asset, _ = trans.GetAsset(hist.HostAssetMap[hostId])

			hist.Host[hostId] = retHost

			//Running COUNT for the historical
			hist.PluginCriticalCount = fmt.Sprintf("%v", critsHist+critsHost)
			hist.PluginHighCount = fmt.Sprintf("%v", highHist+highHost)
			hist.PluginMediumCount = fmt.Sprintf("%v", mediumHist+mediumHost)
			hist.PluginLowCount = fmt.Sprintf("%v", lowHist+lowHost)
			hist.PluginTotalCount = fmt.Sprintf("%v", lowHist+lowHost+mediumHist+mediumHost+highHist+highHost+critsHist+critsHost)
		}

		hist.HostPlugin = make(map[string]PluginDetailSummary)

		for _, vuln := range histDetails.Vulnerabilities {
			var retPlugin PluginDetailSummary

			if trans.ShouldSkipPluginId(string(vuln.PluginId)) {
				continue
			}

			retPlugin.PluginId = string(vuln.PluginId)
			retPlugin.Name = vuln.Name
			retPlugin.Family = vuln.Family
			retPlugin.Count = string(vuln.Count)
			retPlugin.Severity = string(vuln.Severity)

			hist.HostPlugin[string(vuln.PluginId)] = retPlugin
		}

		//Sort!
		//histDetails.Vulnerabilities
		//histDetails.Hosts

		record.ScanHistoryDetails = append(record.ScanHistoryDetails, *hist)
	}

	return record, nil
}
