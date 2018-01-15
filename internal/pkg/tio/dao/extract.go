package dao

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/whereiskurt/tio-cli/internal/pkg/tio/api/tenable"
  "sort"
	"strconv"
	"time"
)


func (trans *Translator) getTenableHostDetail(scanId string, hostId string, historyId string) (hd tenable.HostDetail, err error) {

  if trans.Anonymizer != nil {
    scanId = trans.Anonymizer.DeAnonScanId(scanId)
    historyId = trans.Anonymizer.DeAnonHistoryId(historyId)
    hostId = trans.Anonymizer.DeAnonHostId(scanId, historyId, hostId)
  }

	var portalUrl = trans.Config.Base.BaseUrl + "/scans/" + scanId + "/hosts/" + hostId + "?history_id=" + string(historyId)

	var memcacheKey = portalUrl
	item := trans.Memcache.Get(memcacheKey)
	if item != nil {
		hd := item.Value().(tenable.HostDetail)
		return hd, nil
	}

	raw, _, err := trans.PortalCache.Get(portalUrl)
	if err != nil {
		trans.Warnf("Couldn't HTTP GET tenable.HostDetails for scan id:%s:host%s:histId:%s: %s", scanId, hostId, historyId, err)
		return hd, err
	}
	err = json.Unmarshal([]byte(string(raw)), &hd)
  if err != nil {
    trans.Warnf("Legacy unmarshall for tenable.HostDetail...")

    hd, err := trans.marshalTenableHostDetailOld(scanId, hostId, historyId, raw)

    if err != nil {
      trans.Warnf("Failed to unmarshal Legacy tenable.HostDetail for scan id:%s:host%s:histId:%s: %s", scanId, hostId, historyId, err)
      return hd, err
    }
  }


  if trans.Anonymizer != nil {
    trans.Anonymizer.AnonymizeHostDetail(scanId, historyId, &hd)
    backToRaw, err := json.Marshal(hd)

    if err != nil {
      trans.Warnf("FAILED TO marshal back anonymized tenable.HostDetail: %s", err)
    } else {
      scanId = trans.Anonymizer.AnonScanId(scanId)
      historyId = trans.Anonymizer.AnonHistoryId(historyId)
      hostId = trans.Anonymizer.AnonHostId(scanId, historyId, hostId)

      portalUrl = trans.Config.Base.BaseUrl + "/scans/" + scanId + "/hosts/" + hostId + "?history_id=" + string(historyId)
      
      newCacheFilename, _ := trans.PortalCache.PortalCacheFilename(portalUrl)
      trans.PortalCache.PortalCacheSet(newCacheFilename, backToRaw)

    }
  }


	trans.Memcache.Set(memcacheKey, hd, time.Minute*60)

	return hd, nil
}
func (trans *Translator) marshalTenableHostDetailOld(scanId string, hostId string, historyId string, raw []byte) (hd tenable.HostDetail, err error) {
	var legacy tenable.HostDetailLegacyV2
	err = json.Unmarshal([]byte(string(raw)), &legacy)
	if err != nil {
		trans.Warnf("Failed to unmarshal tenable.HostDetailLegacyV2 for  [Scan:%s Host:%s History:%s] - %s", scanId, hostId, historyId, err)
		return hd, err
	}
	hd.Info.OperatingSystem = append(hd.Info.OperatingSystem, legacy.Info.OperatingSystem)
	hd.Info.FQDN = legacy.Info.FQDN
	hd.Info.NetBIOS = legacy.Info.NetBIOS
	hd.Vulnerabilities = legacy.Vulnerabilities

	unixStart, err := time.Parse(time.ANSIC, legacy.Info.HostStart)
	if err != nil {
		trans.Warnf("Failed to parse '%s' as time.ANSIC - start/end/duration inaccurate for [Scan:%s History:%s Host:%s.]", legacy.Info.HostStart, scanId, historyId, hostId)
		return hd, err
	}

	unixEnd, err := time.Parse(time.ANSIC, legacy.Info.HostEnd)
	if err != nil {
		trans.Warnf("Failed to parse '%s' as time.ANSIC - start/end/duration inaccurate for [Scan:%s History:%s Host:%s.]", legacy.Info.HostEnd, scanId, historyId, hostId)
		return hd, err
	}

	hd.Info.HostStart = json.Number(unixStart.Format(time.ANSIC))
	hd.Info.HostEnd = json.Number(unixEnd.Format(time.ANSIC))

	return hd, err
}

func (trans *Translator) getTenableScanList() (retScanList tenable.ScanList, err error) {

	var portalUrl = trans.Config.Base.BaseUrl + "/scans"
	var memcacheKey = portalUrl
	item := trans.Memcache.Get(memcacheKey)
	if item != nil {
		trans.Stats.Count("GetTenableScanList.Memcached")

		retScanList = item.Value().(tenable.ScanList)
		return retScanList, nil
	}

	trans.Stats.Count("GetTenableScanList.Memcached")

	raw, cacheFilename, err := trans.PortalCache.Get(portalUrl)
	if err != nil {
		trans.Warnf("Couldn't get tenable.ScanList from PortalCache: %s", err)
		return retScanList, err
	}

	err = json.Unmarshal([]byte(string(raw)), &retScanList)
	if err != nil {
		trans.Warnf("Couldn't unmarshal tenable.ScanList: %s", err)
		return retScanList, err
	}

	if trans.Anonymizer != nil {
		trans.Anonymizer.AnonymizeScanList(&retScanList)

		backToRaw, err := json.Marshal(retScanList)
		if err == nil {
			trans.PortalCache.PortalCacheSet(cacheFilename, backToRaw)
		} 		
	}

	trans.Memcache.Set(memcacheKey, retScanList, time.Minute*60)


	return retScanList, nil
}

func (trans *Translator) getTenableScanDetail(scanId string, historyId string) (scanDetail tenable.ScanDetail, err error) {

	if trans.Anonymizer != nil {
		scanId = trans.Anonymizer.DeAnonScanId(scanId)
		historyId = trans.Anonymizer.DeAnonHistoryId(historyId)
	}

	var portalUrl = trans.Config.Base.BaseUrl + "/scans/" + scanId + "?history_id=" + historyId

	trans.Stats.Count("GetTenableScanDetail")

	var memcacheKey = portalUrl
	item := trans.Memcache.Get(memcacheKey)
	if item != nil {
		trans.Stats.Count("GetTenableScanDetail.Memcached")

		scanDetail = item.Value().(tenable.ScanDetail)
		return scanDetail, nil
	}

	raw, _, err := trans.PortalCache.Get(portalUrl)
	if err != nil {
		trans.Warnf("Couldn't get tenable.ScanDetail from PortalCache: %s", err)
		return scanDetail, err
	}
	err = json.Unmarshal([]byte(string(raw)), &scanDetail)
	if err != nil {
		trans.Warnf("Couldn't unmarshal tenable.ScanList: %s", err)
	}

	//Sort histories by creation date DESC, to get offset history_id
	sort.Slice(scanDetail.History, func(i, j int) bool {
		iv, iverr := strconv.ParseInt(string(scanDetail.History[i].CreationDate), 10, 64)
		if iverr != nil {
			panic(iverr) //TODO:Replace with warns
		}
		jv, jverr := strconv.ParseInt(string(scanDetail.History[j].CreationDate), 10, 64)
		if jverr != nil {
			panic(jverr)
		}
		return iv > jv
	})

	if trans.Anonymizer != nil {
		trans.Anonymizer.AnonymizeScanDetail(scanId, &scanDetail)
		backToRaw, err := json.Marshal(scanDetail)
		if err == nil {
			scanId = trans.Anonymizer.AnonScanId(scanId)
			historyId = trans.Anonymizer.AnonHistoryId(historyId)
			portalUrl = trans.Config.Base.BaseUrl + "/scans/" + scanId + "?history_id=" + historyId
			newCacheFilename, _ := trans.PortalCache.PortalCacheFilename(portalUrl)
			trans.PortalCache.PortalCacheSet(newCacheFilename, backToRaw)
		} 		
	}

	return scanDetail, nil
}

func (trans *Translator) getTenableHistoryId(scanId string, previousOffset int) (retHistoryId string, err error) {
	var scanDetail tenable.ScanDetail

	if trans.Anonymizer != nil {
		scanId = trans.Anonymizer.DeAnonScanId(scanId)
	}

	if trans.ShouldSkipScanId(scanId) {
		return retHistoryId, err
	}

	var memcacheKey = fmt.Sprintf("%s:%s", scanId, previousOffset)
	item := trans.Memcache.Get(memcacheKey)
	if item != nil {

		trans.Stats.Count("GetTenableHistoryId.Memcached")

		retHistoryId = item.Value().(string)
		return retHistoryId, err
	}

	trans.Stats.Count("GetTenableHistoryId")

	var portalUrl = trans.Config.Base.BaseUrl + "/scans/" + scanId
	raw, cacheFilename, err := trans.PortalCache.Get(portalUrl)
	if err != nil {
		trans.Errorf("Couldn't get tenable.ScanDetail from PortalCache: %s", err)
		return retHistoryId, err
	}
	err = json.Unmarshal([]byte(string(raw)), &scanDetail)
	if err != nil {
		trans.Errorf("Couldn't unmarshal tenable.ScanList: %s", err)
		return retHistoryId, err
	}

	if len(scanDetail.History) == 0 {
		err := errors.New(fmt.Sprintf("No scan history for scan %s offset %d", scanId, previousOffset))
		return retHistoryId, err
	}

	if previousOffset > len(scanDetail.History)-1 {
		err := errors.New(fmt.Sprintf("Cannot get history id for offset - %d bigger than %d", previousOffset, len(scanDetail.History)-1))
		trans.Errorf("%s", err)
		return retHistoryId, err
	}

	//Sort histories by creation date DESC, to get offset history_id
	sort.Slice(scanDetail.History, func(i, j int) bool {
		iv, iverr := strconv.ParseInt(string(scanDetail.History[i].CreationDate), 10, 64)
		if iverr != nil {
			panic(iverr) //TODO:Replace with warns
		}
		jv, jverr := strconv.ParseInt(string(scanDetail.History[j].CreationDate), 10, 64)
		if jverr != nil {
			panic(jverr)
		}
		return iv > jv
	})


  if trans.Anonymizer != nil {
    trans.Anonymizer.AnonymizeScanDetail(scanId, &scanDetail)

    backToRaw, err := json.Marshal(scanDetail)
    if err == nil {
      trans.PortalCache.PortalCacheSet(cacheFilename, backToRaw)

      scanId = trans.Anonymizer.AnonScanId(scanId)
      portalUrl = trans.Config.Base.BaseUrl + "/scans/" + scanId 
      newCacheFilename, _ := trans.PortalCache.PortalCacheFilename(portalUrl)
      trans.PortalCache.PortalCacheSet(newCacheFilename, backToRaw)
    }     
  }

	retHistoryId = string(scanDetail.History[previousOffset].HistoryId)

	trans.Memcache.Set(memcacheKey, retHistoryId, time.Minute*60)
	return retHistoryId, nil
}
