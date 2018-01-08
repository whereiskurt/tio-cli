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
	var portalUrl = trans.Config.Base.BaseUrl + "/scans/" + scanId + "/hosts/" + hostId + "?history_id=" + string(historyId)

	var memcacheKey = portalUrl
	item := trans.Memcache.Get(memcacheKey)
	if item != nil {
		hd := item.Value().(tenable.HostDetail)
		return hd, nil
	}

	raw, err := trans.PortalCache.Get(portalUrl)
	if err != nil {
		trans.Errorf("Couldn't HTTP GET tenable.HostDetails for scan id:%s:host%s:histId:%s: %s", scanId, hostId, historyId, err)
		return hd, err
	}
	err = json.Unmarshal([]byte(string(raw)), &hd)
	if err != nil {

		trans.Debugf("Failed to unmarshal older version of HostDetail for scan id:%s:host%s:histId:%s", scanId, hostId, historyId)
		hdLegacy, err := trans.getTenableHostDetailLegacy(scanId, hostId, historyId, raw)

		if err != nil {
			trans.Errorf("Failed to unmarshal Legacy tenable.HostDetail for scan id:%s:host%s:histId:%s: %s", scanId, hostId, historyId, err)
			return hd, err
		}

		hd = hdLegacy
	}

	trans.Memcache.Set(memcacheKey, hd, time.Minute*60)

	return hd, nil
}

func (trans *Translator) getTenableHostDetailLegacy(scanId string, hostId string, historyId string, raw []byte) (hd tenable.HostDetail, err error) {
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

	raw, err := trans.PortalCache.Get(portalUrl)
	if err != nil {
		trans.Errorf("Couldn't get tenable.ScanList from PortalCache: %s", err)
		return retScanList, err
	}

	err = json.Unmarshal([]byte(string(raw)), &retScanList)
	if err != nil {
		trans.Errorf("Couldn't unmarshal tenable.ScanList: %s", err)
		return retScanList, err
	}

	trans.Memcache.Set(memcacheKey, retScanList, time.Minute*60)

	return retScanList, nil
}

func (trans *Translator) getTenableScanDetail(scanId string, historyId string) (scanDetail tenable.ScanDetail, err error) {
	var portalUrl = trans.Config.Base.BaseUrl + "/scans/" + scanId + "?history_id=" + historyId

	trans.Stats.Count("GetTenableScanDetail")

	var memcacheKey = portalUrl
	item := trans.Memcache.Get(memcacheKey)
	if item != nil {
		trans.Stats.Count("GetTenableScanDetail.Memcached")

		scanDetail = item.Value().(tenable.ScanDetail)
		return scanDetail, nil
	}

	raw, err := trans.PortalCache.Get(portalUrl)
	if err != nil {
		trans.Errorf("Couldn't get tenable.ScanDetail from PortalCache: %s", err)
		return scanDetail, err
	}
	err = json.Unmarshal([]byte(string(raw)), &scanDetail)
	if err != nil {
		trans.Errorf("Couldn't unmarshal tenable.ScanList: %s", err)
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

	return scanDetail, nil
}

func (trans *Translator) getTenableHistoryId(scanId string, previousOffset int) (retHistoryId string, err error) {
	var scanDetail tenable.ScanDetail

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
	raw, err := trans.PortalCache.Get(portalUrl)
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

	retHistoryId = string(scanDetail.History[previousOffset].HistoryId)

	trans.Memcache.Set(memcacheKey, retHistoryId, time.Minute*60)
	return retHistoryId, nil
}
