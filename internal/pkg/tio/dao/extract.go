package dao

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"time"

	"github.com/whereiskurt/tio-cli/internal/pkg/tio"
	"github.com/whereiskurt/tio-cli/internal/pkg/tio/api/tenable"
)

const (
	STAT_API_TENABLE_SCANLIST          tio.StatType = "tio.dao.TenableScanList.CallCount"
	STAT_API_TENABLE_SCANLIST_MEMCACHE tio.StatType = "tio.dao.TenableScanList.Memcached"

	STAT_API_TENABLE_ASSETHOST          tio.StatType = "tio.dao.TenableAssetVulnerabilties.CallCount"
	STAT_API_TENABLE_ASSETHOST_MEMCACHE tio.StatType = "tio.dao.TenableAssetVulnerabilties.Memcached"

	STAT_API_TENABLE_HOSTDETAIL          tio.StatType = "tio.dao.TenableHostDetail.CallCount"
	STAT_API_TENABLE_HOSTDETAIL_MEMCACHE tio.StatType = "tio.dao.TenableHostDetail.Memcached"

	STAT_API_TENABLE_TAGSCATEGORY tio.StatType = "tio.dao.TenableTags.CallCount"

	STAT_API_TENABLE_ASSETINFO          tio.StatType = "tio.dao.AssetInfo.CallCount"
	STAT_API_TENABLE_ASSETINFO_MEMCACHE tio.StatType = "tio.dao.AssetInfo.Memcached"

	STAT_API_TENABLE_SCANDETAIL          tio.StatType = "tio.dao.TenableScanDetail.CallCount"
	STAT_API_TENABLE_SCANDETAIL_MEMCACHE tio.StatType = "tio.dao.TenableScanDetail.Memcached"

	STAT_API_TENABLE_HISTORYID          tio.StatType = "tio.dao.TenableHistoryId.CallCount"
	STAT_API_TENABLE_HISTORYID_MEMCACHE tio.StatType = "tio.dao.TenableHistoryId.Memcached"
)

func (trans *Translator) getTenableTagCategories() (tags tenable.TagCategories, err error) {
	trans.Stats.Count(STAT_API_TENABLE_TAGSCATEGORY)
	var portalUrl = trans.Config.Base.BaseUrl + "/tags/categories"

	raw, _, err := trans.PortalCache.GetNoCache(portalUrl)

	err = json.Unmarshal([]byte(string(raw)), &tags)
	if err != nil {
		trans.Warnf("Couldn't unmarshal tenable.TagCategory: %s", err)
		return tags, err
	}

	sort.Slice(tags.Categories, func(i, j int) bool {
		return tags.Categories[i].Name < tags.Categories[j].Name
	})

	trans.Infof("Succesfully unmarshalled tenable.TagCategory: %s", raw)

	return tags, err
}
func (trans *Translator) getTenableTagValues() (tags tenable.TagValues, err error) {

	var portalUrl = trans.Config.Base.BaseUrl + "/tags/values"

	raw, _, err := trans.PortalCache.GetNoCache(portalUrl)

	err = json.Unmarshal([]byte(string(raw)), &tags)
	if err != nil {
		trans.Warnf("Couldn't unmarshal tenable.TagValue: %s", err)
		return tags, err
	}

	sort.Slice(tags.Values, func(i, j int) bool {
		if tags.Values[i].CategoryName == tags.Values[j].CategoryName {
			return tags.Values[i].Value < tags.Values[j].Value
		}
		return tags.Values[i].CategoryName < tags.Values[j].CategoryName
	})

	trans.Infof("Succesfully unmarshalled tenable.TagValues: %s", raw)

	return tags, err
}
func (trans *Translator) getTenableAssetHostMap(scanId string, historyId string) (assets tenable.AssetHost, err error) {
	trans.Stats.Count(STAT_API_TENABLE_ASSETHOST)

	var portalUrl = trans.Config.Base.BaseUrl + "/private/scans/" + scanId + "/assets/vulnerabilities?history_id=" + historyId

	var memcacheKey = portalUrl
	item := trans.Memcache.Get(memcacheKey)
	if item != nil {
		trans.Stats.Count(STAT_API_TENABLE_ASSETHOST_MEMCACHE)

		assets = item.Value().(tenable.AssetHost)
		return assets, nil
	}

	raw, _, err := trans.PortalCache.Get(portalUrl)
	if err != nil {
		trans.Errorf("Couldn't HTTP GET tenable.TenableAssetVulnerabilties for scan id:%s:histId:%s: %s", scanId, historyId, err)
		return assets, err
	}

	err = json.Unmarshal([]byte(string(raw)), &assets)
	if err != nil {
		trans.Warnf("Couldn't unmarshal tenable.TenableAssetVulnerabilties: %s", err)
		return assets, err
	}

	return assets, err
}
func (trans *Translator) getTenableAsset(assetUUID string) (assetInfo tenable.AssetInfo, err error) {
	trans.Stats.Count(STAT_API_TENABLE_ASSETINFO)

	var portalUrl = trans.Config.Base.BaseUrl + "/workbenches/assets/" + assetUUID + "/info"
	var memcacheKey = portalUrl
	item := trans.Memcache.Get(memcacheKey)
	if item != nil {
		trans.Stats.Count(STAT_API_TENABLE_ASSETINFO_MEMCACHE)

		assetInfo = item.Value().(tenable.AssetInfo)
		return assetInfo, nil
	}

	raw, _, err := trans.PortalCache.Get(portalUrl)
	if err != nil {
		trans.Errorf("Couldn't HTTP GET tenable.TenableAssetInfo for asset UUID:%s\n%s", assetUUID, err)
	}

	var asset tenable.Asset
	err = json.Unmarshal([]byte(string(raw)), &asset)
	if err != nil {
		trans.Errorf("Couldn't Unmarshal HTTP GET tenable.TenableAssetInfo for asset UUID:%s\n%s", assetUUID, err)
		return assetInfo, err
	}

	sort.Slice(asset.Info.Tags, func(i, j int) bool {
		if asset.Info.Tags[i].CategoryName == asset.Info.Tags[j].CategoryName {
			return asset.Info.Tags[i].Value < asset.Info.Tags[j].Value
		}
		return asset.Info.Tags[i].CategoryName < asset.Info.Tags[j].CategoryName
	})

	trans.Memcache.Set(memcacheKey, asset.Info, time.Minute*60)

	return asset.Info, err
}

func (trans *Translator) getTenableScanList() (sl tenable.ScanList, err error) {
	trans.Stats.Count(STAT_API_TENABLE_SCANLIST)

	var portalUrl = trans.Config.Base.BaseUrl + "/scans"
	var memcacheKey = portalUrl
	item := trans.Memcache.Get(memcacheKey)
	if item != nil {
		trans.Stats.Count(STAT_API_TENABLE_SCANLIST_MEMCACHE)

		sl = item.Value().(tenable.ScanList)
		return sl, nil
	}

	raw, _, err := trans.PortalCache.Get(portalUrl)
	if err != nil {
		trans.Warnf("Couldn't get tenable.ScanList from PortalCache: %s", err)
		return sl, err
	}

	err = json.Unmarshal([]byte(string(raw)), &sl)
	if err != nil {
		trans.Warnf("Couldn't unmarshal tenable.ScanList: %s", err)
		return sl, err
	}

	if trans.Anonymizer != nil {

		trans.Anonymizer.AnonymizeScanList(&sl)

		backToRaw, err := json.Marshal(sl)
		if err != nil {
			trans.Errorf("Error: %s", err)
			return sl, err
		}
		newCacheFilename, _ := trans.PortalCache.PortalCacheFilename(portalUrl)
		newCacheFilename = trans.Anonymizer.RewriteCacheFilename(newCacheFilename)
		trans.PortalCache.PortalCacheSet(newCacheFilename, backToRaw)
	}

	trans.Memcache.Set(memcacheKey, sl, time.Minute*60)

	return sl, nil
}
func (trans *Translator) getTenableHostDetail(scanId string, hostId string, historyId string) (hd tenable.HostDetail, err error) {
	trans.Stats.Count(STAT_API_TENABLE_HOSTDETAIL)

	if trans.Anonymizer != nil {
		scanId = trans.Anonymizer.DeAnonScanId(scanId)
		historyId = trans.Anonymizer.DeAnonHistoryId(historyId)
		hostId = trans.Anonymizer.DeAnonHostId(hostId)
	}

	var portalUrl = trans.Config.Base.BaseUrl + "/scans/" + scanId + "/hosts/" + hostId + "?history_id=" + historyId
	var memcacheKey = portalUrl

	item := trans.Memcache.Get(memcacheKey)
	if item != nil { //CACHE HIT!
		trans.Stats.Count(STAT_API_TENABLE_HOSTDETAIL_MEMCACHE)
		hd := item.Value().(tenable.HostDetail)
		return hd, nil
	}

	raw, _, err := trans.PortalCache.Get(portalUrl)
	if err != nil {
		trans.Errorf("Couldn't HTTP GET tenable.HostDetails for scan id:%s:host%s:histId:%s: %s", scanId, hostId, historyId, err)
		return hd, err
	}

	err = json.Unmarshal([]byte(string(raw)), &hd)
	if err != nil {
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
			return hd, err
		}

		scanId = trans.Anonymizer.AnonScanId(scanId)
		historyId = trans.Anonymizer.AnonHistoryId(historyId)
		hostId = trans.Anonymizer.AnonHostId(scanId, historyId, hostId)

		portalUrl = trans.Config.Base.BaseUrl + "/scans/" + scanId + "/hosts/" + hostId + "?history_id=" + historyId

		newCacheFilename, err := trans.PortalCache.PortalCacheFilename(portalUrl)
		if err == nil {
			newCacheFilename = trans.Anonymizer.RewriteCacheFilename(newCacheFilename)
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
func (trans *Translator) getTenableScanDetail(scanId string, historyId string) (scanDetail tenable.ScanDetail, err error) {
	trans.Stats.Count(STAT_API_TENABLE_SCANDETAIL)

	if trans.Anonymizer != nil {
		scanId = trans.Anonymizer.DeAnonScanId(scanId)
		historyId = trans.Anonymizer.DeAnonHistoryId(historyId)
	}

	var portalUrl = trans.Config.Base.BaseUrl + "/scans/" + scanId + "?history_id=" + historyId

	var memcacheKey = portalUrl
	item := trans.Memcache.Get(memcacheKey)
	if item != nil {
		trans.Stats.Count(STAT_API_TENABLE_SCANDETAIL_MEMCACHE)

		scanDetail = item.Value().(tenable.ScanDetail)
		return scanDetail, nil
	}

	raw, _, err := trans.PortalCache.Get(portalUrl)
	if err != nil {
		if !trans.Config.Base.OfflineMode {
			trans.Warnf("Couldn't get tenable.ScanDetail from PortalCache: %s", err)
		}
		return scanDetail, err
	}
	err = json.Unmarshal([]byte(string(raw)), &scanDetail)
	if err != nil {
		trans.Warnf("Couldn't unmarshal tenable.ScanList: %s", err)
		return scanDetail, err
	}

	//Sort histories by creation date DESC, to get offset history_id
	sort.Slice(scanDetail.History, func(i, j int) bool {
		iv, _ := strconv.ParseInt(string(scanDetail.History[i].CreationDate), 10, 64)
		jv, _ := strconv.ParseInt(string(scanDetail.History[j].CreationDate), 10, 64)
		return iv > jv
	})

	if trans.Anonymizer != nil {

		trans.Anonymizer.AnonymizeScanDetail(scanId, &scanDetail)
		backToRaw, err := json.Marshal(scanDetail)
		if err != nil {
			return scanDetail, err
		}

		scanId = trans.Anonymizer.AnonScanId(scanId)
		historyId = trans.Anonymizer.AnonHistoryId(historyId)

		portalUrl = trans.Config.Base.BaseUrl + "/scans/" + scanId + "?history_id=" + historyId
		newCacheFilename, _ := trans.PortalCache.PortalCacheFilename(portalUrl)
		newCacheFilename = trans.Anonymizer.RewriteCacheFilename(newCacheFilename)

		trans.PortalCache.PortalCacheSet(newCacheFilename, backToRaw)

	}

	return scanDetail, err
}
func (trans *Translator) getTenableHistoryId(scanId string, previousOffset int) (retHistoryId string, err error) {
	trans.Stats.Count(STAT_API_TENABLE_HISTORYID)

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

		trans.Stats.Count(STAT_API_TENABLE_HISTORYID_MEMCACHE)

		retHistoryId = item.Value().(string)
		return retHistoryId, err
	}

	var portalUrl = trans.Config.Base.BaseUrl + "/scans/" + scanId
	raw, _, err := trans.PortalCache.Get(portalUrl)
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
		err := errors.New(fmt.Sprintf("Cannot get historyId. No past scans for scanId:%s", scanId))
		return retHistoryId, err
	}

	if previousOffset > len(scanDetail.History)-1 {
		err := errors.New(fmt.Sprintf("Not enough run histories.  Cannot get offset - %d bigger than %d for scanId: %s", previousOffset, len(scanDetail.History)-1, scanId))
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
		if err != nil {
			return retHistoryId, err
		}
		scanId = trans.Anonymizer.AnonScanId(scanId)

		portalUrl = trans.Config.Base.BaseUrl + "/scans/" + scanId
		newCacheFilename, _ := trans.PortalCache.PortalCacheFilename(portalUrl)
		newCacheFilename = trans.Anonymizer.RewriteCacheFilename(newCacheFilename)

		trans.PortalCache.PortalCacheSet(newCacheFilename, backToRaw)

	}

	retHistoryId = string(scanDetail.History[previousOffset].HistoryId)

	trans.Memcache.Set(memcacheKey, retHistoryId, time.Minute*60)
	return retHistoryId, nil
}
