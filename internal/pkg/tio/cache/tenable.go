package cache

import (
	"encoding/json"
	"sort"
	"time"
	"fmt"

	"github.com/whereiskurt/tio-cli/internal/pkg/tio/api/tenable"
)

func (pc *PortalCache) GetPluginsList() (plugins []tenable.Plugin, err error) {

	url := pc.BaseUrl + "/plugins/families"
	raw, err := pc.GET(url)
	if err != nil {
		pc.Log.Errorf("HTTP: GET: %s - %s", url, err)
		return
	}

	var fam tenable.PluginFamilies
	err = json.Unmarshal([]byte(string(raw)), &fam)
	if err != nil {
		pc.Log.Errorf("Unmarshal PluginFamilies %s", err)
		return
	}

	for _, f := range fam.Families {
		url = pc.BaseUrl + "/plugins/families/" + string(f.Id)
		raw, err = pc.GET(url)
		if err != nil {
			pc.Log.Errorf("HTTP: GET: %s - %s", url, err)
			return
		}

		var family tenable.FamilyPlugins
		err = json.Unmarshal([]byte(string(raw)), &family)
		if err != nil {
			pc.Log.Errorf("Unmarshal FamilyPlugins %s", err)
			return
		}

		for _, plug := range family.Plugins {
			var rec tenable.Plugin
			rec.Id = plug.Id
			rec.FamilyName = f.Name
			rec.Name = plug.Name
			plugins = append(plugins, rec) //<-- return value
		}

	}

	return
}


func (pc *PortalCache) GetPluginDetail(pluginId string) (detail tenable.Plugin, err error) {
	var url = pc.BaseUrl + "/plugins/plugin/" + pluginId

	raw, err := pc.GET(url)
	if err != nil {
		pc.Log.Errorf("HTTP: GET: %s - %s", url, err)
		return 
	}

	err = json.Unmarshal([]byte(string(raw)), &detail) //<-- return value
	if err != nil {
		pc.Log.Errorf("Unmarshal FamilyPlugins %s", err)	
		return 
	}

	return
}

func (pc *PortalCache) GetTagCategories() (tags tenable.TagCategories, err error) {
	var url = pc.BaseUrl + "/tags/categories"

	raw, err := pc.Portal.GET(url)

	err = json.Unmarshal([]byte(string(raw)), &tags)
	if err != nil {
		pc.Log.Errorf("Couldn't unmarshal tenable.TagCategory: %s", err)
		return
	}

	sort.Slice(tags.Categories, func(i, j int) bool {
		return tags.Categories[i].Name < tags.Categories[j].Name
	})

	return
}



func (pc *PortalCache) GetTagValues() (tags tenable.TagValues, err error) {

	var url = pc.BaseUrl + "/tags/values"

	raw, err := pc.Portal.GET(url)

	err = json.Unmarshal([]byte(string(raw)), &tags)
	if err != nil {
		pc.Log.Errorf("Couldn't unmarshal tenable.TagValue: %s", err)
		return
	}

	sort.Slice(tags.Values, func(i, j int) bool {
		if tags.Values[i].CategoryName == tags.Values[j].CategoryName {
			return tags.Values[i].Value < tags.Values[j].Value
		}
		return tags.Values[i].CategoryName < tags.Values[j].CategoryName
	})

	return 
}


func (pc *PortalCache) GetScanAssetHostMap(scanId string, historyId string) (assets tenable.AssetHost, err error) {
	var url = pc.BaseUrl + "/private/scans/" + scanId + "/assets/vulnerabilities?history_id=" + historyId

		item := pc.Memcache.Get(url)
	if item != nil 	{
		assets = item.Value().(tenable.AssetHost)
		return 
	}

	raw, err := pc.GET(url)
	if err != nil {
		pc.Log.Errorf("Couldn't HTTP GET tenable.TenableAssetVulnerabilties for scan id:%s:histId:%s: %s", scanId, historyId, err)
		return 
	}

	err = json.Unmarshal([]byte(string(raw)), &assets)
	if err != nil {
		pc.Log.Errorf("Couldn't unmarshal tenable.TenableAssetVulnerabilties: %s", err)
		return 
	}

	pc.Memcache.Set(url, assets, time.Minute*60)

	return 
}


func (pc *PortalCache) GetAsset(assetUUID string) (assetInfo tenable.AssetInfo, err error) {
	var url = pc.BaseUrl + "/workbenches/assets/" + assetUUID + "/info"
	var memcacheKey = url
	item := pc.Memcache.Get(memcacheKey)
	if item != nil {
		assetInfo = item.Value().(tenable.AssetInfo)
		return 
	}

	raw, err := pc.GET(url)
	if err != nil {
		pc.Log.Errorf("Couldn't HTTP GET tenable.TenableAssetInfo for asset UUID:%s\n%s", assetUUID, err)
		return
	}

	var asset tenable.Asset
	err = json.Unmarshal([]byte(string(raw)), &asset)
	if err != nil {
		pc.Log.Errorf("Couldn't Unmarshal HTTP GET tenable.TenableAssetInfo for asset UUID:%s\n%s", assetUUID, err)
		return
	}

	sort.Slice(asset.Info.Tags, func(i, j int) bool {
		if asset.Info.Tags[i].CategoryName == asset.Info.Tags[j].CategoryName {
			return asset.Info.Tags[i].Value < asset.Info.Tags[j].Value
		}
		return asset.Info.Tags[i].CategoryName < asset.Info.Tags[j].CategoryName
	})
	assetInfo = asset.Info
	pc.Memcache.Set(memcacheKey, assetInfo, time.Minute*60)

	return
}


func (pc *PortalCache) SearchAssetByTag(tagCategory string, tagValue string) (assets []tenable.AssetInfo, err error) {

	var params string = fmt.Sprintf("date_range=0&filter.0.quality=set-has&filter.0.filter=tag.%s&filter.0.value=%s&filter.search_type=and", tagCategory, tagValue)
	var url = pc.BaseUrl + "/workbenches/assets?" + params
	
	item := pc.Memcache.Get(url)
	if item != nil {
		assets = item.Value().([]tenable.AssetInfo)
		return 
	}

	raw, err := pc.GET(url)

	var assetSearch tenable.AssetSearchResults
	err = json.Unmarshal([]byte(string(raw)), &assetSearch)
	if err != nil {
		pc.Log.Errorf("Couldn't Unmarshal HTTP GET tenable.TenableAssetInfo on search for category:%s value:%s\n%s", tagCategory, tagValue, err)
		return
	}

	for _, a := range assetSearch.Assets {
		assets = append(assets, a)
	}

	pc.Memcache.Set(url, assets, time.Minute*60)

	return
}


func (pc *PortalCache) GetScanList() (sl tenable.ScanList, err error) {
	var url = pc.BaseUrl + "/scans"

	item := pc.Memcache.Get(url)
	if item != nil {
		sl = item.Value().(tenable.ScanList)
		return
	}

	raw, err := pc.GET(url)
	if err != nil {
		pc.Log.Warnf("Couldn't get tenable.ScanList from PortalCache: %s", err)
		return
	}

	err = json.Unmarshal([]byte(string(raw)), &sl)
	if err != nil {
		pc.Log.Warnf("Couldn't unmarshal tenable.ScanList: %s", err)
		return 
	}

	if pc.Anonymizer != nil {

		pc.Anonymizer.AnonymizeScanList(&sl)

		raw, err = json.Marshal(sl)
		if err != nil {
			pc.Log.Errorf("Failed to anon and marshal object back to ScanList: %s", err)
			return
		}
		newCacheFilename, _ := pc.Filename(url)
		newCacheFilename = pc.Anonymizer.RewriteCacheFilename(newCacheFilename)
		pc.Store(newCacheFilename, raw)
	}

	pc.Memcache.Set(url, sl, time.Minute*60)

	return 
}