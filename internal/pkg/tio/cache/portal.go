package cache

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"regexp"
	"github.com/karlseguin/ccache"
	"github.com/whereiskurt/tio-cli/internal/pkg/tio"
	"github.com/whereiskurt/tio-cli/internal/pkg/tio/api/tenable"
	"github.com/whereiskurt/tio-cli/internal/pkg/tio/obfu"
)

const (
	STAT_CACHE_HIT   tio.StatType = "tio.cache.HIT"
	STAT_CACHE_MISS  tio.StatType = "tio.cache.MISS"
	STAT_CACHE_STORE tio.StatType = "tio.cache.STORE"
)

type TranslatorCache struct {
	Log *tio.Logger
}

type PortalCache struct {
	Portal         *tenable.Portal
	Anonymizer     *tenable.Anonymizer
	BaseUrl    		 string
	CacheDisabled  bool
	ClobberCache   bool
	CacheFolder    string
	CacheKey       string
	UseCryptoCache bool
	OfflineMode    bool
	CacheKeyBytes  []byte
	Log            *tio.Logger
	Stats          *tio.Statistics
	Memcache        *ccache.Cache


}

var reAllScans = regexp.MustCompile("^.*?/scans$")
var rePlugin = regexp.MustCompile("^.*?/plugins/plugin/(\\d+)$")
var rePluginFamilies = regexp.MustCompile("^.*?/plugins/families$")
var reFamilyPlugins = regexp.MustCompile("^.*?/plugins/families/(\\d+)$")
var reCurrentScan = regexp.MustCompile("^.*?/scans/(\\d+)$")
var reHistoryScan = regexp.MustCompile("^.*?/scans/(\\d+)\\?history_id=(\\d+)$")
var reHostScan = regexp.MustCompile("^.*?/scans/(\\d+)\\/hosts/(\\d+)\\?history_id=(\\d+)$")
var reAssetHostMap = regexp.MustCompile("^.*?/private/scans/(\\d+)\\/assets/vulnerabilities?\\?history_id=(\\d+)$")
var reAssetInfo = regexp.MustCompile("^.*?/workbenches/assets/(.+)/info$")                                           //matches a GUID!
var reAssetSearch = regexp.MustCompile("^.*?\\/workbenches\\/assets\\?.+?tag\\.(.+?)\\&filter\\.0\\.value=(.+?)\\&") //matches a GUID!

func NewPortalCache(config *tio.BaseConfig) *PortalCache {
	p := new(PortalCache)
	p.Portal = tenable.NewPortal(config)
	p.Memcache = ccache.New(ccache.Configure().MaxSize(500000).ItemsToPrune(50))

	p.BaseUrl = config.BaseUrl

	p.Stats = tio.NewStatistics()

	p.CacheFolder = config.CacheFolder
	p.CacheKey = config.CacheKey
	p.UseCryptoCache = config.UseCryptoCache
	p.ClobberCache = config.ClobberCache
	p.CacheDisabled = config.CacheDisabled
	p.OfflineMode = config.OfflineMode

	p.Log = config.Logger

	p.CacheKeyBytes = []byte(fmt.Sprintf("%s", string(p.CacheKey)))

	if !p.CacheDisabled {
		err := os.MkdirAll(config.CacheFolder+"/", 0777)
		if err != nil {
			config.Logger.Errorf("%s", err)
			return nil
		}
	}

	return p
}
func NewTranslatorCache(config *tio.BaseConfig) *TranslatorCache {
	t := new(TranslatorCache)
	t.Log = config.Logger
	return t
}

func (portal *PortalCache) Filename(url string) (filename string, err error) {
	var folder string
	var crypto bool = portal.UseCryptoCache
	var KEY_SIZE int = 4

	if matched := reAllScans.FindStringSubmatch(url); matched != nil {
		folder = "tenable/scans/"

	} else if matched := rePluginFamilies.FindStringSubmatch(url); matched != nil {
		folder = "tenable/plugins/families/" 

	} else if matched := reFamilyPlugins.FindStringSubmatch(url); matched != nil {
		familyId := matched[1]
		folder = "tenable/plugins/families/" + familyId + "/"

	} else if matched := rePlugin.FindStringSubmatch(url); matched != nil {
		plugin := matched[1]
		if crypto {
			pkey := sha256.Sum256([]byte(fmt.Sprintf("%s%s", portal.CacheKey, plugin)))
			plugin = fmt.Sprintf("%x", pkey[:KEY_SIZE])
		}
		folder = "tenable/plugins/" + plugin + "/"

	} else if matched := reCurrentScan.FindStringSubmatch(url); matched != nil {
		scan := matched[1]
		if crypto {
			skey := sha256.Sum256([]byte(fmt.Sprintf("%s%s", portal.CacheKey, scan)))
			scan = fmt.Sprintf("%x", skey[:KEY_SIZE])
		}
		folder = "tenable/scans/" + scan + "/"

	} else if matched := reHistoryScan.FindStringSubmatch(url); matched != nil {
		scan := matched[1]
		history := matched[2]
		if crypto {
			skey := sha256.Sum256([]byte(fmt.Sprintf("%s%s", portal.CacheKey, scan)))
			scan = fmt.Sprintf("%x", skey[:KEY_SIZE])
			hkey := sha256.Sum256([]byte(fmt.Sprintf("%s%s", portal.CacheKey, scan)))
			history = fmt.Sprintf("%x", hkey[:KEY_SIZE])
		}
		folder = "tenable/scans/" + scan + "/history_id=" + history + "/"

	} else if matched := reAssetHostMap.FindStringSubmatch(url); matched != nil {
		scan := matched[1]
		history := matched[2]
		if crypto {
			skey := sha256.Sum256([]byte(fmt.Sprintf("%s%s", portal.CacheKey, scan)))
			scan = fmt.Sprintf("%x", skey[:KEY_SIZE])
			hkey := sha256.Sum256([]byte(fmt.Sprintf("%s%s", portal.CacheKey, scan)))
			history = fmt.Sprintf("%x", hkey[:KEY_SIZE])
		}
		folder = "tenable/scans/" + scan + "/history_id=" + history + "/map/"

	} else if matched := reAssetInfo.FindStringSubmatch(url); matched != nil {
		assetUUID := matched[1]

		if crypto {
			skey := sha256.Sum256([]byte(fmt.Sprintf("%s%s", portal.CacheKey, assetUUID)))
			assetUUID = fmt.Sprintf("%x", skey[:KEY_SIZE])
		}
		folder = "tenable/asset/" + assetUUID + "/"

	} else if matched := reAssetSearch.FindStringSubmatch(url); matched != nil {
		category := matched[1]
		value := matched[2]
		folder = "tenable/search/asset/" + category + "/" + value + "/"

	} else if matched := reHostScan.FindStringSubmatch(url); matched != nil {
		scan := matched[1]
		host := matched[2]
		history := matched[3]
		if crypto {
			skey := sha256.Sum256([]byte(fmt.Sprintf("%s%s", portal.CacheKey, scan)))
			scan = fmt.Sprintf("%x", skey[:KEY_SIZE])
			hkey := sha256.Sum256([]byte(fmt.Sprintf("%s%s", portal.CacheKey, host)))
			host = fmt.Sprintf("%x", hkey[:KEY_SIZE])
			histkey := sha256.Sum256([]byte(fmt.Sprintf("%s%s", portal.CacheKey, scan)))
			history = fmt.Sprintf("%x", histkey[:KEY_SIZE])
		}
		folder = "tenable/scans/" + scan + "/history_id=" + history + "/hosts/" + host + "/"

	} else {
		err := errors.New("Falied to matched regex for Cache: " + url)
		portal.Log.Errorf("%s", err)
		return "", err
	}

	if filename == "" {
		shaKey := sha256.Sum256([]byte(fmt.Sprintf("%s", portal.CacheKey)))
		shaKeyHex := fmt.Sprintf("%x.dat", shaKey[:KEY_SIZE])
		filename = portal.CacheFolder + folder + shaKeyHex
	}

	return filename, err
}

func (portal *PortalCache) Store(filename string, store []byte) (err error) {
	portal.Stats.Count(STAT_CACHE_STORE)

	if portal.UseCryptoCache {
		encDat, err := obfu.Encrypt(store, portal.CacheKeyBytes)
		if err != nil {
			return err
		}
		store = encDat
	}

	err = os.MkdirAll(path.Dir(filename), 0777)
	if err != nil {
		portal.Log.Errorf("Cannot create cache folder '%s' - %s", filename, err)
		return err
	}

	err = ioutil.WriteFile(filename, store, 0644)
	return err
}
func (portal *PortalCache) Fetch(filename string) (store []byte, err error) {

	store, err = ioutil.ReadFile(filename)
	if err != nil {
		return
	}
	portal.Stats.Count(STAT_CACHE_HIT)

	if !portal.UseCryptoCache {
		return
	}

	store, err = obfu.Decrypt(store, portal.CacheKeyBytes)
	if err != nil {
		portal.Log.Errorf("Cache: Failed to decrypt: %s", err)
		return
	}

	return
}

func (portal *PortalCache) GET(url string) (body []byte, err error) {
	if portal.CacheDisabled == true {
		body, err = portal.Portal.GET(url)
		return
	}

	filename, err := portal.Filename(url)
	if err != nil {
		portal.Log.Errorf("%s", err)
		return
	}

	if !portal.ClobberCache {
		body, err = portal.Fetch(filename)
		if err == nil {
			return
		}
	}

	portal.Stats.Count(STAT_CACHE_MISS)

	if portal.OfflineMode == true {
		err = fmt.Errorf("Cache MISSED for '%s' in '--offlineMode'", filename)
		return
	}

	//TODO: Add some 'soft retry' concepts here.
	body, err = portal.Portal.GET(url)
	if err != nil {
		return
	}

	err = portal.Store(filename, body)
	if err != nil {
		return
	}

	return 
}
