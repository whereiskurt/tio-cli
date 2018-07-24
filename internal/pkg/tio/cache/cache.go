package cache

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"regexp"

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
	CacheDisabled  bool
	CacheFolder    string
	CacheKey       string
	UseCryptoCache bool
	OfflineMode    bool
	CacheKeyBytes  []byte
	Log            *tio.Logger
	Stats          *tio.Statistics
}

var reAllScans = regexp.MustCompile("^.*?/scans$")
var rePlugin = regexp.MustCompile("^.*?/plugins/plugin/(\\d+)$")
var reCurrentScan = regexp.MustCompile("^.*?/scans/(\\d+)$")
var reHistoryScan = regexp.MustCompile("^.*?/scans/(\\d+)\\?history_id=(\\d+)$")
var reHostScan = regexp.MustCompile("^.*?/scans/(\\d+)\\/hosts/(\\d+)\\?history_id=(\\d+)$")

func NewPortalCache(config *tio.BaseConfig) *PortalCache {
	p := new(PortalCache)
	p.Portal = tenable.NewPortal(config)

	p.Stats = tio.NewStatistics()

	p.CacheFolder = config.CacheFolder
	p.CacheKey = config.CacheKey
	p.UseCryptoCache = config.UseCryptoCache
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

func (portal *PortalCache) PortalCacheFilename(url string) (filename string, err error) {
	var folder string
	var crypto bool = portal.UseCryptoCache
	var KEY_SIZE int = 4

	if matched := reAllScans.FindStringSubmatch(url); matched != nil {
		folder = "tenable/scans/"

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

	shaKey := sha256.Sum256([]byte(fmt.Sprintf("%s", portal.CacheKey)))
	shaKeyHex := fmt.Sprintf("%x.dat", shaKey[:KEY_SIZE])

	filename = portal.CacheFolder + folder + shaKeyHex

	return filename, err
}

func (portal *PortalCache) PortalCacheSet(cacheFilename string, store []byte) (err error) {
	portal.Stats.Count(STAT_CACHE_STORE)

	if portal.UseCryptoCache {
		encDat, err := obfu.Encrypt(store, portal.CacheKeyBytes)
		if err != nil {
			return err
		}
		store = encDat
	}

	err = os.MkdirAll(path.Dir(cacheFilename), 0777)
	if err != nil {
		portal.Log.Errorf("Cannot create cache folder '%s' - %s", cacheFilename, err)
		return err
	}

	err = ioutil.WriteFile(cacheFilename, store, 0644)
	return err
}
func (portal *PortalCache) PortalCacheGet(cacheFilename string) ([]byte, error) {

	dat, err := ioutil.ReadFile(cacheFilename)
	if err != nil {
		return nil, err
	}
	portal.Stats.Count(STAT_CACHE_HIT)

	if !portal.UseCryptoCache {
		return dat, nil
	}

	decDat, decErr := obfu.Decrypt(dat, portal.CacheKeyBytes)
	if decErr != nil {
		portal.Log.Errorf("Cache: Failed to decrypt: %s", decErr)
		return nil, decErr
	}

	return decDat, nil
}

func (portal *PortalCache) Get(url string) (body []byte, filename string, err error) {

	if portal.CacheDisabled == true {
		body, err = portal.Portal.Get(url)
		return body, filename, err
	}

	filename, err = portal.PortalCacheFilename(url)
	if err != nil {
		portal.Log.Errorf("%s", err)
		return body, filename, err
	}

	body, err = portal.PortalCacheGet(filename)
	if err == nil {
		return body, filename, err
	}

	portal.Stats.Count(STAT_CACHE_MISS)

	if portal.OfflineMode == true {
		err = fmt.Errorf("Cache MISSED for '%s' in '--offlineMode'", filename)
		return body, filename, err
	}

	//TODO: Add some 'soft retry' concepts here.
	body, err = portal.Portal.Get(url)
	if err != nil {
		return body, filename, err
	}

	err = portal.PortalCacheSet(filename, body)
	if err != nil {
		return body, filename, err
	}

	return body, filename, err
}

func NewTranslatorCache(config *tio.BaseConfig) *TranslatorCache {
	t := new(TranslatorCache)
	t.Log = config.Logger
	return t
}
