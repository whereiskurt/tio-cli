package cache

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"github.com/whereiskurt/tio-cli/internal/pkg/tio"
	"github.com/whereiskurt/tio-cli/internal/pkg/tio/api/tenable"
	"github.com/whereiskurt/tio-cli/internal/pkg/tio/util"
	"io/ioutil"
	"os"
	"regexp"
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

	CacheKeyBytes []byte

	Log *tio.Logger

	Stats *tio.Statistics
}

var reAllScans = regexp.MustCompile("^.+?/scans$")
var rePlugin = regexp.MustCompile("^.+?/plugins/plugin/(\\d+)$")
var reCurrentScan = regexp.MustCompile("^.+?/scans/(\\d+)$")
var reHistoryScan = regexp.MustCompile("^.+?/scans/(\\d+)\\?history_id=(\\d+)$")
var reHostScan = regexp.MustCompile("^.+?/scans/(\\d+)\\/hosts/(\\d+)?history_id=(\\d+)$")

func (portal *PortalCache) PortalCacheFilename(url string) (string, error) {
	var folder string

	if matched := reAllScans.FindStringSubmatch(url); matched != nil {
		portal.Log.Debug("MATCHED regex for AllScans")
		folder = "tenable/scans/"

	} else if matched := rePlugin.FindStringSubmatch(url); matched != nil {
		portal.Log.Debug("MATCHED regex for Plugin")
		folder = "tenable/plugins/" + matched[1] + "/"

	} else if matched := reCurrentScan.FindStringSubmatch(url); matched != nil {
		portal.Log.Debug("MATCHED regex for CurrentScan")
		folder = "tenable/scans/" + matched[1] + "/"

	} else if matched := reHistoryScan.FindStringSubmatch(url); matched != nil {
		portal.Log.Debug("MATCHED regex for HistoryScan")
		folder = "tenable/scans/" + matched[1] + "/history_id=" + matched[2] + "/"

	} else if matched := reHostScan.FindStringSubmatch(url); matched != nil {
		portal.Log.Debug("MATCHED regex for HostScan")
		folder = "tenable/scans/" + matched[1] + "/history_id=" + matched[3] + "/hosts/" + matched[2] + "/"

	} else {
		err := errors.New("Falied to matched regex for Cache: " + url)
		portal.Log.Errorf("%s", err)
		return "", err
	}

	shaKey := sha256.Sum256([]byte(fmt.Sprintf("%s%s", portal.CacheKey, url)))
	shaKeyHex := fmt.Sprintf("%x.dat", shaKey[:16])

	var filename string = portal.CacheFolder + folder + shaKeyHex

	err := os.MkdirAll(portal.CacheFolder+folder, 0777)
	if err != nil {
		portal.Log.Errorf("%s", err)
		return "", err
	}

	portal.Log.Debugf("Cache Filename: %s, for URL: %s", filename, url)

	return filename, nil
}
func (portal *PortalCache) PortalCacheSet(cacheFilename string, store []byte) error {
	if portal.UseCryptoCache {
		encDat, err := util.Encrypt(store, portal.CacheKeyBytes)
		if err != nil {
			return err
		}
		store = encDat
	}
	err := ioutil.WriteFile(cacheFilename, store, 0644)
	return err
}
func (portal *PortalCache) PortalCacheGet(cacheFilename string) ([]byte, error) {
	dat, err := ioutil.ReadFile(cacheFilename)
	if err != nil {
		return nil, err
	}
	portal.Log.Debugf("Cache: HIT on filename %s", cacheFilename)

	portal.Stats.Count("HIT.FILESYSTEM")

	if !portal.UseCryptoCache {
		portal.Log.Debugf("Cache: NO CRYPTO - not decryption needed.")
		return dat, nil
	}

	decDat, decErr := util.Decrypt(dat, portal.CacheKeyBytes)
	if decErr != nil {
		portal.Log.Errorf("Cache: Failed to decrypt: %s", decErr)
		return nil, decErr
	}

	return decDat, nil
}

func (portal *PortalCache) Get(url string) ([]byte, error) {

	if portal.CacheDisabled == true {
		bytes, err := portal.Portal.Get(url)
		return bytes, err
	}

	cacheFilename, err := portal.PortalCacheFilename(url)
	if err != nil {
		portal.Log.Errorf("%s", err)
		return nil, err
	}

	dat, err := portal.PortalCacheGet(cacheFilename)
	if err == nil {
		return dat, err
	}
	portal.Log.Debugf("Cache: MISSED: GET '%s' not in local cache.", url)

	//TODO: Add some 'soft retry' concepts here.
	body, err := portal.Portal.Get(url)
	if err != nil {
		return nil, err
	}

	cacheErr := portal.PortalCacheSet(cacheFilename, body)
	if cacheErr != nil {
		portal.Log.Debugf(fmt.Sprintf("Failed to store in cache. Error: %s", cacheErr))
		return nil, cacheErr

	}
	portal.Log.Debugf("Cache: STORE: GET '%s' is now in local cache.", url)
	return body, nil
}

func NewPortalCache(config *tio.BaseConfig) *PortalCache {
	p := new(PortalCache)
	p.Portal = tenable.NewPortal(config)

	p.Stats = tio.NewStatistics()

	p.CacheFolder = config.CacheFolder
	p.CacheKey = config.CacheKey
	p.UseCryptoCache = config.UseCryptoCache
	p.CacheDisabled = config.CacheDisabled
	p.Log = config.Logger

	p.CacheKeyBytes = []byte(fmt.Sprintf("%s", string(p.CacheKey)))

	if !p.CacheDisabled {
		err := os.MkdirAll(config.CacheFolder+"/portal/", 0777)
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
