package cache

import (
	"github.com/whereiskurt/tio-cli/internal/pkg/tio"
	"github.com/whereiskurt/tio-cli/internal/pkg/tio/util"
	"github.com/whereiskurt/tio-cli/internal/pkg/tio/api/tenable"
	"crypto/sha256"
	"os"
	"regexp"
	"fmt"
	"strings"
	"errors"
	"io/ioutil"
)

type TranslatorCache struct {
	CacheDisabled  bool
	CacheFolder    string
	CacheKey       string
	UseCryptoCache bool
	Log *tio.Logger
}

type PortalCache struct {
	Portal *tenable.Portal
	CacheDisabled  bool
	CacheFolder    string
	CacheKey       string
	UseCryptoCache bool

	CacheKeyBytes []byte

	Log *tio.Logger
}

//"/scans"
var reAllScans = regexp.MustCompile("^.+?/scans$")
//"/scans/123456"
var reCurrentScan = regexp.MustCompile("^.+?/scans/(\\d+)$")
//"/scans/123456?history_id=101010231
var reHistoryScan = regexp.MustCompile("^.+?/scans/(\\d+)\\?history_id=(\\d+)$")
//"/scans/123456/hosts/1234?history_id=101010231
var reHostScan = regexp.MustCompile("^.+?/scans/(\\d+)\\/hosts/(\\d+)?history_id=(\\d+)$")


func (portal *PortalCache) CacheStore(cacheFilename string, store []byte) error {
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

func (portal *PortalCache) CacheHit(cacheFilename string) ([]byte, error) {
  dat, err := ioutil.ReadFile(cacheFilename)
  if (err != nil) {
  	return nil, err
  }
  if !portal.UseCryptoCache { 
  	return dat, nil
  }
	decDat, decErr := util.Decrypt(dat, portal.CacheKeyBytes)
	if decErr == nil {
		return decDat, decErr
  }
	return nil,decErr
}

func (portal *PortalCache) Get(url string) ([]byte, error) {
	if portal.CacheDisabled == true {
		bytes, err := portal.Portal.Get(url)
		return bytes, err
	}

	cacheFilename, err := portal.GetCacheFilename(url)
	if err != nil {
  	portal.Log.Errorf("%s", err)
		return nil, err
	}

	dat, err := portal.CacheHit(cacheFilename)
	if err == nil {
		return dat, err
	}

	body, err := portal.Portal.Get(url)
	if (err != nil) {
		return nil, err
	}

	portal.CacheStore(cacheFilename, body)

	return body, nil
}

func (portal *PortalCache) GetCacheFilename(url string) (string, error) {
//  matchAllScans := reAllScans.FindStringSubmatch(url)

  if matched := reAllScans.FindStringSubmatch(url); matched != nil {
  	portal.Log.Debug("MATCHED regex for AllScans")
  } else if matched := reCurrentScan.FindStringSubmatch(url); matched != nil {
  	portal.Log.Debug("MATCHED regex for CurrentScan")
  } else if matched := reHistoryScan.FindStringSubmatch(url); matched != nil {
  	portal.Log.Debug("MATCHED regex for HistoryScan")
  } else if matched := reHostScan.FindStringSubmatch(url); matched != nil {
  	portal.Log.Debug("MATCHED regex for HostScan")
  } else {
  	err := errors.New("Falied to matched regex for Cache: " + url)
  	portal.Log.Errorf("%s", err)
  	return "", err
  }

  shaKey := sha256.Sum256([]byte(fmt.Sprintf("%s%s", portal.CacheKey, url)))
  filename := fmt.Sprintf("%x.dat", shaKey)

  folder := strings.Replace(url, "/", "", -1)

  return portal.CacheFolder + "/" + folder + "/" + filename, nil
}

func NewPortalCache(config *tio.BaseConfig) *PortalCache {
	p := new(PortalCache)
	p.Portal = tenable.NewPortal(config)
	p.CacheDisabled = config.CacheDisabled
	p.CacheKey = config.CacheKey
	p.CacheFolder = config.CacheFolder
	p.UseCryptoCache = config.UseCryptoCache
	
	p.Log = config.Logger

  p.CacheKeyBytes = []byte(fmt.Sprintf("%s", string(p.CacheKey)))
	return p
}

func NewTranslatorCache(config *tio.BaseConfig) *TranslatorCache {
	t := new(TranslatorCache)

	t.CacheFolder = config.CacheFolder
	t.CacheKey = config.CacheKey
	t.UseCryptoCache = config.UseCryptoCache
	t.CacheDisabled = config.CacheDisabled
	t.Log = config.Logger

	if !t.CacheDisabled {
		err := os.MkdirAll(config.CacheFolder+"/", 0777)
		if err != nil {
			config.Logger.Errorf("%s", err)
			return nil
		}		
	}

	return t
}
