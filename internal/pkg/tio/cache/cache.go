package cache

import (
	"github.com/whereiskurt/tio-cli/internal/pkg/tio"
	"github.com/whereiskurt/tio-cli/internal/pkg/tio/util"
	"github.com/whereiskurt/tio-cli/internal/pkg/tio/api/tenable"
	"crypto/sha256"
	"os"
	"regexp"
	"fmt"
	//"strings"
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

func (portal *PortalCache) GetCacheFilename(url string) (string, error) {
	var folder string

  if matched := reAllScans.FindStringSubmatch(url); matched != nil {
  	portal.Log.Debug("MATCHED regex for AllScans")
  	folder = "scans/"
  
  } else if matched := reCurrentScan.FindStringSubmatch(url); matched != nil {
  	portal.Log.Debug("MATCHED regex for CurrentScan")
  	folder = "scans/" + matched[1] + "/"
  
  } else if matched := reHistoryScan.FindStringSubmatch(url); matched != nil {
  	portal.Log.Debug("MATCHED regex for HistoryScan")
  
  } else if matched := reHostScan.FindStringSubmatch(url); matched != nil {
  	portal.Log.Debug("MATCHED regex for HostScan")
  	folder = "scans/" + matched[1] + "/history_id"
  } else {
  	err := errors.New("Falied to matched regex for Cache: " + url)
  	portal.Log.Errorf("%s", err)
  	return "", err
  }

  shaKey := sha256.Sum256([]byte(fmt.Sprintf("%s%s", portal.CacheKey, url)))
  shaKeyHex := fmt.Sprintf("%x.dat", shaKey[:16])

  var filename string = portal.CacheFolder + folder + shaKeyHex

	err := os.MkdirAll(portal.CacheFolder + folder, 0777)
	if err != nil {
		portal.Log.Errorf("%s", err)
		return "", err
	}		

  portal.Log.Debugf("Cache Filename: %s, for URL: %s", filename, url)
	
  return filename, nil
}

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
	portal.Log.Debugf("Cache: HIT")

  if !portal.UseCryptoCache { 
	  portal.Log.Debugf("Cache: NO CRYPTO")
  	return dat, nil
  }

	decDat, decErr := util.Decrypt(dat, portal.CacheKeyBytes)
	if decErr != nil {
	  portal.Log.Errorf("%s", decErr)
		return nil, decErr
  }
	
	return decDat, nil
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
  portal.Log.Debugf("Cache: MISS")

	body, err := portal.Portal.Get(url)
	if (err != nil) {
		return nil, err
	}
  portal.Log.Debugf("Fetched body: " + string(body))

	cacheErr := portal.CacheStore(cacheFilename, body)
	if cacheErr != nil {
  	portal.Log.Debugf(fmt.Sprintf("Failed to store in cache. Error: %s", cacheErr))
		return nil, cacheErr

	}
	return body, nil
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
