package dao

import (
	"github.com/whereiskurt/tio-cli/internal/pkg/tio"
	"github.com/whereiskurt/tio-cli/internal/pkg/tio/cache"
	"github.com/whereiskurt/tio-cli/internal/pkg/tio/api/tenable"
  "github.com/karlseguin/ccache"
  "encoding/json"
  "time"
)

type Translator struct {
	Config *tio.VulnerabilityConfig
	
	TranslatorCache  *cache.TranslatorCache
	PortalCache *cache.PortalCache

	Memcache *ccache.Cache
}

func NewTranslator(config *tio.VulnerabilityConfig) *Translator {
	t := new(Translator)
	t.Config = config
	t.TranslatorCache = cache.NewTranslatorCache(config.Base)
	t.PortalCache = cache.NewPortalCache(config.Base)
	t.Memcache = ccache.New(ccache.Configure().MaxSize(500000).ItemsToPrune(50))

	return t
}

func (trans *Translator) GetScanList() (tenable.ScanList, error) {
  var returnScanList tenable.ScanList

	var portalUrl = trans.Config.Base.BaseUrl + "/scans"

  item  := trans.Memcache.Get(portalUrl)
  if item  != nil {
  	trans.Config.Base.Logger.Debugf("Memcache: GET '%s'", portalUrl)
    returnScanList = item.Value().(tenable.ScanList)
    return returnScanList, nil
  }

  raw, err := trans.PortalCache.Get(portalUrl)

  err = json.Unmarshal([]byte(string(raw)), &returnScanList)
  if err != nil {
      trans.Config.Base.Logger.Errorf("Couldn't unmarshal tenable.ScanList: %s", err)
      return returnScanList, err
  }

  trans.Memcache.Set(portalUrl, returnScanList, time.Minute * 60)

	return returnScanList, nil
}