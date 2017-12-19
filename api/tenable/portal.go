//These are the API structures from the TIO documentation

package tenable

import (
  "tio-cli/api/util"
  "os"
  "sort"
  "fmt"
  "strconv"
  "log"
  "net/http"
  "encoding/json"
  "crypto/sha256"
  "github.com/spf13/viper"
  "time"
  "io/ioutil"
  "strings"
  
  "github.com/karlseguin/ccache"
)

//Defaulting to CST TZ for our scanner 
const TZ_FORMAT string = "2006-01-_2 15:04:05 -0700 MST"  
//const TZ_OFFSETFORSCANNER string  = "-0600 CST" //TODO: Lookup per scanner

var tr = &http.Transport{
  MaxIdleConns:       20,
  IdleConnTimeout:    60 * time.Second,
}

var BAD_GATEWAY_TIMEOUT_MS time.Duration = 1000 * time.Millisecond
var BAD_GATEWAY_TOTAL = 0
var BAD_GATEWAY_IN_A_ROW = 0

var memcache = ccache.New(ccache.Configure().MaxSize(500000).ItemsToPrune(500))

func (portal *Portal) getCacheFilename(endPoint string, httpMethod string, folder string) string {
  shaKey := sha256.Sum256([]byte(fmt.Sprintf("%s%s", endPoint, httpMethod)))
  shaKeyString := fmt.Sprintf("%x", shaKey)
  return portal.cacheFolder + "/" + folder + "/" + shaKeyString
}

type Portal struct {
  baseUrl string
  accessKey string
  secretKey string
  cacheKey string
  cacheFolder string
  useCryptoCache bool
  tzDefault string
}

func NewPortal() *Portal {
  p := new(Portal)
  
  p.accessKey = viper.GetString("accessKey")
  p.secretKey = viper.GetString("secretKey")
  p.cacheKey = viper.GetString("cacheKey")
  p.baseUrl  = viper.GetString("baseUrl")
  
  p.cacheFolder  = viper.GetString("cacheFolder")
  p.useCryptoCache  = viper.GetBool("useCryptoCache")
  
  p.tzDefault  = viper.GetString("tzDefault")

  if p.tzDefault == "" {
    t := time.Now()
    ts := fmt.Sprintf("%v", t)
    p.tzDefault = ts[len(ts)-10:]
  }

  return p
}

func (portal *Portal) GetTimezone(scannerName string) string {
  //if scannerName == "XYZ" { }
  return portal.tzDefault
}


func (portal *Portal) Delete(endPoint string) int {
  var url string = portal.baseUrl + "/" + endPoint

  client := &http.Client{Transport: tr}
  req, err := http.NewRequest("DELETE", url, nil)
  if (err != nil) {
    log.Fatal(err)
  }

  var htmlHeader = fmt.Sprintf("accessKey=%s;secretKey=%s", portal.accessKey, portal.secretKey)
  req.Header.Add("X-ApiKeys", htmlHeader)

  resp, err := client.Do(req)
  if (err != nil) {
    log.Fatal(err)
  }

  defer resp.Body.Close()

  body, err := ioutil.ReadAll(resp.Body)
  if (err != nil) {
    log.Fatal(err)
  }

  if strings.Contains(string(body), `"error"`) {
    log.Fatal("Cannot delete historyId from Tenable.IO, feature not yet implemented.")
  }

  return 200
}


var badGateways[] string

func (portal *Portal) Get(endPoint string, httpMethod string, folder string) []byte {

  var url string = portal.baseUrl + "/" + endPoint

  item := memcache.Get("url:" + url)
  if item != nil {
    body := item.Value().([]byte)
    //fmt.Print(GREEN+fmt.Sprintf("M")+RESET)  //In-Memory
    return body
  }

  var encryptKey []byte = []byte(fmt.Sprintf("%s", string(portal.cacheKey)))

  if BAD_GATEWAY_IN_A_ROW > 20 { 
    fmt.Println()
    log.Fatal(fmt.Sprintf("Too many BAD GATEWAY IN A ROW (>20) requests.\n\nTenable.IO may have bad data in a past historical scan.\nConsider adding '--ignore-scans' or '--ignore-history to your command'.\n\n%v", badGateways))
  }

  var cacheFileName = ""

  if folder != "" {
    cacheFileName = portal.getCacheFilename(endPoint, httpMethod, folder)
  }

  if cacheFileName != "" {
    dat, err := ioutil.ReadFile(cacheFileName)
    if (err == nil) {
      if portal.useCryptoCache == true {
        decDat, err := util.Decrypt(dat, encryptKey)
        if err != nil {
          log.Fatal(err)
        }
        dat = decDat
      }
      return dat
    } else {
      //TODO: Move this directory creation closer to writing of file
      //Make a cache directory, if it doesn't exist
      err = os.MkdirAll(portal.cacheFolder + "/" + folder, 0777)
      if (err != nil) {
        log.Fatal(err)
      }
    }
  }

  //Prepare HTTPS client for request..
  client := &http.Client{Transport: tr}
  req, err := http.NewRequest(httpMethod, url, nil)
  if (err != nil) {
    log.Fatal(err)
  }

  //Addess acess tokens to HEADER
  var htmlHeader = fmt.Sprintf("accessKey=%s;secretKey=%s", portal.accessKey, portal.secretKey)
  req.Header.Add("X-ApiKeys", htmlHeader)

  //var reqStartTime   = time.Now()
  //Make the request
  resp, err := client.Do(req)
  if (err != nil) {
    log.Println(err)
    return nil
  }

  defer resp.Body.Close()
  
  //var reqEndTime   = time.Now()
  //var reqDuration = fmt.Sprintf("%v", reqEndTime.Sub(reqStartTime))
  //fmt.Printf("www:tm:%v:%v:%v\n",reqDuration ,reqStartTime, reqEndTime)

  //Read the repsonse
  body, err := ioutil.ReadAll(resp.Body)
  if (err != nil) {
    log.Fatal(err)
  }

  //////////
  //Full message from cloud.tenable.io:
  //  {"statusCode":401,"error":"Unauthorized","message":"Invalid Credentials"}
  //
  if strings.Contains(string(body), `"statusCode":401`) {
    log.Fatal("ERROR: Your secretKey and accessKey (credentials) are invalid. ")
  }

  //SOFT failure - Tenable.IO returns bad data here
  //Sometimes Tenable returns errors, even when your request is well formed.
  //TODO: Loop over 'badBodies[]' for matching strings.
  
  //ORIG:if strings.Contains(string(body), `{"error":"Asset or host not found"}`) || strings.Contains(string(body), `{"error":"You need to log in to perform this request"}`) ||  strings.Contains(string(body), "504 Gateway Time-out") || strings.Contains(string(body), `{"statusCode":504,"error":"Gateway Timeout"`) || strings.Contains(string(body),`{"error":"Invalid Credentials"}`)  || strings.Contains(string(body),`Please retry request.`) {
  if strings.Contains(string(body), `{"error":"Asset or host not found"}`) || strings.Contains(string(body), `{"error":"You need to log in to perform this request"}`) ||  strings.Contains(string(body), "504 Gateway Time-out") || strings.Contains(string(body), `{"statusCode":504,"error":"Gateway Timeout"`) || strings.Contains(string(body),`{"error":"Invalid Credentials"}`)  || strings.Contains(string(body),`Please retry request.`) || strings.Contains(string(body),`Please wait a moment`)  {
    
    //TODO: Build a GUI! :-)
    //log.Println(fmt.Sprintf("ERROR: Request '%v' returned:\n%v\n", endPoint, string(body) ))

    badGateways = append(badGateways, fmt.Sprintf("Requested:%v\nResponse Body:%s\n", url, strings.TrimSpace(string(body))))

    BAD_GATEWAY_IN_A_ROW = BAD_GATEWAY_IN_A_ROW + 1
    BAD_GATEWAY_TOTAL = BAD_GATEWAY_TOTAL + 1

    if cacheFileName != "" {
      os.Remove(cacheFileName)
    }

    time.Sleep(BAD_GATEWAY_TIMEOUT_MS ) 
    
    //RECURSE!!
    body = portal.Get(endPoint, httpMethod, folder)
  } else {
        
    if cacheFileName != "" {
      cacheContents := body
      if portal.useCryptoCache == true {
        r, err := util.Encrypt(body, encryptKey)
        if (err != nil) { log.Fatal(err) }
        cacheContents = r
      }

      err = ioutil.WriteFile(cacheFileName, cacheContents, 0644)
      if (err != nil) { log.Fatal(err) }

    }

  }

  //RESET!
  BAD_GATEWAY_IN_A_ROW = 0
  badGateways = nil


  //fmt.Print(GREEN+fmt.Sprintf("A")+RESET)  //API
  return body
}

func (portal *Portal) GetScanList() ScanList {
  var sl ScanList
  var endPoint = "scans"
  var cacheFolder = "scans" //Empty string means no cache!
  var httpMethod = "GET"

  var key = "allscans"
  item  := memcache.Get(key)
  if item  != nil {
    sl := item.Value().(ScanList)
    return sl
  }

  raw := portal.Get(endPoint, httpMethod, cacheFolder)

  err := json.Unmarshal([]byte(string(raw)), &sl)
  if err != nil {
      panic(err)
  }

  memcache.Set(key, sl, time.Minute * 60)

  return sl
}

func (portal *Portal) GetScanDetails(scanId string, historyIndex int) ScanDetails {

  var sd ScanDetails
  var key = "scan:" + scanId + ":" + fmt.Sprintf("%v",historyIndex)

  item := memcache.Get(key)
  if item != nil {
    sd := item.Value().(ScanDetails)
    return sd
  }

  var endPoint = "scans/" + scanId
  var httpMethod = "GET"
  
  raw := portal.Get(endPoint, httpMethod, endPoint)

  err := json.Unmarshal([]byte(string(raw)), &sd)
  if err != nil {
      panic(err)
  }

  sort.Slice(sd.History, func(i, j int) bool {
    iv, iverr := strconv.ParseInt(string(sd.History[i].HistoryId), 10, 64)
    if iverr != nil {
        panic(iverr)
    }
    jv, jverr := strconv.ParseInt(string(sd.History[j].HistoryId), 10, 64)
    if jverr != nil {
        panic(jverr)
    }
    return iv > jv
  })

  var offset int = historyIndex //len(sd.History) - historyIndex - 1

  if offset < 0 || offset >= len(sd.History) {
    return ScanDetails{}
  }

  var historyId = sd.History[offset].HistoryId 

  //var scanStatus = sd.History[offset].Status
  //if scanStatus == "running" {
  //  return ScanDetails{}
  //}
  
  var tenableEndPoint = "scans/" + scanId + "?history_id=" + string(historyId)
  var cacheFolder = "scans/" + scanId + "/history_id=" + string(historyId)

  //fmt.Println(fmt.Sprintf("tenableEndPoint: %v, cacheFolder: %v", tenableEndPoint, cacheFolder))
  
  raw = portal.Get(tenableEndPoint, httpMethod, cacheFolder)
  
  err = json.Unmarshal([]byte(string(raw)), &sd)
  if err != nil {
      panic(err)
  }

  sort.Slice(sd.History, func(i, j int) bool {
    iv, iverr := strconv.ParseInt(string(sd.History[i].HistoryId), 10, 64)
    if iverr != nil {
        panic(iverr)
    }
    jv, jverr := strconv.ParseInt(string(sd.History[j].HistoryId), 10, 64)
    if jverr != nil {
        panic(jverr)
    }
    return iv > jv
  })


  memcache.Set(key, sd, time.Minute * 60)

  return sd
}

func (portal *Portal) GetHostDetails(scanId string, hostId string, historyIndex int) HostDetails {
  var hd HostDetails
  
  var key = "scan:" + scanId + ":" + hostId + ":" + fmt.Sprintf("%v",historyIndex)

  item  := memcache.Get(key)
  if item  != nil {
    hd = item.Value().(HostDetails)
    return hd
  }

  var sd ScanDetails = portal.GetScanDetails(scanId, historyIndex)

  var historyId = sd.History[historyIndex].HistoryId 

  var tenableEndPoint = "scans/" + scanId + "/hosts/" + hostId + "?history_id=" + string(historyId)
  var cacheFolder = "scans/" + scanId + "/history_id=" + string(historyId) + "/hosts/" + hostId 

  var httpMethod = "GET"
  raw := string(portal.Get(tenableEndPoint, httpMethod, cacheFolder))

  err := json.Unmarshal([]byte(raw), &hd)

  if err != nil {
    var hd2 HostDetailsV2
    errV2 := json.Unmarshal([]byte(raw), &hd2)
    if errV2 != nil {
      log.Println(fmt.Sprintf("ERROR: Cannot unmarhall V2 (did they release V3???): %v", errV2 ))
      var cachefilename = portal.getCacheFilename(tenableEndPoint, httpMethod, cacheFolder)
      os.Remove(cachefilename)

      log.Fatal(fmt.Sprintf("Failed to parse.  Deleting cache filename '%s'", cachefilename ))
    }

    hd.Info.OperatingSystem=strings.Join(hd2.Info.OperatingSystem, "|") //Flatten the array

    //NOTE: There was a time when Tenable.IO stored this as a pure number (1510041721)
    if hostStartInt, err := strconv.ParseInt(string(hd2.Info.HostStart),10,64); err == nil {
      t := time.Unix(hostStartInt, 0)
      hd.Info.HostStart = fmt.Sprintf("%s", t.Format(time.ANSIC))
    } else {
      hd.Info.HostStart=fmt.Sprintf("%s", hd2.Info.HostStart)
    }

    if hostEndInt, err := strconv.ParseInt(string(hd2.Info.HostEnd),10,64); err == nil {
      t := time.Unix(hostEndInt, 0)
      hd.Info.HostEnd = fmt.Sprintf("%s", t.Format(time.ANSIC))
    } else {
      hd.Info.HostEnd=fmt.Sprintf("%s", hd2.Info.HostEnd)
    }

    hd.Info.MACAddress=hd2.Info.MACAddress
    hd.Info.FQDN =hd2.Info.FQDN 
    hd.Info.NetBIOS=hd2.Info.NetBIOS
    hd.Info.HostIP=hd2.Info.HostIP
    hd.Vulnerabilities = hd2.Vulnerabilities
  }

  memcache.Set(key, hd, time.Minute * 60)

  return hd
}

func (portal *Portal) GetScanName(scanId string) string {
  var key = fmt.Sprintf("scanName:%s", scanId)
  item  := memcache.Get(key)
  if item  != nil {
    return item.Value().(string)
  }

  var allScans = portal.GetScanList()

  var name = "STALECACHE"
  for _, scan := range allScans.Scans {
    if string(scan.Id) == scanId {
      name = scan.Name
      break;
    }
  }

  if name == "STALECACHE" {
    log.Fatal(fmt.Sprintf("Couldn't find '%v' ", scanId))
  }

  memcache.Set(key, name, time.Minute * 60)
  return name
}

func (portal * Portal) GetPlugin(pluginId string) Plugin {
  var plugin Plugin
  var httpMethod = "GET"
  var endPoint = "plugins/plugin/" + pluginId

  var key = "plugin:" + pluginId

  item  := memcache.Get(key)
  if item  != nil {
    plugin  := item.Value().(Plugin)
    return plugin
  }

  raw := string(portal.Get(endPoint, httpMethod, endPoint))

  err := json.Unmarshal([]byte(raw), &plugin)
  if err != nil {
      log.Fatalf("Malformed response for get plugin: '%v\n%v'", endPoint, raw)
  }

  //Unpack a few attributes from the array.
  for _, a := range plugin.Attributes {
    if a.Name == "risk_factor" {
      plugin.RiskFactor = a.Value

    } else if a.Name == "plugin_publication_date" {
      plugin.PluginPublicationDate = a.Value

    } else if a.Name == "patch_publication_date" {
      plugin.PatchPublicationDate = a.Value
 
    } else if a.Name == "fname" {
      plugin.FunctionName = a.Value
 
    }

    //Short-cut - break from loop if we have the attributes we wanted
    if  plugin.RiskFactor != "" && plugin.PluginPublicationDate != "" && plugin.PatchPublicationDate != "" {
      break;
    }
  }
  memcache.Set(key, plugin, time.Minute * 60)

  return plugin
}

