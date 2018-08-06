package tenable

import (
	"bytes"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	"github.com/whereiskurt/tio-cli/internal/pkg/tio"
)

const (
	STAT_API_GETSUCCESS  tio.StatType = "tio.api.GET.Success"
	STAT_API_GETFAILED   tio.StatType = "tio.api.GET.Failure"
	STAT_API_POSTSUCCESS tio.StatType = "tio.api.POST.Success"
	STAT_API_POSTFAILED  tio.StatType = "tio.api.POST.Failure"
)

type Portal struct {
	BaseUrl   string
	AccessKey string
	SecretKey string
	Log       *tio.Logger
	Stats     *tio.Statistics
}

func NewPortal(config *tio.BaseConfig) *Portal {
	p := new(Portal)
	p.Log = config.Logger

	p.BaseUrl = config.BaseUrl
	p.AccessKey = config.AccessKey
	p.SecretKey = config.SecretKey

	p.Stats = tio.NewStatistics()

	return p
}

var tr = &http.Transport{
	MaxIdleConns:    20,
	IdleConnTimeout: 30 * time.Second,
}

var headerCalls int

func (portal *Portal) TenableXHeader() string {
	headerCalls++
	akeys := strings.Split(portal.AccessKey, ",")
	skeys := strings.Split(portal.SecretKey, ",")

	var key int = headerCalls % len(akeys)

	return fmt.Sprintf("accessKey=%s;secretKey=%s", akeys[key], skeys[key])
}

//NOTE: HTTP DELETE is NOT implemented for deleting scan history_id..
func (portal *Portal) Delete(endPoint string) error {
	var url string = endPoint

	client := &http.Client{Transport: tr}
	req, err := http.NewRequest("DELETE", url, nil)
	if err != nil {
		portal.Log.Errorf("%s", err)
		return err
	}

	req.Header.Add("X-ApiKeys", portal.TenableXHeader())

	resp, err := client.Do(req)
	if err != nil {
		portal.Log.Errorf("%s", err)
		return err
	}

	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		portal.Log.Errorf("%s", err)
		return err
	}

	if strings.Contains(string(body), `"error"`) {
		err := errors.New(fmt.Sprintf("Cannot delete from Tenable.IO, feature not yet implemented:%s", string(body)))
		portal.Log.Errorf("%s", err)
		return err
	}

	return nil
}

func (portal *Portal) Post(endPoint string, postData string, postType string) (body []byte, err error) {
	var reqStartTime = time.Now() //Start the clock!

	client := &http.Client{Transport: tr}

	req, err := http.NewRequest("POST", endPoint, bytes.NewBuffer([]byte(postData)))
	if err != nil {
		portal.Log.Errorf("%s", err)
		return nil, err
	}
	req.Header.Add("X-ApiKeys", portal.TenableXHeader())
	req.Header.Set("Content-Type", postType)

	resp, err := client.Do(req) // <-------HTTPS GET Request!
	if err != nil {
		portal.Stats.Count(STAT_API_POSTFAILED)
		portal.Log.Errorf("%s", err)
		return nil, err
	}
	defer resp.Body.Close()
	portal.Stats.Count(STAT_API_POSTSUCCESS)

	var reqEndTime = time.Now() //Stop the clock!
	var reqDuration = fmt.Sprintf("%v", reqEndTime.Sub(reqStartTime))

	portal.Log.Debugf("HTTP POST '%s' took %v", endPoint, reqDuration)

	body, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		portal.Log.Errorf("%s", err)
		return nil, err
	}

	return body, nil
}

func (portal *Portal) Get(endPoint string) ([]byte, error) {
	var reqStartTime = time.Now() //Start the clock!

	client := &http.Client{Transport: tr}

	req, err := http.NewRequest("GET", endPoint, nil)
	if err != nil {
		portal.Log.Errorf("%s", err)
		return nil, err
	}
	req.Header.Add("X-ApiKeys", portal.TenableXHeader())

	resp, err := client.Do(req) // <-------HTTPS GET Request!
	if err != nil {
		portal.Stats.Count(STAT_API_GETFAILED)
		portal.Log.Errorf("%s", err)
		return nil, err
	}
	defer resp.Body.Close()

	portal.Stats.Count(STAT_API_GETSUCCESS)

	var reqEndTime = time.Now() //Stop the clock!
	var reqDuration = fmt.Sprintf("%v", reqEndTime.Sub(reqStartTime))

	portal.Log.Debugf("HTTP GET '%s' took %v", endPoint, reqDuration)

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		portal.Log.Errorf("%s", err)
		return nil, err
	}

	//////////
	//Full message from cloud.tenable.io:
	//  {"statusCode":401,"error":"Unauthorized","message":"Invalid Credentials"}
	if strings.Contains(string(body), `"statusCode":401`) {
		err := errors.New("Your secretKey and accessKey (credentials) are invalid.")
		portal.Log.Errorf("%s", err)
		return nil, err
	}

	if strings.Contains(string(body), `{"error":"Asset or host not found"}`) || strings.Contains(string(body), `{"error":"You need to log in to perform this request"}`) || strings.Contains(string(body), "504 Gateway Time-out") || strings.Contains(string(body), `{"statusCode":504,"error":"Gateway Timeout"`) || strings.Contains(string(body), `{"error":"Invalid Credentials"}`) || strings.Contains(string(body), `Please retry request.`) || strings.Contains(string(body), `Please wait a moment`) {
		warn := fmt.Sprintf("FAILED: GET '%s' Body:'%s'", endPoint, body)
		portal.Log.Warn(warn)
		err := errors.New(warn)
		return body, err
	}

	return body, nil
}
