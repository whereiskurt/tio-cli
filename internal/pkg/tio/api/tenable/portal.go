package tenable

import (
	"errors"
	"fmt"
	"github.com/whereiskurt/tio-cli/internal/pkg/tio"
	"io/ioutil"
	"net/http"
	"strings"
	"time"
)

type Portal struct {
	BaseUrl       string
	AccessKey     string
	SecretKey     string
	TenableHeader string
	Log           *tio.Logger
	stats         map[string]interface{}
	counters      map[string]int
}

func NewPortal(config *tio.BaseConfig) *Portal {
	p := new(Portal)
	p.Log = config.Logger

	p.BaseUrl = config.BaseUrl
	p.AccessKey = config.AccessKey
	p.SecretKey = config.SecretKey

	p.TenableHeader = fmt.Sprintf("accessKey=%s;secretKey=%s", config.AccessKey, config.SecretKey)

	p.stats = make(map[string]interface{})
	p.counters = make(map[string]int)
	config.AddStatistics("tenable.portal", &p.stats)
	return p
}

var tr = &http.Transport{
	MaxIdleConns:    20,
	IdleConnTimeout: 60 * time.Second,
}

func (portal *Portal) Delete(endPoint string) error {
	var url string = portal.BaseUrl + "/" + endPoint

	client := &http.Client{Transport: tr}
	req, err := http.NewRequest("DELETE", url, nil)
	if err != nil {
		portal.Log.Errorf("%s", err)
		return err
	}

	req.Header.Add("X-ApiKeys", portal.TenableHeader)

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
		err := errors.New("Cannot delete from Tenable.IO, feature not yet implemented.")
		portal.Log.Errorf("%s", err)
		return err
	}

	return nil
}

func (portal *Portal) Get(endPoint string) ([]byte, error) {
	var url string = endPoint
	var method string = "GET"

	portal.counters["GET"]++
	portal.stats["GET"] = fmt.Sprintf("%d", portal.counters["GET"])
	//portal.stats["ENDPOINT"] = append(portal.stats["ENDPOINT"], url)

	client := &http.Client{Transport: tr}
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		portal.Log.Errorf("%s", err)
		return nil, err
	}
	req.Header.Add("X-ApiKeys", portal.TenableHeader)

	//Make the request
	var reqStartTime = time.Now() //Start the clock!
	resp, err := client.Do(req)
	if err != nil {
		portal.Log.Errorf("%s", err)
		return nil, err
	}
	var reqEndTime = time.Now() //Stop the clock!
	defer resp.Body.Close()

	var reqDuration = fmt.Sprintf("%v", reqEndTime.Sub(reqStartTime))

	portal.Log.Debugf("GET '%s' took %v", url, reqDuration)

	//Read the repsonse
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
		warn := fmt.Sprintf("SOFT FAILURE: GET %s failed : Body:\n%s\n", endPoint, body)
		portal.Log.Warn(warn)
		err := errors.New(warn)
		return body, err
	}

	return body, nil
}
