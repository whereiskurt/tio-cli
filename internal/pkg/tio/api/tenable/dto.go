//These are the API structures from the TIO documentation

package tenable

import (
	"encoding/json"
	"fmt"
	"time"
)

//https://cloud.tenable.com/api#/resources/scans/
type ScanList struct {
	Folders []struct {
		Id json.Number `json:"id"`
	}
	Scans     []ScanListItem `json:"scans"`
	Timestamp json.Number    `json:"timestamp"`
}

type ScanListItem struct {
	Id               json.Number `json:"id"`
	UUID             string      `json:"uuid"`
	Name             string      `json:"name"`
	Status           string      `json:"status"`
	Owner            string      `json:"owner"`
	UserPermissions  json.Number `json:"user_permissions"`
	Enabled          bool        `json:"enabled"`
	RRules           string      `json:"rrules"`
	Timezone         string      `json:"timezone"`
	StartTime        string      `json:"startTime"`
	CreationDate     json.Number `json:"creation_date"`
	LastModifiedDate json.Number `json:"last_modification_date"`
}

//https://cloud.tenable.com/api#/resources/scans/{scanId}
type ScanDetail struct {
	Info            ScanDetailInfo
	Hosts           []ScanDetailHosts
	Vulnerabilities []ScanDetailVulnerabilities
	History         []ScanDetailHistory
}
type ScanDetailInfo struct {
	Id           json.Number `json:"object_id"`
	UUID         string      `json:"uuid"`
	Owner        string      `json:"owner`
	Start        json.Number `json:"scan_start"`
	End          json.Number `json:"scan_end"`
	ScannerStart json.Number `json:"scanner_start"`
	ScannerEnd   json.Number `json:"scanner_end"`
	ScannerName  string      `json:"scanner_name"`
	HostCount    json.Number `json:"hostcount"`
	Targets      string      `json:"targets"`
	PolicyName   string      `json:"policy"`
}
type ScanDetailHosts struct {
	Id               json.Number `json:"host_id"`
	Index            json.Number `json:"host_index"`
	HostIP           string      `json:"hostname"` //the documentation is bad on this! It's actually IP address
	SeverityTotal    json.Number `json:"severity"`
	SeverityCritical json.Number `json:"critical"`
	SeverityHigh     json.Number `json:"high"`
	SeverityMedium   json.Number `json:"medium"`
	SeverityLow      json.Number `json:"low"`
}
type ScanDetailVulnerabilities struct {
	Id       json.Number `json:"vuln_index"`
	PluginId json.Number `json:"plugin_id"`
	Name     string      `json:"plugin_name"`
	HostName string      `json:"hostname"`
	Family   string      `json:"plugin_family"`
	Count    json.Number `json:"count"`
	Severity json.Number `json:"severity"`
}
type ScanDetailHistory struct {
	HistoryId        json.Number `json:"history_id"`
	UUID             string      `json:"uuid"`
	ScanType         string      `json:"type"`
	Status           string      `json:"status"`
	LastModifiedDate json.Number `json:"last_modification_date"`
	CreationDate     json.Number `json:"creation_date"`
}

//http://eagain.net/articles/go-dynamic-json/
//https://cloud.tenable.com/api#/resources/scans/{id}/host/{host_id}
type HostDetail struct {
	Info            HostDetailInfo
	Vulnerabilities []HostDetailVulnerabilities
}
type HostDetailInfo struct {
	HostStart       json.Number `json:"host_start"`       //becoming a number
	HostEnd         json.Number `json:"host_end"`         //becoming a number
	OperatingSystem []string    `json:"operating-system"` //becoming an array
	MACAddress      string      `json:"mac-address"`
	FQDN            string      `json:"host-fqdn"`
	NetBIOS         string      `json:"netbios-name"`
	HostIP          string      `json:"host-ip"`
}

//NOTE: This is needed for Marshal'ing back un-modified HotDetail object.
//      I think there is some type confusion where it treats the json.Numbers
//      as Date Strings... not sure what's up or why this is necessary entirely.
func (hdi HostDetailInfo) MarshalJSON() ([]byte, error) {
	var TM_FORMAT_NOTZ = "Mon Jan _2 15:04:05 2006"

	type Alias HostDetailInfo

	stm, _ := time.Parse(TM_FORMAT_NOTZ, fmt.Sprintf("%s", hdi.HostStart))
	etm, _ := time.Parse(TM_FORMAT_NOTZ, fmt.Sprintf("%s", hdi.HostEnd))

	start := json.Number(fmt.Sprintf("%d", stm.Unix()))
	end := json.Number(fmt.Sprintf("%d", etm.Unix()))

	return json.Marshal(&struct {
		HostStart json.Number `json:"host_start"` 
		HostEnd   json.Number `json:"host_end"`   
		Alias
	}{
		HostStart: json.Number(start),
		HostEnd:   json.Number(end),
		Alias:     (Alias)(hdi),
	})
}

type HostDetailLegacyV2 struct {
	Info            HostDetailInfoLegacyV2
	Vulnerabilities []HostDetailVulnerabilities
}
type HostDetailInfoLegacyV2 struct {
	HostStart       string `json:"host_start"`
	HostEnd         string `json:"host_end"`
	MACAddress      string `json:"mac-address"`
	FQDN            string `json:"host-fqdn"`
	NetBIOS         string `json:"netbios-name"`
	OperatingSystem string `json:"operating-system"`
	HostIP          string `json:"host-ip"`
}

type HostDetailVulnerabilities struct {
	HostId       json.Number `json:"host_id"`
	HostName     string      `json:"hostname"`
	PluginId     json.Number `json:"plugin_id"`
	PluginName   string      `json:"plugin_name"`
	PluginFamily string      `json:"plugin_family"`
	Count        json.Number `json:"count"`
	Severity     json.Number `json:"severity"`
}

//https://cloud.tenable.com/api#/resources/plugins/plugin/{pluginId}
//NOTE: A cache record would basically never goes stale.
type Plugin struct {
	Id         json.Number `json:"id"`
	Name       string      `json:"name"`
	FamilyName string      `json:"family_name"`
	Attributes []struct {
		Name  string `json:"attribute_name"`
		Value string `json:"attribute_value"`
	}
	RiskFactor                 string
	FunctionName               string
	PluginPublicationDate      string
	DaysSincePluginPublication string
	PatchPublicationDate       string
	DaysSincePatchPublication  string
}
