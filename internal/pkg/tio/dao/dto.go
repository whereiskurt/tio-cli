package dao

import (
	"fmt"
	"strings"
)

type Scan struct {
	ScanId      string `json:"id"`
	UUID        string `json:"uuid"`
	Name        string `json:"name"`
	Status      string `json:"status"`
	Owner       string `json:"owner"`
	Targets     string `json:"targets"`
	ScannerName string `json:"scanner_name"`

	UserPermissions  string `json:"user_permissions"`
	Enabled          string `json:"enabled"`
	RRules           string `json:"rrules"`
	Timezone         string `json:"timezone"`
	StartTime        string `json:"start_time"`
	CreationDate     string `json:"creation_date"`
	LastModifiedDate string `json:"last_modification_date"`
	PolicyName       string `json:"policy_name"`
	Timestamp        string `json:"timestamp"`
}

func (s *Scan) CSV() string {
	return strings.Join([]string{s.ScanId, "'" + s.Name + "'", "'" + s.Status + "'", "'" + s.Owner + "'", "'" + s.Targets + "'", "'" + s.ScannerName + "'", "'" + s.Enabled + "'", "'" + s.RRules + "'", "'" + s.LastModifiedDate + "'", "'" + s.PolicyName + "'"}, ",")
}
func (s *Scan) CSVHeader() string {
	return fmt.Sprintf("ScanId,Name,Status,Owner,Targets,ScannerName,Enabled,RRules,LastModifiedDate,PolicyName")
}

type ScanHistory struct {
	Scan               Scan
	ScanHistoryCount   string `json:'ScanHistoryCount'`
	ScanHistoryDetails []ScanHistoryDetail
}

type ScanHistoryDetail struct {
	Scan Scan

	HistoryId           string `json:"history_id"`
	HistoryIndex        string `json:"history_index"`
	Status              string `json:"status"`
	CreationDate        string `json:'create_date'`
	LastModifiedDate    string `json:'last_modified_date'`
	PluginCriticalCount string `json:"plugin_critical_count"`
	PluginHighCount     string `json:"plugin_high_count"`
	PluginMediumCount   string `json:"plugin_medium_count"`
	PluginLowCount      string `json:"plugin_low_count"`
	PluginTotalCount    string `json:"plugin_total_count"`

	ScanStart     string `json:"scan_start"`
	ScanStartUnix string `json:"scan_start_unix"`
	ScanEnd       string `json:"scan_end"`
	ScanEndUnix   string `json:"scan_end_unix"`
	ScanDuration  string `json:"scan_duration"`

	HostCount  string                         `json:"hostCount"`
	Host       map[string]HostScanSummary     `json:"hostMap"`
	HostPlugin map[string]PluginDetailSummary `json:"hostPluginMap"`

	HostAssetMap map[string]string `json:"hostAssetMap"`
}

//TODO: Replace with building and ARRYA and using encoding/csv
func (s *ScanHistoryDetail) CSV() string {
	return strings.Join([]string{s.Scan.CSV(), s.HistoryId, s.HistoryIndex, "'" + s.Status + "'", s.CreationDate, s.LastModifiedDate, s.PluginCriticalCount, s.PluginHighCount, s.PluginMediumCount, s.PluginLowCount, s.PluginTotalCount, "'" + s.ScanStart + "'", s.ScanStartUnix, "'" + s.ScanEnd + "'", s.ScanEndUnix, "'" + s.ScanDuration + "'", s.HostCount}, ",")
}
func (s *ScanHistoryDetail) CSVHeader() string {
	return fmt.Sprintf("%s,%s", s.Scan.CSVHeader(), "HistoryId,HistoryIndex,Status,CreationDate,LastModifiedDate,PluginCriticalCount,PluginHighCount,PluginMediumCount,PluginLowCount,PluginTotalCount,ScanStart,ScanStartUnix,ScanEnd,ScanEndUnix,ScanDuration,HostCount")
}

type HostScanSummary struct {
	HostId              string `json:"hostId"`
	Asset               AssetDetail
	ScanDetail          ScanHistoryDetail
	HostDetail          HostScanDetail
	PluginCriticalCount string `json:"pluginCriticalCount"`
	PluginHighCount     string `json:"pluginHighCount"`
	PluginMediumCount   string `json:"pluginMediumCount"`
	PluginLowCount      string `json:"pluginLowCount"`
	PluginTotalCount    string `json:"pluginTotalCount"`
}

type HostScanDetail struct {
	FQDN             string                         `json:"hostFQDN"`
	IP               string                         `json:"hostIP"`
	NetBIOS          string                         `json:"hostNetBIOS"` //Windows only, but prevelant.
	MACAddresses     string                         `json:"hostMACAddresses"`
	OperatingSystems string                         `json:"hostOperatingSystems"`
	ScanStart        string                         `json:"hostScanStart"`
	ScanStartUnix    string                         `json:"hostScanStartUnix"`
	ScanEnd          string                         `json:"hostScanEnd"`
	ScanEndUnix      string                         `json:"hostScanEndUnix"`
	ScanDuration     string                         `json:"hostScanDuration"`
	Plugin           map[string]PluginDetailSummary `json:"hostPluginMap"`
}

type PluginDetailSummary struct {
	PluginId string `"json:pluginId"`
	Name     string `"json:pluginName"`
	Family   string `"json:pluginFamily"`
	Count    string `"json:pluginCount"`
	Severity string `"json:severityTypeId"`
	Detail   PluginDetail
}

type PluginDetail struct {
	RiskFactor            string `"json:riskFactor"`
	FunctionName          string `"json:functionName"`
	PluginPublicationDate string `"json:pluginPublicationDate"`
	PatchPublicationDate  string `"json:patchPublicationDate"`
	Attribute             map[string]PluginDetailAttribute
}
type PluginDetailAttribute struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

////// Computed
type HostPluginExposure struct {
	Host                    HostScanSummary
	Plugin                  PluginDetailSummary
	FirstScan               ScanHistoryDetail
	LastScan                ScanHistoryDetail
	DaysSinceFirstDetection string `json:"daysSinceFirstDetection"`
	DaysSinceLastDetection  string `json:"DaysSinceLastDetection"`
	VulnerableStatus        string `json:"VulnerableStatus"`
	DurationStatus          string `json:"DurationStatus"`
	IsVulnerable            bool   `json:"IsVulnerable"`
	IsPatched               bool   `json:"IsPatched"`
}

type AssetDetail struct {
	UUID string
	Tags []AssetTagDetail
}

type AssetTagDetail struct {
	UUID         string
	CategoryName string
	Value        string
	AddedBy      string
	AddedAt      string
	Source       string
}
