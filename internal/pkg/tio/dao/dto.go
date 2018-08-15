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

	HistoryId           string
	HistoryIndex        string
	Status              string
	CreationDate        string
	LastModifiedDate    string
	PluginCriticalCount string
	PluginHighCount     string
	PluginMediumCount   string
	PluginLowCount      string
	PluginTotalCount    string

	ScanStart     string
	ScanStartUnix string
	ScanEnd       string
	ScanEndUnix   string
	ScanDuration  string

	HostCount  string
	Host       map[string]HostScanSummary
	HostPlugin map[string]PluginDetailSummary

	HostAssetMap map[string]string
}

//TODO: Replace with building and ARRYA and using encoding/csv
func (s *ScanHistoryDetail) CSV() string {
	return strings.Join([]string{s.Scan.CSV(), s.HistoryId, s.HistoryIndex, "'" + s.Status + "'", s.CreationDate, s.LastModifiedDate, s.PluginCriticalCount, s.PluginHighCount, s.PluginMediumCount, s.PluginLowCount, s.PluginTotalCount, "'" + s.ScanStart + "'", s.ScanStartUnix, "'" + s.ScanEnd + "'", s.ScanEndUnix, "'" + s.ScanDuration + "'", s.HostCount}, ",")
}
func (s *ScanHistoryDetail) CSVHeader() string {
	return fmt.Sprintf("%s,%s", s.Scan.CSVHeader(), "HistoryId,HistoryIndex,Status,CreationDate,LastModifiedDate,PluginCriticalCount,PluginHighCount,PluginMediumCount,PluginLowCount,PluginTotalCount,ScanStart,ScanStartUnix,ScanEnd,ScanEndUnix,ScanDuration,HostCount")
}

type HostScanSummary struct {
	HostId              string
	Asset               AssetDetail
	ScanDetail          ScanHistoryDetail
	HostDetail          HostScanDetail
	PluginCriticalCount string
	PluginHighCount     string
	PluginMediumCount   string
	PluginLowCount      string
	PluginTotalCount    string
}

type HostScanDetail struct {
	IP               string
	FQDN             string
	NetBIOS          string
	MACAddresses     string
	OperatingSystems string
	ScanStart        string
	ScanStartUnix    string
	ScanEnd          string
	ScanEndUnix      string
	ScanDuration     string
	Plugin           map[string]PluginDetailSummary
}

type PluginDetailSummary struct {
	PluginId string
	Name     string
	Family   string
	Count    string
	Severity string
	Detail   PluginDetail
}

type PluginDetail struct {
	RiskFactor            string
	FunctionName          string
	PluginPublicationDate string
	PatchPublicationDate  string
	Attribute             map[string]PluginDetailAttribute
}
type PluginDetailAttribute struct {
	Name  string
	Value string
}

////// Computed
type HostPluginExposure struct {
	Host                    HostScanSummary
	Plugin                  PluginDetailSummary
	FirstScan               ScanHistoryDetail
	LastScan                ScanHistoryDetail
	DaysSinceFirstDetection string
	DaysSinceLastDetection  string
	VulnerableStatus        string
	DurationStatus          string
	IsVulnerable            bool
	IsPatched               bool
}

type AssetDetail struct {
	UUID        string
	Tags        []AssetTagDetail
	TenableUUID []string
	IPV4        []string
	IPV6        []string
	FQDN        []string
	MACAddress  []string
	NetBIOS     []string
	SystemType  []string
	HostName    []string
	AgentName   []string
	BIOSUUID    []string
}

type AssetTagDetail struct {
	UUID         string
	CategoryName string
	Value        string
	AddedBy      string
	AddedAt      string
	Source       string
}

type TagValue struct {
	ContainerUUID       string
	UUID                string
	ModelName           string
	Value               string
	Description         string
	Type                string
	CategoryUUID        string
	CategoryName        string
	CategoryDescription string
}

type TagCategory struct {
	ContainerUUID string
	UUID          string
	ModelName     string
	Name          string
	Description   string
}
