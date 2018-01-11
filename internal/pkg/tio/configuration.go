package tio

import (
	//	"fmt"
	"os"
	"reflect"
)

type ReflectIntoConfig interface {
	SetString(field string, value string)
	SetBool(field string, value bool)
}

type BaseConfig struct {
	ConfigFile         string
	VerbosityMode      string
	BaseUrl            string
	AccessKey          string
	SecretKey          string
	CacheKey           string
	CacheFolder        string
	CacheDisabled      bool
	UseCryptoCache     bool
	QuietMode          bool
	OfflineMode          bool
	NoColourMode       bool
	DisplayVersionMode bool
	LogFilename        string
	LogFolder          string
	LogFileAppend      bool

	DefaultTimezone   string

	OutputFilename   string
	OutputFolder     string
	OutputFileAppend bool
	OutputCSVMode    bool
	OutputJSONMode   bool

	ConcurrentWorkers string
	DisplayGUIMode    bool

	LogFileHandle *os.File
	Logger        *Logger

	Output         *os.File
	statisticsRefs map[string]*map[string]interface{}
}

func (config *BaseConfig) AddStatistics(key string, stats *map[string]interface{}) {
	config.statisticsRefs[key] = stats
	return
}
func (config *BaseConfig) GetStatistics() map[string]*map[string]interface{} {
	return config.statisticsRefs
}

// func (config *BaseConfig) String() string {
// 	return fmt.Sprintf("BaseConfig: BLAHBLAHLBAH")
// }

// func (config *VulnerabilityConfig) String() string {
// 	return fmt.Sprintf("VulnConfig: BLAHBLAHLBAH")
// }

type VulnerabilityConfig struct {
	Base            *BaseConfig
	Current         bool
	Previous        string
	Depth           string
	DetailView      bool
	ListView        bool
	ScanId          string
	IgnoreScanId    string
	HistoryId       string
	IgnoreHistoryId string
	AssetId         string
	IgnoreAssetId   string
	PluginId        string
	IgnorePluginId  string
}

func NewBaseConfig() *BaseConfig {
	c := new(BaseConfig)
	c.statisticsRefs = make(map[string]*map[string]interface{})
	return c
}
func NewVulnerabilityConfig() *VulnerabilityConfig {
	c := new(VulnerabilityConfig)
	c.Base = NewBaseConfig()
	return c
}

func (config *BaseConfig) SetString(field string, value string) {
	v := reflect.ValueOf(config).Elem().FieldByName(field)
	if v.IsValid() {
		v.SetString(value)
	}
	return
}
func (vulnConfig *VulnerabilityConfig) SetString(field string, value string) {
	v := reflect.ValueOf(vulnConfig).Elem().FieldByName(field)
	if v.IsValid() {
		v.SetString(value)
	}
	return
}
func (config *BaseConfig) SetBool(field string, value bool) {
	v := reflect.ValueOf(config).Elem().FieldByName(field)
	if v.IsValid() {
		v.SetBool(value)
	}
	return
}
func (vulnConfig *VulnerabilityConfig) SetBool(field string, value bool) {
	v := reflect.ValueOf(vulnConfig).Elem().FieldByName(field)
	if v.IsValid() {
		v.SetBool(value)
	}
	return
}
