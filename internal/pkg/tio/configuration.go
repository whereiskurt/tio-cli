package tio

import (
	"os"
	"reflect"
)

type ConfigReflector interface {
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
	UseCryptoCache     bool
	QuietMode          bool
	NoColourMode       bool
	DisplayVersionMode bool
	LogFilename        string
	LogFileAppend      bool
	OutputFilename     string
	OutputFileAppend   bool
	ConcurrentWorkers  string
	Log                *os.File
	Output             *os.File
}

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
