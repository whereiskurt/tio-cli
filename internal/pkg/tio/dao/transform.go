package dao

import (
	"fmt"
	"github.com/whereiskurt/tio-cli/internal/pkg/tio/api/tenable"
	"strconv"
	"strings"
	"time"
)

var TM_FORMAT_NOTZ = "Mon Jan _2 15:04:05 2006"
var TM_FORMAT_TZ string = "2006-01-_2 15:04:05 -0700 MST"

func (trans *Translator) fromScanList(scanList tenable.ScanList) []Scan {
	var scans []Scan

	for _, s := range scanList.Scans {
		scanId := string(s.Id)

		if trans.ShouldSkipScanId(scanId) {
			continue
		}

		scan := new(Scan)
		scan.ScanId = scanId
		scan.UUID = s.UUID
		scan.Name = s.Name
		scan.Status = s.Status
		scan.Owner = s.Owner
		scan.UserPermissions = string(s.UserPermissions)
		scan.Enabled = fmt.Sprintf("%v", s.Enabled)
		scan.RRules = s.RRules
		scan.Timezone = s.Timezone
		scan.StartTime = s.StartTime
		scan.CreationDate = string(s.CreationDate)
		scan.LastModifiedDate = string(s.LastModifiedDate)
		scan.Timestamp = string(scanList.Timestamp)

		scans = append(scans, *scan)
	}

	return scans
}

func (trans *Translator) fromScanDetail(scanId string, detail tenable.ScanDetail) (record ScanHistory, err error) {
	var previousOffset, _ = strconv.Atoi(trans.Config.Previous)
	var depth, _ = strconv.Atoi(trans.Config.Depth)

	scan, err := trans.GetScan(scanId)
	if err != nil {
		trans.Errorf("%s", err)
		return record, err
	}

	record.Scan.ScanId = scanId
	record.Scan.UUID = scan.UUID
	record.Scan.Name = scan.Name
	record.Scan.PolicyName = detail.Info.PolicyName
	record.Scan.Owner = detail.Info.Owner
	record.Scan.Targets = detail.Info.Targets
	record.Scan.CreationDate = string(scan.CreationDate)
	record.Scan.LastModifiedDate = string(scan.LastModifiedDate)
	record.Scan.Status = scan.Status
	record.Scan.Enabled = fmt.Sprintf("%s", scan.Enabled)
	record.Scan.RRules = scan.RRules
	record.Scan.Timezone = scan.Timezone
	record.Scan.StartTime = scan.StartTime
	record.Scan.PolicyName = detail.Info.PolicyName
	record.ScanHistoryCount = fmt.Sprintf("%v", len(detail.History))
	record.Scan.ScannerName = detail.Info.ScannerName

	for i := previousOffset; i < len(detail.History) && i < depth+previousOffset; i++ {
		var hist = new(ScanHistoryDetail)

		historyId, err := trans.getTenableHistoryId(scanId, i)
		if err != nil {
			trans.Errorf("HistoryID not available for scan '%s' offset '%d' - %s", scanId, i, err)
			return record, err
		}

		if trans.ShouldSkipHistoryId(historyId) {
			continue
		}

		histDetails, err := trans.getTenableScanDetail(scanId, historyId)
		if err != nil {
			trans.Errorf("%s", err)
			return record, err
		}

		hist.HistoryId = fmt.Sprintf("%v", histDetails.History[i].HistoryId)
		hist.HostCount = fmt.Sprintf("%v", len(histDetails.Hosts))
		hist.LastModifiedDate = string(histDetails.History[i].LastModifiedDate)
		hist.CreationDate = string(histDetails.History[i].CreationDate)
		hist.Status = histDetails.History[i].Status

		start := histDetails.Info.Start
		end := histDetails.Info.End

		rawScanStart, errParseStart := strconv.ParseInt(string(start), 10, 64)
		if errParseStart != nil {
			rawScanStart = int64(0)
			trans.Warnf("hist.Start: Failed to parse value '%s' for scan '%s':id:%s:histid:%s (status: %s). Setting to zero.", string(start), record.Scan.Name, record.Scan.ScanId, historyId, hist.Status)
		}

		rawScanEnd, errParseEnd := strconv.ParseInt(string(end), 10, 64)
		if errParseEnd != nil {
			rawScanEnd = rawScanStart
			trans.Warnf("hist.End: Failed to parse value '%s' for scan name:'%s':id:%s:histid:%s (status: %s). Setting to %s", string(end), record.Scan.Name, record.Scan.ScanId, historyId, hist.Status, string(start))
		}

		unixScanStart := time.Unix(rawScanStart, 0)
		unixScanEnd := time.Unix(rawScanEnd, 0)

		hist.ScanStart = fmt.Sprintf("%v", unixScanStart)
		hist.ScanStartUnix = fmt.Sprintf("%s", string(start))
		hist.ScanEnd = fmt.Sprintf("%v", unixScanEnd)
		hist.ScanEndUnix = fmt.Sprintf("%s", string(end))
		hist.ScanDuration = fmt.Sprintf("%v", unixScanEnd.Sub(unixScanStart))

		hist.Host = make(map[string]HostScanDetailSummary)

		for _, host := range histDetails.Hosts {
			var retHost HostScanDetailSummary
			var hostId = string(host.Id)

			critsHist, _ := strconv.Atoi(hist.PluginCriticalCount)
			critsHost, _ := strconv.Atoi(string(host.SeverityCritical))
			highHist, _ := strconv.Atoi(hist.PluginHighCount)
			highHost, _ := strconv.Atoi(string(host.SeverityHigh))
			mediumHist, _ := strconv.Atoi(hist.PluginMediumCount)
			mediumHost, _ := strconv.Atoi(string(host.SeverityMedium))
			lowHist, _ := strconv.Atoi(hist.PluginLowCount)
			lowHost, _ := strconv.Atoi(string(host.SeverityLow))

			retHost.HostId = hostId
			retHost.ScanDetail.Scan.ScanId = scanId
			retHost.ScanDetail.HistoryId = historyId
			retHost.ScanDetail.HistoryIndex = fmt.Sprintf("%v", i)

			retHost.PluginCriticalCount = fmt.Sprintf("%v", critsHost)
			retHost.PluginHighCount = fmt.Sprintf("%v", highHost)
			retHost.PluginMediumCount = fmt.Sprintf("%v", mediumHost)
			retHost.PluginLowCount = fmt.Sprintf("%v", lowHost)
			retHost.PluginTotalCount = fmt.Sprintf("%v", lowHost+mediumHost+highHost+critsHost)

			hist.Host[hostId] = retHost

			//Running COUNT for the historical
			hist.PluginCriticalCount = fmt.Sprintf("%v", critsHist+critsHost)
			hist.PluginHighCount = fmt.Sprintf("%v", highHist+highHost)
			hist.PluginMediumCount = fmt.Sprintf("%v", mediumHist+mediumHost)
			hist.PluginLowCount = fmt.Sprintf("%v", lowHist+lowHost)
			hist.PluginTotalCount = fmt.Sprintf("%v", lowHist+lowHost+mediumHist+mediumHost+highHist+highHost+critsHist+critsHost)
		}

		hist.HostPlugin = make(map[string]PluginDetailSummary)

		for _, vuln := range histDetails.Vulnerabilities {
			var retPlugin PluginDetailSummary

			if trans.ShouldSkipPluginId(string(vuln.PluginId)) {
				continue
			}

			retPlugin.PluginId = string(vuln.PluginId)
			retPlugin.Name = vuln.Name
			retPlugin.Family = vuln.Family
			retPlugin.Count = string(vuln.Count)
			retPlugin.Severity = string(vuln.Severity)

			hist.HostPlugin[string(vuln.PluginId)] = retPlugin
		}

		record.ScanHistoryDetails = append(record.ScanHistoryDetails, *hist)
	}

	return record, nil
}

func (trans *Translator) fromHostDetailSummary(hsd HostScanDetailSummary, hd tenable.HostDetail) (host HostScanDetail, err error) {

	tz := trans.GetScannerTZ(hsd.ScanDetail.Scan)

	host.IP = hd.Info.HostIP
	host.FQDN = hd.Info.FQDN
	host.NetBIOS = hd.Info.NetBIOS
	host.MACAddresses = strings.Replace(hd.Info.MACAddress, "\n", ",", -1)
	host.OperatingSystems = strings.Join(hd.Info.OperatingSystem, ",")

	start, tmStart, err := trans.fromNoTZ(string(hd.Info.HostStart), tz)
	host.ScanStartUnix = fmt.Sprintf("%v", tmStart.In(time.Local).Unix())
	host.ScanStart = start

	end, tmEnd, err := trans.fromNoTZ(string(hd.Info.HostEnd), tz)
	host.ScanEndUnix = fmt.Sprintf("%v", tmEnd.In(time.Local).Unix())
	host.ScanEnd = end

	host.ScanDuration = fmt.Sprintf("%v", tmEnd.Sub(tmStart))

	host.Plugin = make(map[string]PluginDetailSummary)

	for _, v := range hd.Vulnerabilities {
		var p PluginDetailSummary
		p.PluginId = string(v.PluginId)
		p.Name = v.PluginName
		p.Family = v.PluginFamily
		p.Count = string(v.Count)
		p.Severity = string(v.Severity)
		host.Plugin[p.PluginId] = p
	}

	return host, nil
}

func (trans *Translator) fromNoTZ(dts string, setTZ string) (withTZ string, unix time.Time, err error) {
	unix, err = time.Parse(TM_FORMAT_NOTZ, dts)
	if err != nil {
		trans.Warnf("Couldn't parse time.ANSIC for '%v' as integer.", dts)
		return withTZ, unix, err
	}

	//Render UNIX time (which is UTC 0) and add timezone from scanner.
	//The scanner captured the UNIX time, without a TZ.
	withTZ = strings.Replace(fmt.Sprintf("%v", unix), "+0000 UTC", setTZ, -1)
	tmTZ, err := time.Parse(TM_FORMAT_TZ, withTZ)

	if err != nil {
		trans.Warnf("Couldn't parse Unix date '%v' with timezone '%s'.", unix, setTZ)
		return withTZ, unix, err
	}
	withTZ = fmt.Sprintf("%v", tmTZ)
	return withTZ, unix, err
}
