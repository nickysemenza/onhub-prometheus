package main

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/benmanns/onhub/diagnosticreport"
	"github.com/hako/durafmt"
	"github.com/olekukonko/tablewriter"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const reportURL = "http://onhub.here/api/v1/diagnostic-report"
const reportFetchFrequency = time.Second

var (
	reportFetchTiming = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "harrison",
		Subsystem: "onhub",
		Name:      "report_fetch_timing",
		Help:      "Number of ms it takes to fetch the report",
	})
	deviceCount = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "harrison",
		Subsystem: "onhub",
		Name:      "active_devices",
		Help:      "Number of active devices on the network",
	})
	deviceState = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "harrison",
		Subsystem: "onhub",
		Name:      "device_state",
		Help:      "Current device state",
	},
		[]string{"device_id", "hostname", "ip", "last_seen"})
)

type device struct {
	id       string
	hostname string
	ip       string
	// lastSeen          time.Time
	timeSinceLastSeen time.Duration
}

func (d *device) getSinceLastSeenString() string {
	return durafmt.Parse(d.timeSinceLastSeen).String()
}

func (d *device) isActive() bool {
	return d.timeSinceLastSeen == time.Duration(0)
}

type deviceList []device

func (i *infoSection) buildDeviceList() deviceList {
	var devices deviceList
	for _, x := range i.ApState.Stations {
		prettyName := x.DhcpHostname
		if prettyName == "" {
			prettyName = fmt.Sprintf("(%s)", truncateString(x.ID, 20))
		}

		ip := ""
		if len(x.IPAddresses) > 0 {
			ip = x.IPAddresses[0]
		}
		since := time.Duration(0)
		if !x.Connected {
			lastSeenTime := time.Unix(int64(x.LastSeenSecondsSinceEpoch), 0)
			since = time.Since(lastSeenTime).Truncate(time.Minute)
		}

		devices = append(devices, device{
			id:                x.ID,
			hostname:          x.DhcpHostname,
			ip:                ip,
			timeSinceLastSeen: since,
		})

	}
	return devices
}

func calculateMetrics(devices deviceList) {
	activeDevices := 0
	for _, d := range devices {
		a := float64(0)
		if d.isActive() {
			activeDevices++
			a = 1
		}
		deviceState.WithLabelValues(d.id, d.hostname, d.ip, d.getSinceLastSeenString()).Set(a)
	}
	deviceCount.Set(float64(activeDevices))
}
func init() {
	prometheus.MustRegister(deviceCount)
	prometheus.MustRegister(deviceState)
	prometheus.MustRegister(reportFetchTiming)
}
func renderTable(dl deviceList) {
	table := tablewriter.NewWriter(os.Stdout)
	for _, d := range dl {
		table.Append([]string{truncateString(d.id, 10), d.hostname, d.ip, d.getSinceLastSeenString()})
	}
	table.SetHeader([]string{"id", "hostname", "ip", "last seen"})
	table.Render()
}
func main() {

	go func() {
		for {
			fetchAndProcess()
			time.Sleep(reportFetchFrequency)
		}
	}()

	log.Println("starting server...")

	http.Handle("/metrics", promhttp.Handler())
	log.Fatal(http.ListenAndServe(":9999", nil))
}

func fetchAndProcess() {
	//fetch
	start := time.Now()
	if err := fetchDiagnosticReport(); err != nil {
		log.Fatalln("error fetching report", err)
	}
	durationMs := time.Since(start) / time.Millisecond
	reportFetchTiming.Set(float64(durationMs))
	log.Println("fetched diagnostic report.")

	//process
	report, err := parseReportFromFile()
	if err != nil {
		log.Fatalln("failed parsing")
	}
	info := getDiagnosticReportInfo(report)

	devices := info.buildDeviceList()
	calculateMetrics(devices)
}

func getDiagnosticReportInfo(report *diagnosticreport.DiagnosticReport) infoSection {
	info := infoSection{}
	json.Unmarshal([]byte(report.InfoJSON), &info)
	return info
}

func parseReportFromFile() (*diagnosticreport.DiagnosticReport, error) {
	file, err := os.Open("diagnostic-report")
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := ioutil.ReadAll(file)
	if err != nil {
		return nil, err
	}
	return diagnosticreport.Parse(data)
}

func fetchDiagnosticReport() error {
	resp, err := http.Get(reportURL)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	out, err := os.Create("diagnostic-report")
	if err != nil {
		return err
	}
	defer out.Close()
	io.Copy(out, resp.Body)
	return nil
}

type infoSection struct {
	ApCloudStorage struct {
		LocalClientMeshLatencyTestResults struct {
		} `json:"_localClientMeshLatencyTestResults"`
		LocalClientSpeedTestResults struct {
		} `json:"_localClientSpeedTestResults"`
		WanConnectivityTestResult struct {
		} `json:"_wanConnectivityTestResult"`
		WanSpeedTestRequest struct {
			DateTimeSecondsSinceEpoch int `json:"_dateTimeSecondsSinceEpoch"`
		} `json:"_wanSpeedTestRequest"`
		WanSpeedTestResults struct {
			DateTimeSecondsSinceEpoch   int `json:"_dateTimeSecondsSinceEpoch"`
			DownloadSpeedBytesPerSecond int `json:"_downloadSpeedBytesPerSecond"`
			UploadSpeedBytesPerSecond   int `json:"_uploadSpeedBytesPerSecond"`
		} `json:"_wanSpeedTestResults"`
		WifiblasterSpeedTestResults struct {
			PerStationThroughputResults []struct {
				DateTimeSecondsSinceEpoch  int    `json:"_dateTimeSecondsSinceEpoch"`
				DownlinkSpeedBitsPerSecond int    `json:"_downlinkSpeedBitsPerSecond"`
				StationID                  string `json:"_stationId"`
			} `json:"_perStationThroughputResults"`
		} `json:"_wifiblasterSpeedTestResults"`
	} `json:"_apCloudStorage"`
	ApConfiguration struct {
		AnonymousMetricsCollection struct {
			Enabled bool `json:"_enabled"`
		} `json:"_anonymousMetricsCollection"`
		AnonymousMetricsCollectionConfiguration struct {
			Enabled bool `json:"_enabled"`
		} `json:"_anonymousMetricsCollectionConfiguration"`
		AutoUpdateChannelConfiguration struct {
			Channel string `json:"_channel"`
		} `json:"_autoUpdateChannelConfiguration"`
		BackgroundDataCollectionConfiguration struct {
			Enabled bool `json:"_enabled"`
		} `json:"_backgroundDataCollectionConfiguration"`
		BandSteeringConfiguration struct {
			Enabled bool `json:"_enabled"`
		} `json:"_bandSteeringConfiguration"`
		BlockedStationsConfiguration struct {
			Stations []interface{} `json:"_stations"`
		} `json:"_blockedStationsConfiguration"`
		BridgeMode struct {
			Enabled bool `json:"_enabled"`
		} `json:"_bridgeMode"`
		BridgeModeConfiguration struct {
			Enabled bool `json:"_enabled"`
		} `json:"_bridgeModeConfiguration"`
		ContentFilteringPolicyConfiguration struct {
			Policies []interface{} `json:"_policies"`
			Version  string        `json:"_version"`
		} `json:"_contentFilteringPolicyConfiguration"`
		DefaultPrioritizedDeviceConfiguration struct {
			DurationInSeconds int    `json:"_durationInSeconds"`
			ID                string `json:"_id"`
		} `json:"_defaultPrioritizedDeviceConfiguration"`
		DhcpConfiguration struct {
		} `json:"_dhcpConfiguration"`
		DhcpReservationConfiguration []struct {
			ID         string `json:"_id"`
			IPAddress  string `json:"_ipAddress"`
			MacAddress string `json:"_macAddress"`
		} `json:"_dhcpReservationConfiguration"`
		DNSConfiguration struct {
			Mode        string        `json:"_mode"`
			Servers     []interface{} `json:"_servers"`
			ServersIpv6 []interface{} `json:"_serversIpv6"`
		} `json:"_dnsConfiguration"`
		ExposedPortConfiguration []interface{} `json:"_exposedPortConfiguration"`
		FeaturesConfiguration    struct {
			EnabledFeatures []string `json:"_enabledFeatures"`
		} `json:"_featuresConfiguration"`
		FutureBlockedStationsConfiguration struct {
			Stations []interface{} `json:"_stations"`
		} `json:"_futureBlockedStationsConfiguration"`
		GroupConfiguration struct {
			Children []interface{} `json:"_children"`
			GroupID  string        `json:"_groupId"`
		} `json:"_groupConfiguration"`
		GroupSetupNetworkConfiguration struct {
			ExpireTimeInSecondsSinceEpoch int    `json:"_expireTimeInSecondsSinceEpoch"`
			Psk                           string `json:"_psk"`
			Ssid                          string `json:"_ssid"`
		} `json:"_groupSetupNetworkConfiguration"`
		GuestNetworkConfiguration struct {
			Enabled        bool `json:"_enabled"`
			SharedStations []struct {
				ID                   string `json:"_id"`
				WelcomeMatProperties string `json:"_welcomeMatProperties"`
			} `json:"_sharedStations"`
			Ssid       string `json:"_ssid"`
			WelcomeMat struct {
				Enabled          bool   `json:"_enabled"`
				IntroductionText string `json:"_introductionText"`
				PhotoURL         string `json:"_photoUrl"`
				Title            string `json:"_title"`
			} `json:"_welcomeMat"`
		} `json:"_guestNetworkConfiguration"`
		Ipv6Configuration struct {
			Enabled      bool   `json:"_enabled"`
			Mode         string `json:"_mode"`
			Prefix       string `json:"_prefix"`
			PrefixLength int    `json:"_prefixLength"`
			Source       string `json:"_source"`
		} `json:"_ipv6Configuration"`
		IspConfiguration struct {
			IspType string `json:"_ispType"`
		} `json:"_ispConfiguration"`
		LightingConfiguration struct {
			AutomaticIntensityEnabled bool `json:"_automaticIntensityEnabled"`
			Intensity                 int  `json:"_intensity"`
		} `json:"_lightingConfiguration"`
		MeshNetworkConfiguration struct {
			Enabled  bool   `json:"_enabled"`
			RootNode bool   `json:"_rootNode"`
			Ssid     string `json:"_ssid"`
		} `json:"_meshNetworkConfiguration"`
		MonlogConfiguration struct {
		} `json:"_monlogConfiguration"`
		PortForwardingConfiguration    []interface{} `json:"_portForwardingConfiguration"`
		PrimaryPskNetworkConfiguration struct {
			Enabled bool   `json:"_enabled"`
			Ssid    string `json:"_ssid"`
		} `json:"_primaryPskNetworkConfiguration"`
		PrioritizedDeviceConfiguration struct {
			ExpireTimeInSecondsSinceEpoch int    `json:"_expireTimeInSecondsSinceEpoch"`
			ID                            string `json:"_id"`
			MacAddress                    string `json:"_macAddress"`
		} `json:"_prioritizedDeviceConfiguration"`
		PskNetworkConfiguration struct {
			PrimaryPskEnabled   bool   `json:"_primaryPskEnabled"`
			SecondaryPskEnabled bool   `json:"_secondaryPskEnabled"`
			Ssid                string `json:"_ssid"`
		} `json:"_pskNetworkConfiguration"`
		RadioConfiguration []struct {
			Channel                 int    `json:"_channel"`
			HtCapab                 string `json:"_htCapab"`
			VhtOperCentrFreqSeg0Idx int    `json:"_vhtOperCentrFreqSeg0Idx"`
			VhtOperCentrFreqSeg1Idx int    `json:"_vhtOperCentrFreqSeg1Idx"`
			VhtOperChwidth          string `json:"_vhtOperChwidth"`
		} `json:"_radioConfiguration"`
		RadiosConfiguration struct {
			Ieee80211Channel []struct {
				Channel                 int    `json:"_channel"`
				HtCapab                 string `json:"_htCapab"`
				VhtOperCentrFreqSeg0Idx int    `json:"_vhtOperCentrFreqSeg0Idx"`
				VhtOperCentrFreqSeg1Idx int    `json:"_vhtOperCentrFreqSeg1Idx"`
				VhtOperChwidth          string `json:"_vhtOperChwidth"`
			} `json:"_ieee80211Channel"`
			RegulatoryRules struct {
				BandPermissions []struct {
					BandwidthMhz int      `json:"_bandwidthMhz"`
					LowerFreqMhz int      `json:"_lowerFreqMhz"`
					MaxEirpMbm   int      `json:"_maxEirpMbm"`
					RegRuleFlags []string `json:"_regRuleFlags"`
					UpperFreqMhz int      `json:"_upperFreqMhz"`
				} `json:"_bandPermissions"`
				DfsRegion              string `json:"_dfsRegion"`
				RegulationRulesCountry string `json:"_regulationRulesCountry"`
			} `json:"_regulatoryRules"`
		} `json:"_radiosConfiguration"`
		RouterConfiguration struct {
			IPAddress string `json:"_ipAddress"`
			Netmask   string `json:"_netmask"`
			PoolBegin string `json:"_poolBegin"`
			PoolEnd   string `json:"_poolEnd"`
		} `json:"_routerConfiguration"`
		RrmConfiguration struct {
			Enabled bool `json:"_enabled"`
		} `json:"_rrmConfiguration"`
		RuntimeFlags       []interface{} `json:"_runtimeFlags"`
		SetupConfiguration struct {
		} `json:"_setupConfiguration"`
		StationPolicyConfiguration struct {
			Stations []interface{} `json:"_stations"`
		} `json:"_stationPolicyConfiguration"`
		UpnpConfiguration struct {
			Enabled bool `json:"_enabled"`
		} `json:"_upnpConfiguration"`
		WanConfiguration struct {
			ConnectionType     string `json:"_connectionType"`
			PppoeConfiguration struct {
				Username string `json:"_username"`
			} `json:"_pppoeConfiguration"`
			StaticConfiguration struct {
				Gateway   string `json:"_gateway"`
				IPAddress string `json:"_ipAddress"`
				Netmask   string `json:"_netmask"`
			} `json:"_staticConfiguration"`
		} `json:"_wanConfiguration"`
	} `json:"_apConfiguration"`
	ApCredentials struct {
		MonlogCredentials struct {
			Nonce       int  `json:"_nonce"`
			Provisioned bool `json:"_provisioned"`
		} `json:"_monlogCredentials"`
	} `json:"_apCredentials"`
	ApGroup struct {
		CurrentMeshKey struct {
			BundleKek                   string `json:"_bundleKek"`
			BundleMac                   string `json:"_bundleMac"`
			ExpiryTimeSecondsSinceEpoch int    `json:"_expiryTimeSecondsSinceEpoch"`
		} `json:"_currentMeshKey"`
	} `json:"_apGroup"`
	ApInsights struct {
		NewFeatures struct {
		} `json:"_newFeatures"`
		UploadDiagnosticReportResult []interface{} `json:"_uploadDiagnosticReportResult"`
	} `json:"_apInsights"`
	ApState struct {
		AutoUpdate struct {
			Channel    string `json:"_channel"`
			NewVersion string `json:"_newVersion"`
			Status     string `json:"_status"`
		} `json:"_autoUpdate"`
		BlockedStations struct {
			Stations []interface{} `json:"_stations"`
		} `json:"_blockedStations"`
		CertHash string `json:"_certHash"`
		Child    struct {
			Lost bool `json:"_lost"`
		} `json:"_child"`
		Country struct {
			Code string `json:"_code"`
		} `json:"_country"`
		DeveloperMode struct {
			Enabled bool `json:"_enabled"`
		} `json:"_developerMode"`
		DeviceInformation struct {
			SerialNumber string `json:"_serialNumber"`
		} `json:"_deviceInformation"`
		DNS struct {
			Servers     []string `json:"_servers"`
			ServersIpv6 []string `json:"_serversIpv6"`
		} `json:"_dns"`
		Ipv6 struct {
			Enabled                     bool   `json:"_enabled"`
			NonTemporaryAddressReceived bool   `json:"_nonTemporaryAddressReceived"`
			PrefixDelegationReceived    bool   `json:"_prefixDelegationReceived"`
			Status                      string `json:"_status"`
		} `json:"_ipv6"`
		Lan struct {
			Bridged bool     `json:"_bridged"`
			ID      string   `json:"_id"`
			Ids     []string `json:"_ids"`
		} `json:"_lan"`
		Setup struct {
			Complete       bool   `json:"_complete"`
			EncodedSsidPsk string `json:"_encodedSsidPsk"`
		} `json:"_setup"`
		Stations []struct {
			CategorizationSignals []struct {
				Name  string `json:"_name"`
				Value string `json:"_value"`
			} `json:"_categorizationSignals"`
			Connected                 bool          `json:"_connected"`
			DhcpHostname              string        `json:"_dhcpHostname"`
			Guest                     bool          `json:"_guest"`
			ID                        string        `json:"_id"`
			IPAddresses               []string      `json:"_ipAddresses"`
			LastSeenSecondsSinceEpoch int           `json:"_lastSeenSecondsSinceEpoch"`
			MdnsNames                 []string      `json:"_mdnsNames"`
			OtherIPAddresses          []interface{} `json:"_otherIpAddresses"`
			Oui                       string        `json:"_oui"`
			TaxonomyIds               []string      `json:"_taxonomyIds"`
			UpnpAttributes            []struct {
				Name  string `json:"_name"`
				Value string `json:"_value"`
			} `json:"_upnpAttributes"`
			Wireless     bool   `json:"_wireless"`
			WirelessBand string `json:"_wirelessBand"`
		} `json:"_stations"`
		VorlonTransitionMode struct {
			Mode string `json:"_mode"`
		} `json:"_vorlonTransitionMode"`
		Wan struct {
			GatewayAddress string `json:"_gatewayAddress"`
			IPAddress      string `json:"_ipAddress"`
			LinkSpeedMbps  int    `json:"_linkSpeedMbps"`
		} `json:"_wan"`
	} `json:"_apState"`
	CloudActionConfiguration struct {
		Credential struct {
			Provisioned bool `json:"_provisioned"`
		} `json:"_credential"`
	} `json:"_cloudActionConfiguration"`
	LocalActionConfiguration struct {
		HueBridgeConfiguration struct {
			HueBridges []interface{} `json:"_hueBridges"`
		} `json:"_hueBridgeConfiguration"`
	} `json:"_localActionConfiguration"`
	Base struct {
		FirmwareVersion             string `json:"firmwareVersion"`
		LocalAnonymousAccessMaxRole string `json:"localAnonymousAccessMaxRole"`
		LocalDiscoveryEnabled       bool   `json:"localDiscoveryEnabled"`
		LocalPairingEnabled         bool   `json:"localPairingEnabled"`
	} `json:"base"`
}

func truncateString(str string, num int) string {
	bnoden := str
	if len(str) > num {
		if num > 3 {
			num -= 3
		}
		bnoden = str[0:num] + "..."
	}
	return bnoden
}
