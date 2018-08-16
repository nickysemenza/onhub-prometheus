package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/benmanns/onhub/diagnosticreport"
	"github.com/getsentry/raven-go"
	"github.com/hako/durafmt"
	_ "github.com/joho/godotenv/autoload"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	contextKeyConfig  = contextKey("config")
	reportFetchTiming = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "onhub_report_fetch_timing",
		Help: "Number of ms it takes to fetch the report",
	})
	deviceCount = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "onhub_active_devices",
		Help: "Number of active devices on the network",
	})
	deviceState = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "onhub_device_state",
		Help: "Current device state",
	},
		[]string{"device_id", "hostname", "ip", "last_seen"})
)

//register prometheus metrics
func init() {
	prometheus.MustRegister(deviceCount)
	prometheus.MustRegister(deviceState)
	prometheus.MustRegister(reportFetchTiming)
}

func getReportURL() string {
	return fmt.Sprintf("http://%s/api/v1/diagnostic-report", os.Getenv("ONHUB_HOST"))
}

func main() {
	raven.SetDSN(os.Getenv("SENTRY_DSN"))
	raven.SetEnvironment(os.Getenv("SENTRY_ENVIRONMENT"))

	//build config
	config := &config{
		bindAddr:              ":9200",
		fetchFrequencySeconds: 600,
		reportURL:             getReportURL(),
	}
	ctx := context.WithValue(context.Background(), contextKeyConfig, config)

	//process in background
	go work(ctx)

	//expose metrics over HTTP
	log.Printf("starting server, addr=%s, frequency=%d seconds", config.bindAddr, config.fetchFrequencySeconds)
	http.Handle("/metrics", promhttp.Handler())
	log.Fatal(http.ListenAndServe(config.bindAddr, nil))
}

type contextKey string
type config struct {
	bindAddr              string
	fetchFrequencySeconds int
	reportURL             string
}

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

func getConfigFromContext(ctx context.Context) *config {
	return ctx.Value(contextKeyConfig).(*config)
}

func work(ctx context.Context) {
	for {
		fetchAndProcess(ctx)
		time.Sleep(time.Duration(getConfigFromContext(ctx).fetchFrequencySeconds) * time.Second)
	}
}

//build a list of devices
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

//calculate prometheus metrics
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

//fetch the latest report, and process it
func fetchAndProcess(ctx context.Context) {
	//fetch
	start := time.Now()
	data, err := fetchDiagnosticReport(ctx)
	if err != nil {
		raven.CaptureError(err, nil)
		log.Println("error fetching report", err)
		return
	} else {
		durationMs := time.Since(start) / time.Millisecond
		reportFetchTiming.Set(float64(durationMs))
		log.Println("fetched diagnostic report.")
	}

	//process
	report, err := diagnosticreport.Parse(data)
	if err != nil {
		raven.CaptureError(err, nil)
		log.Println("failed parsing", err)
		return
	}
	info := getDiagnosticReportInfo(report)

	devices := info.buildDeviceList()
	calculateMetrics(devices)
}

//extract and unmarshall the inner 'info' section
func getDiagnosticReportInfo(report *diagnosticreport.DiagnosticReport) infoSection {
	info := infoSection{}
	json.Unmarshal([]byte(report.InfoJSON), &info)
	return info
}

//fetches the report
func fetchDiagnosticReport(ctx context.Context) ([]byte, error) {
	resp, err := http.Get(getConfigFromContext(ctx).reportURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var out bytes.Buffer
	_, err = io.Copy(&out, resp.Body)
	if err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

//util func to trucate a string
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
