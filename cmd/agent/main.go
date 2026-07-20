package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/blang/semver"
	"github.com/nezhahq/go-github-selfupdate/selfupdate"
	"github.com/nezhahq/service"
	ping "github.com/prometheus-community/pro-bing"
	utls "github.com/refraction-networking/utls"
	"github.com/shirou/gopsutil/v4/host"
	"github.com/urfave/cli/v2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/resolver"

	"github.com/nezhahq/agent/cmd/agent/commands"
	"github.com/nezhahq/agent/model"
	"github.com/nezhahq/agent/pkg/fsnotifyx"
	"github.com/nezhahq/agent/pkg/logger"
	"github.com/nezhahq/agent/pkg/monitor"
	"github.com/nezhahq/agent/pkg/processgroup"
	"github.com/nezhahq/agent/pkg/util"
	utlsx "github.com/nezhahq/agent/pkg/utls"
	pb "github.com/nezhahq/agent/proto"
)

var (
	version               = monitor.Version // 来自于 GoReleaser 的版本号
	arch                  string
	executablePath        string
	defaultConfigPath     = loadDefaultConfigPath()
	client                pb.NezhaServiceClient
	initialized           bool
	agentConfig           model.AgentConfig
	prevDashboardBootTime uint64 // 面板上次启动时间
	geoipReported         bool   // 在面板重启后是否上报成功过 GeoIP
	lastReportHostInfo    time.Time
	lastReportIPInfo      time.Time

	hostStatus atomic.Bool
	ipStatus   atomic.Bool

	// reloadMu guards reloadTimer. A non-nil reloadTimer means a delayed swap
	// to a new agentConfig is queued. A second ApplyConfig task may arrive
	// before the timer fires (e.g. the dashboard pushing a counter-task after
	// the operator cancels a server transfer); we Stop() the previous timer
	// and replace it so the most recent config wins instead of the agent
	// committing a swap the dashboard already rolled back.
	reloadMu         sync.Mutex
	reloadTimer      *time.Timer
	reloadIsTransfer bool

	dnsResolver = &net.Resolver{PreferGo: true}
	httpClient  = &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Timeout: time.Second * 30,
	}

	reloadSigChan = make(chan struct{}, 1)
)

var (
	println = logger.Println
	printf  = logger.Printf
)

const (
	delayWhenError = time.Second * 10 // Agent 重连间隔

	minUpdateInterval = 1440
	maxUpdateInterval = 2880

	binaryName = "nezha-agent"
)

func setEnv() {
	resolver.SetDefaultScheme("passthrough")
	net.DefaultResolver.PreferGo = true // 使用 Go 内置的 DNS 解析器解析域名
	net.DefaultResolver.Dial = func(ctx context.Context, network, address string) (net.Conn, error) {
		config := loadRuntimeConfig()
		dnsConfig := dnsConfigTupleFrom(config)
		d := net.Dialer{
			Timeout: time.Second * 5,
		}
		var conn net.Conn
		var err error
		for _, server := range util.RangeRnd(dnsConfig.servers) {
			conn, err = d.DialContext(ctx, "udp", server)
			if err == nil {
				return conn, nil
			}
		}
		return nil, err
	}
	headers := util.BrowserHeaders()
	http.DefaultClient.Timeout = time.Second * 30
	httpClient.Transport = utlsx.NewUTLSHTTPRoundTripperWithProxy(
		utls.HelloChrome_Auto, new(utls.Config),
		http.DefaultTransport, nil, headers,
	)
}

func loadDefaultConfigPath() string {
	var err error
	executablePath, err = os.Executable()
	if err != nil {
		return ""
	}
	return filepath.Join(filepath.Dir(executablePath), "config.yml")
}

func preRun(configPath string) error {
	// init
	setEnv()

	if configPath == "" {
		configPath = defaultConfigPath
	}

	// windows环境处理
	if runtime.GOOS == "windows" {
		hostArch, err := host.KernelArch()
		if err != nil {
			return err
		}
		switch hostArch {
		case "i386", "i686":
			hostArch = "386"
		case "x86_64":
			hostArch = "amd64"
		case "aarch64":
			hostArch = "arm64"
		}
		if arch != hostArch {
			return fmt.Errorf("与当前系统不匹配，当前运行 %s_%s, 需要下载 %s_%s", runtime.GOOS, arch, runtime.GOOS, hostArch)
		}
	}

	if err := agentConfig.Read(configPath); err != nil {
		return fmt.Errorf("init config failed: %v", err)
	}
	publishRuntimeConfig(agentConfig)

	return nil
}

func main() {
	app := &cli.App{
		Usage:   "哪吒监控 Agent",
		Version: version,
		Flags: []cli.Flag{
			&cli.StringFlag{Name: "config", Aliases: []string{"c"}, Usage: "配置文件路径"},
		},
		Action: func(c *cli.Context) error {
			if path := c.String("config"); path != "" {
				if err := preRun(path); err != nil {
					return err
				}
			} else {
				if err := preRun(""); err != nil {
					return err
				}
			}
			runService("", "")
			return nil
		},
		Commands: []*cli.Command{
			{
				Name:  "edit",
				Usage: "编辑配置文件",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "config", Aliases: []string{"c"}, Usage: "配置文件路径"},
				},
				Action: func(c *cli.Context) error {
					if path := c.String("config"); path != "" {
						commands.EditAgentConfig(path, &agentConfig)
					} else {
						commands.EditAgentConfig(defaultConfigPath, &agentConfig)
					}
					return nil
				},
			},
			{
				Name:      "service",
				Usage:     "服务操作",
				UsageText: "<install/uninstall/start/stop/restart>",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "config", Aliases: []string{"c"}, Usage: "配置文件路径"},
				},
				Action: func(c *cli.Context) error {
					if arg := c.Args().Get(0); arg != "" {
						if path := c.String("config"); path != "" {
							ap, _ := filepath.Abs(path)
							runService(arg, ap)
						} else {
							ap, _ := filepath.Abs(defaultConfigPath)
							runService(arg, ap)
						}
						return nil
					}
					return cli.Exit("必须指定一个参数", 1)
				},
			},
		},
	}

	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}

func run() {
	startupConfig := startupConfigViewFrom(loadRuntimeConfig())
	// 定时检查更新
	if _, err := semver.Parse(version); err == nil && !startupConfig.disableAutoUpdate {
		if doSelfUpdate(updateConfigTupleFrom(loadRuntimeConfig()), true) {
			os.Exit(1)
		}
		go func() {
			var interval time.Duration
			if startupConfig.selfUpdatePeriod > 0 {
				interval = time.Duration(startupConfig.selfUpdatePeriod) * time.Minute
			} else {
				interval = time.Duration(rand.Intn(maxUpdateInterval-minUpdateInterval)+minUpdateInterval) * time.Minute
			}
			for range time.Tick(interval) {
				if doSelfUpdate(updateConfigTupleFrom(loadRuntimeConfig()), true) {
					os.Exit(1)
				}
			}
		}()
	}

	var err error
	var dashboardBootTimeReceipt *pb.Uint64Receipt
	var conn *grpc.ClientConn

	retry := func() {
		initialized = false
		if conn != nil {
			conn.Close()
		}
		time.Sleep(delayWhenError)
		println("Try to reconnect ...")
	}

	for {
		connectionConfig := loadConnectionConfigTuple()
		conn, err = grpc.NewClient(connectionConfig.Server, connectionConfig.dialOptions()...)
		if err != nil {
			printf("与面板建立连接失败: %v", err)
			retry()
			continue
		}
		client = pb.NewNezhaServiceClient(conn)
		printf("Connection to %s established", connectionConfig.Server)
		session := newConnectionSession(context.Background())
		reconnectSession := func(cause error) {
			graceContext, cancelGrace := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancelGrace()
			reconnectAfterSessionExit(session, sessionShutdown{graceContext: graceContext, cause: cause}, retry)
		}

		timeOutCtx, cancel := context.WithTimeout(session.streamContext, 10*time.Second)
		config := loadRuntimeConfig()
		dashboardBootTimeReceipt, err = client.ReportSystemInfo2(timeOutCtx, monitor.GetHost(config).PB())
		if err != nil {
			printf("上报系统信息失败: %v", err)
			cancel()
			reconnectSession(err)
			continue
		}
		cancel()

		geoipReported = geoipReported && prevDashboardBootTime > 0 && dashboardBootTimeReceipt.GetData() == prevDashboardBootTime
		prevDashboardBootTime = dashboardBootTimeReceipt.GetData()
		initialized = true

		// 执行 Task
		tasks, err := client.RequestTask(session.requestTaskContext)
		if err != nil {
			printf("请求任务失败: %v", err)
			reconnectSession(err)
			continue
		}
		requestSession := session.bindRequestTask(tasks)
		session.startDaemon(func() { receiveTasksDaemon(requestSession, session) })

		reportSession, err := openReportState(session, client)
		if err != nil {
			printf("上报状态信息失败: %v", err)
			reconnectSession(err)
			continue
		}
		session.startDaemon(func() { reportStateDaemon(reportSession, session.signalExit) })

		shutdownCause := error(context.Canceled)
		select {
		case <-reloadSigChan:
			println("Reloading...")
		case <-session.streamContext.Done():
			println("Worker exit...")
			shutdownCause = context.Cause(session.streamContext)
		case <-session.exitContext.Done():
			println("Worker exit...")
			shutdownCause = context.Cause(session.exitContext)
		}

		reconnectSession(shutdownCause)
	}
}

func openReportState(
	session *connectionSession,
	reportClient pb.NezhaServiceClient,
) (*reportStateSession, error) {
	reportSession := session.newReportStateSession()
	stream, err := reportClient.ReportSystemState(reportSession.streamContext)
	if err != nil {
		reportSession.cancelStream(err)
		return nil, err
	}
	session.bindReportState(reportSession, stream)
	return reportSession, nil
}

func runService(action string, path string) {
	startupConfig := startupConfigViewFrom(loadRuntimeConfig())
	winConfig := map[string]interface{}{
		"OnFailure": "restart",
	}

	args := []string{"-c", path}
	name := filepath.Base(executablePath)
	if path != defaultConfigPath && path != "" {
		hex := util.MD5Sum(path)[:7]
		name = fmt.Sprintf("%s-%s", name, hex)
	}

	svcConfig := &service.Config{
		Name:             name,
		DisplayName:      filepath.Base(executablePath),
		Arguments:        args,
		Description:      "哪吒监控 Agent",
		WorkingDirectory: filepath.Dir(executablePath),
		Option:           winConfig,
	}

	prg := &commands.Program{
		Exit: make(chan struct{}),
		Run:  run,
	}
	s, err := service.New(prg, svcConfig)
	if err != nil {
		printf("创建服务时出错，以普通模式运行: %v", err)
		run()
		return
	}
	prg.Service = s

	serviceLogger, err := logger.NewNezhaServiceLogger(s, nil)
	if err != nil {
		printf("获取 service logger 时出错: %+v", err)
		logger.InitDefaultLogger(startupConfig.debug, service.ConsoleLogger)
	} else {
		logger.InitDefaultLogger(startupConfig.debug, serviceLogger)
	}

	if action == "install" {
		initName := s.Platform()
		if err := agentConfig.Read(path); err != nil {
			log.Fatalf("init config failed: %v", err)
		}
		printf("Init system is: %s", initName)
	}

	if len(action) != 0 {
		err := service.Control(s, action)
		if err != nil {
			log.Fatal(err)
		}
		return
	}

	err = s.Run()
	if err != nil {
		logger.Error(err)
	}
}

// reportStateDaemon 向server上报状态信息
func reportStateDaemon(stateClient *reportStateSession, requestExit func(error)) {
	var err error
	defer func() { stateClient.finishTerminal(err) }()
	for {
		config := loadRuntimeConfig()
		reportConfig := reportConfigTupleFrom(config)
		schedule, reportErr := reportState(stateClient, reportSchedule{host: lastReportHostInfo, ip: lastReportIPInfo}, reportConfig)
		lastReportHostInfo, lastReportIPInfo, err = schedule.host, schedule.ip, reportErr
		if err != nil {
			printf("reportStateDaemon exit: %v", err)
			requestExit(err)
			return
		}
		timer := time.NewTimer(time.Second * time.Duration(reportConfig.reportDelay))
		select {
		case <-timer.C:
		case <-stateClient.cadenceContext.Done():
			timer.Stop()
			for {
				_, err = stateClient.Recv()
				if err != nil {
					return
				}
			}
		}
	}
}

type reportStateClient interface {
	Context() context.Context
	Send(*pb.State) error
	Recv() (*pb.Receipt, error)
}

func reportState(statClient reportStateClient, schedule reportSchedule, config reportConfigTuple) (reportSchedule, error) {
	if statClient.Context().Err() != nil {
		return schedule, statClient.Context().Err()
	}
	if initialized {
		reportMonitorDependencies.trackNetworkSpeed(config.snapshot)
		if err := statClient.Send(reportMonitorDependencies.getState(config.snapshot, config.skipConnectionCount, config.skipProcsCount).PB()); err != nil {
			return schedule, err
		}
		_, err := statClient.Recv()
		if err != nil {
			return schedule, err
		}
	}
	// 每10分钟重新获取一次硬件信息
	if schedule.host.Before(time.Now().Add(-10 * time.Minute)) {
		if reportHost(statClient.Context(), config.snapshot) {
			schedule.host = time.Now()
		}
	}
	// 更新IP信息
	if time.Since(schedule.ip) > time.Second*time.Duration(config.ipReportPeriod) || !geoipReported {
		if reportGeoIP(statClient.Context(), config.snapshot, geoIPReportOptions{
			useIPv6CountryCode: config.useIPv6CountryCode,
			forceUpdate:        !geoipReported,
		}) {
			schedule.ip = time.Now()
			geoipReported = true
		}
	}
	return schedule, nil
}

func reportHost(parent context.Context, config *model.AgentConfig) bool {
	if !hostStatus.CompareAndSwap(false, true) {
		return false
	}
	defer hostStatus.Store(false)
	if client != nil && initialized {
		rpcContext, cancel := context.WithTimeout(parent, 10*time.Second)
		defer cancel()
		// The parent must reach the actual RPC; timing out only the caller orphans
		// the underlying gRPC operation after the connection session is canceled.
		receipt, err := client.ReportSystemInfo2(rpcContext, reportMonitorDependencies.getHost(config).PB())
		if err != nil {
			printf("ReportSystemInfo2 error: %v", err)
			return false
		}
		geoipReported = geoipReported && prevDashboardBootTime > 0 && receipt.GetData() == prevDashboardBootTime
	}
	return true
}

type geoIPReportOptions struct {
	useIPv6CountryCode bool
	forceUpdate        bool
}

func reportGeoIP(parent context.Context, config *model.AgentConfig, options geoIPReportOptions) bool {
	if !ipStatus.CompareAndSwap(false, true) {
		return false
	}
	defer ipStatus.Store(false)

	if client == nil || !initialized {
		return false
	}

	pbg := reportMonitorDependencies.fetchIP(config, options.useIPv6CountryCode)
	if pbg == nil {
		return false
	}

	if !reportMonitorDependencies.geoIPChanged() && !options.forceUpdate {
		return true
	}

	rpcContext, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	// The parent must reach the actual RPC so session cancellation stops the
	// network call instead of abandoning work behind a caller-only timeout.
	geoip, err := client.ReportGeoIP(rpcContext, pbg)
	if err != nil {
		return false
	}

	prevDashboardBootTime = geoip.GetDashboardBootTime()

	reportMonitorDependencies.markGeoIPReported(geoip.GetCountryCode())

	return true
}

// doSelfUpdate 执行更新检查 如果更新成功则会结束进程
func doSelfUpdate(config updateConfigTuple, useLocalVersion bool) (exit bool) {
	v := semver.MustParse("0.1.0")
	if useLocalVersion {
		vr, err := semver.Parse(version)
		if err != nil {
			printf("failed to parse current version string: %v", err)
			return
		}
		cmd := exec.Command(executablePath, "-v")
		vb, err := cmd.Output()
		if err != nil {
			printf("failed to retrieve current executable version: %v", err)
			return
		}
		vraw := strings.Split(strings.TrimSpace(string(vb)), " ")
		vstr := vraw[len(vraw)-1]
		v, err = semver.Parse(vstr)
		if err != nil {
			printf("failed to parse executable version string: %v", err)
			return
		}
		if !vr.Equals(v) {
			printf("executable version differs from current version, exiting to re-check update...")
			exit = true
			return
		}
	}

	execHash := util.MD5Sum(executablePath)[:7]
	statName := fmt.Sprintf("agent-%s.stat", execHash)
	tmpDir := filepath.Join(os.TempDir(), binaryName)
	if err := os.MkdirAll(tmpDir, 0755); err != nil {
		printf("failed to create temp dir: %v", err)
		return
	}

	statFile := filepath.Join(tmpDir, statName)
	if _, err := os.Stat(statFile); err == nil {
		printf("found self-update stat file, waiting for another process to finish update...")
		if fErr := fsnotifyx.ExitOnDeleteFile(context.Background(), printf, statFile); fErr != nil {
			if errors.Is(fErr, fsnotifyx.ErrTimeout) {
				os.Remove(statFile) // try to remove stat file
			}
			printf("failed to monitor path of stat file: %v", fErr)
			return
		}
		exit = true
		return
	} else {
		if !errors.Is(err, os.ErrNotExist) {
			printf("failed to retrieve self-update stat at %s", statFile)
			return
		}
	}

	stat, err := os.OpenFile(statFile, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		printf("failed to create self-update stat file: %v", err)
		return
	}

	defer func() {
		stat.Close()
		if err := os.Remove(statFile); err != nil {
			printf("remove stat failed: %v", err)
		}
	}()

	printf("检查更新: %v", v)
	var latest *selfupdate.Release
	switch {
	case config.useGiteeToUpgrade:
		updater, erru := selfupdate.NewGiteeUpdater(selfupdate.Config{
			BinaryName: binaryName,
		})
		if erru != nil {
			printf("更新失败: %v", erru)
			return
		}
		latest, err = updater.UpdateSelf(v, "naibahq/agent")
	case config.useAtomGitToUpgrade:
		updater, erru := selfupdate.NewAtomGitUpdater(selfupdate.Config{
			BinaryName: binaryName,
		})
		if erru != nil {
			printf("更新失败: %v", erru)
			return
		}
		latest, err = updater.UpdateSelf(v, "naiba/nezha-agent")
	case monitor.CachedCountryCode() == "cn":
		if rand.Intn(2) == 0 {
			updater, erru := selfupdate.NewGiteeUpdater(selfupdate.Config{
				BinaryName: binaryName,
			})
			if erru != nil {
				printf("更新失败: %v", erru)
				return
			}
			latest, err = updater.UpdateSelf(v, "naibahq/agent")
		} else {
			updater, erru := selfupdate.NewAtomGitUpdater(selfupdate.Config{
				BinaryName: binaryName,
			})
			if erru != nil {
				printf("更新失败: %v", erru)
				return
			}
			latest, err = updater.UpdateSelf(v, "naiba/nezha-agent")
		}
	default:
		updater, erru := selfupdate.NewUpdater(selfupdate.Config{
			BinaryName: binaryName,
		})
		if erru != nil {
			printf("更新失败: %v", erru)
			return
		}
		latest, err = updater.UpdateSelf(v, "nezhahq/agent")
	}

	if err != nil {
		printf("更新失败: %v", err)
		return
	}

	if !latest.Version.Equals(v) {
		printf("已经更新至: %v, 正在结束进程", latest.Version)
		exit = true
	}
	return
}

func handleUpgradeTaskWithConfig(config updateConfigTuple, gates taskFeatureGates) {
	if gates.disableForceUpdate {
		return
	}
	if doSelfUpdate(config, false) {
		os.Exit(1)
	}
}

func handleTcpPingTaskWithConfig(gates taskFeatureGates, task *pb.Task, result *pb.TaskResult) {
	if gates.disableSendQuery {
		result.Data = "This server has disabled query sending"
		return
	}

	host, port, err := net.SplitHostPort(task.GetData())
	if err != nil {
		result.Data = err.Error()
		return
	}
	ipAddr, err := lookupIP(host)
	if err != nil {
		result.Data = err.Error()
		return
	}
	addr := net.JoinHostPort(ipAddr, port)
	printf("TCP-Ping Task: Pinging %s", addr)
	start := time.Now()
	conn, err := net.DialTimeout("tcp", addr, time.Second*10)
	if err != nil {
		result.Data = err.Error()
	} else {
		conn.Close()
		result.Delay = float32(time.Since(start).Microseconds()) / 1000.0
		result.Successful = true
	}
}

func handleIcmpPingTaskWithConfig(gates taskFeatureGates, task *pb.Task, result *pb.TaskResult) {
	if gates.disableSendQuery {
		result.Data = "This server has disabled query sending"
		return
	}

	ipAddr, err := lookupIP(task.GetData())
	printf("ICMP-Ping Task: Pinging %s(%s)", task.GetData(), ipAddr)
	if err != nil {
		result.Data = err.Error()
		return
	}
	pinger, err := ping.NewPinger(ipAddr)
	if err == nil {
		pinger.SetPrivileged(true)
		pinger.Count = 5
		pinger.Timeout = time.Second * 20
		err = pinger.Run() // Blocks until finished.
	}
	if err == nil {
		stat := pinger.Statistics()
		if stat.PacketsRecv == 0 {
			result.Data = "pockets recv 0"
			return
		}
		result.Delay = float32(stat.AvgRtt.Microseconds()) / 1000.0
		result.Successful = true
	} else {
		result.Data = err.Error()
	}
}

func handleHttpGetTaskWithConfig(gates taskFeatureGates, task *pb.Task, result *pb.TaskResult) {
	if gates.disableSendQuery {
		result.Data = "This server has disabled query sending"
		return
	}
	start := time.Now()
	taskUrl := task.GetData()
	resp, err := httpClient.Get(taskUrl)
	printf("HTTP-GET Task: %s", taskUrl)
	if err == nil {
		defer resp.Body.Close()
		_, err = io.Copy(io.Discard, resp.Body)
	}
	if err == nil {
		// 检查 HTTP Response 状态
		result.Delay = float32(time.Since(start).Microseconds()) / 1000.0
		if resp.StatusCode > 399 || resp.StatusCode < 200 {
			err = errors.New("\n应用错误: " + resp.Status)
		}
	}
	if err == nil {
		// 检查 SSL 证书信息
		if resp.TLS != nil && len(resp.TLS.PeerCertificates) > 0 {
			c := resp.TLS.PeerCertificates[0]
			result.Data = c.Issuer.CommonName + "|" + c.NotAfter.String()
		}
		result.Successful = true
	} else {
		// HTTP 请求失败
		result.Data = err.Error()
	}
}

func handleCommandTaskWithConfig(gates taskFeatureGates, task *pb.Task, result *pb.TaskResult) {
	if gates.disableCommandExecute {
		result.Data = "此 Agent 已禁止命令执行"
		return
	}
	startedAt := time.Now()
	endCh := make(chan struct{})
	pg, err := processgroup.NewProcessExitGroup()
	if err != nil {
		// 进程组创建失败，直接退出
		result.Data = err.Error()
		return
	}
	timeout := time.NewTimer(time.Hour * 2)
	cmd := processgroup.NewCommand(task.GetData())
	var b bytes.Buffer
	cmd.Stdout = &b
	cmd.Env = os.Environ()
	if err = cmd.Start(); err != nil {
		// Start failed: no process to wait on and the timeout goroutine has
		// not been launched yet, so just release the timer before returning,
		// otherwise it lingers for 2h.
		timeout.Stop()
		result.Data = err.Error()
		return
	}
	pg.AddProcess(cmd)
	go func() {
		select {
		case <-timeout.C:
			result.Data = "任务执行超时\n"
			pg.Dispose()
		case <-endCh:
			timeout.Stop()
		}
	}()
	if err = cmd.Wait(); err != nil {
		result.Data += fmt.Sprintf("%s\n%s", b.String(), err.Error())
	} else {
		result.Data = b.String()
		result.Successful = true
	}
	// Always signal completion so the timeout goroutine exits and stops the
	// timer, regardless of whether the command succeeded or failed. The
	// previous code only closed endCh on success, stranding one goroutine and
	// one 2h timer for every non-zero-exit command.
	close(endCh)
	pg.Dispose()
	result.Delay = float32(time.Since(startedAt).Seconds())
}

func handleReportConfigTaskWithConfig(config *model.AgentConfig, result *pb.TaskResult) {
	reloadMu.Lock()
	if reloadTimer != nil {
		reloadMu.Unlock()
		result.Data = "another reload is in process"
		return
	}
	reloadMu.Unlock()

	if config.DisableCommandExecute {
		result.Data = "此 Agent 已禁止命令执行"
		return
	}

	println("Executing Report Config Task")

	c, err := json.Marshal(config)
	if err != nil {
		result.Data = err.Error()
		return
	}

	result.Data = string(c)
	result.Successful = true
}

// reloadPending reports whether a delayed config swap is currently queued.
// Used by handleReportConfigTask to avoid dumping a config that is about to
// change out from under the caller.
func reloadPending() bool {
	reloadMu.Lock()
	defer reloadMu.Unlock()
	return reloadTimer != nil
}

// handleApplyConfigTask applies a remote-pushed configuration. Used both as a
// targeted secret rotation step in the server-transfer flow and as a generic
// runtime reconfiguration mechanism. Failures surface to the dashboard via
// TaskResult, so a stuck transfer doesn't have to wait 24h for the timeout
// sweep. Pending TaskResult.Successful=true does NOT yet mean the swap
// succeeded; the dashboard's authoritative signal is the agent reconnecting
// under the new credential.
//
// Apply order inside the 10s-deferred applyPendingReload is save-first-
// then-swap, so a crash between disk write and in-memory swap leaves the
// agent's persistent state ahead of its runtime state, not behind it — a
// restart will load the new config and reconnect with the new secret. The
// previous order (in-memory swap then Save) could leave the agent talking
// under the new secret in-process but configured to reload the old secret
// if it crashed before disk flush. NOTE: Save itself is intentionally
// deferred by 10s so an operator who cancels the transfer mid-window can
// supersede before disk is touched — on cancel the dashboard pushes a
// counter-ApplyConfig carrying the previous secret, and the supersede path
// drops the original timer before its Save runs.
//
// Save target path: the AgentConfig struct here is cloned from the runtime
// snapshot loaded after reloadMu is acquired (preserving the unexported
// filePath captured at Read), then merges the JSON payload on top. Pass-by-
// value into applyPendingReload preserves it again. If
// any of these copies stops preserving filePath, Save silently fails with
// "open : no such file" — TestApplyPendingReloadWritesToConfigReadPath
// pins down the end-to-end invariant.
//
// Supersede behaviour: if an ApplyConfig arrives while a previous one is still
// in its 10s delay window, the new task wins and the old timer is dropped.
// This keeps the dashboard's revert flow honest — when an operator cancels a
// server transfer the dashboard pushes a counter-ApplyConfig carrying the
// original secret; without supersede the agent would commit the cancelled
// swap anyway and lock itself out.
// rotatedClientSecretLength mirrors what the dashboard's
// utils.GenerateRandomString emits for per-transfer HandshakeSecret /
// RevertHandshakeSecret. The dashboard config also generates user-global
// AgentSecret with the same length and alphabet.
const rotatedClientSecretLength = 32

// validateRotatedClientSecret rejects payloads that would lock the agent
// out at the next reconnect. The dashboard's secret generator emits
// exactly 32 base62 characters; anything outside that shape is treated as
// a corrupt or adversarial value. We are deliberately stricter than gRPC
// metadata's per-character rules so the agent stays recoverable.
func validateRotatedClientSecret(secret string) error {
	if len(secret) != rotatedClientSecretLength {
		return fmt.Errorf("rejected client_secret rotation: length=%d, want %d", len(secret), rotatedClientSecretLength)
	}
	for i := 0; i < len(secret); i++ {
		c := secret[i]
		switch {
		case c >= '0' && c <= '9':
		case c >= 'A' && c <= 'Z':
		case c >= 'a' && c <= 'z':
		default:
			return fmt.Errorf("rejected client_secret rotation: byte %d (0x%02x) outside [0-9A-Za-z]", i, c)
		}
	}
	return nil
}

// handleApplyConfigTask handles a generic admin-pushed config reload from
// dashboard's POST /api/v1/server/config. It refuses any payload that would
// rotate client_secret — that path is reserved for handleServerTransferApplyTask
// and travels over TaskTypeServerTransferApply with mandatory TLS gating.
// Refuses to supersede an in-flight transfer reload so a benign admin push
// cannot drop a transfer mid-flight (dashboard would wait the full 24h
// timeout sweep).
func handleApplyConfigTask(task *pb.Task, result *pb.TaskResult) {
	reloadMu.Lock()
	defer reloadMu.Unlock()

	config := loadRuntimeConfig()
	tmpConfig, ok := parseApplyConfigLocked(config, task, result)
	if !ok {
		return
	}
	if tmpConfig.ClientSecret != config.ClientSecret {
		result.Data = "ApplyConfig rejected: client_secret rotation must use TaskTypeServerTransferApply"
		return
	}
	if reloadTimer != nil && reloadIsTransfer {
		result.Data = "另一条 server transfer 配置正在生效中，请稍后再试 (transfer reload in progress)"
		return
	}
	scheduleConfigReload(tmpConfig, false)
	result.Successful = true
}

// handleServerTransferApplyTask handles dashboard's per-transfer credential
// rotation push. Unlike handleApplyConfigTask:
//   - client_secret rotation is the whole point; the validator enforces the
//     32-char [0-9A-Za-z] shape so an adversarial payload cannot lock the
//     agent out.
//   - the TLS gate checks tmpConfig (the connection the rotated secret will
//     travel over next), not agentConfig (the current connection). Allowing
//     a payload to simultaneously rotate the secret and disable TLS would
//     leak the new secret over plaintext on the very next reconnect.
//   - the transfer-interlock direction is reversed vs. the generic handler:
//     a later transfer push supersedes an earlier transfer push (10s last-
//     arrival wins, exactly what the dashboard's cancel/revert flow needs).
func handleServerTransferApplyTask(task *pb.Task, result *pb.TaskResult) {
	reloadMu.Lock()
	defer reloadMu.Unlock()

	config := loadRuntimeConfig()
	tmpConfig, ok := parseApplyConfigLocked(config, task, result)
	if !ok {
		return
	}
	if err := validateRotatedClientSecret(tmpConfig.ClientSecret); err != nil {
		printf("Rejecting ServerTransferApply: %v", err)
		result.Data = err.Error()
		return
	}
	if !tmpConfig.TLS || tmpConfig.InsecureTLS {
		result.Data = "ServerTransferApply rejected: rotated secret cannot be delivered over plaintext or InsecureTLS"
		return
	}
	scheduleConfigReload(tmpConfig, true)
	result.Successful = true
}

// parseApplyConfigLocked uses the snapshot loaded after acquiring reloadMu as
// the edit baseline. Loading before the lock would let a waiting ApplyConfig
// overwrite a newer committed generation with stale fields after the lock is
// released by applyPendingReload.
func parseApplyConfigLocked(config *model.AgentConfig, task *pb.Task, result *pb.TaskResult) (model.AgentConfig, bool) {
	if config.DisableCommandExecute {
		result.Data = "此 Agent 已禁止命令执行 (DisableCommandExecute)"
		return model.AgentConfig{}, false
	}
	tmpConfig := config.Clone()
	if err := json.Unmarshal([]byte(task.GetData()), &tmpConfig); err != nil {
		printf("Parsing Config failed: %v", err)
		result.Data = err.Error()
		return model.AgentConfig{}, false
	}
	if err := model.ValidateConfig(&tmpConfig, true); err != nil {
		printf("Validate Config failed: %v", err)
		result.Data = err.Error()
		return model.AgentConfig{}, false
	}
	return tmpConfig, true
}

// scheduleConfigReload installs the 10s-deferred swap that applyPendingReload
// will commit. Caller must hold reloadMu. The timer identity is captured in
// the closure so a fired-but-not-yet-run stale callback can detect that a
// newer ApplyConfig has already superseded it.
func scheduleConfigReload(cfg model.AgentConfig, isTransfer bool) {
	if reloadTimer != nil {
		reloadTimer.Stop()
		println("Superseding pending reload with newer config")
	}
	println("Will reload workers in 10 seconds")
	pendingConfig := cfg.Clone()
	var timer *time.Timer
	timer = time.AfterFunc(10*time.Second, func() {
		applyPendingReload(timer, pendingConfig)
	})
	reloadTimer = timer
	reloadIsTransfer = isTransfer
}

// applyPendingReload commits cfg to disk, the runtime snapshot and the locked
// persistence working copy, but only if thisTimer is still the active reload timer (no supersede
// happened between AfterFunc firing and the callback acquiring reloadMu).
// Identity-checking the timer instead of "is any timer scheduled" is the
// only thing preventing a fired-but-not-yet-run stale callback from
// clobbering a newer config the supersede path already installed.
func applyPendingReload(thisTimer *time.Timer, cfg model.AgentConfig) {
	reloadMu.Lock()
	defer reloadMu.Unlock()

	if reloadTimer != thisTimer {
		// Either we were superseded (reloadTimer points at a newer timer)
		// or already applied (reloadTimer == nil). Either way, skip — the
		// live timer's callback owns the commit.
		return
	}

	println("Applying new configuration...")
	// Save-first: persist the new config before mutating the in-process
	// global. See handleApplyConfigTask's comment for the crash-safety
	// reasoning. The save runs under reloadMu so concurrent
	// handleApplyConfigTask calls cannot observe a half-committed state
	// (timer cleared but agentConfig not yet swapped).
	if err := commitPendingRuntimeConfig(cfg, func() {
		reloadTimer = nil
		reloadIsTransfer = false
	}, notifyReloadWorker); err != nil {
		printf("Save new config failed: %v", err)
		// Leave reloadTimer in place so a retry from the dashboard can
		// supersede it; clearing it here would let the dashboard believe
		// the rotation succeeded.
		return
	}
}

func lookupIP(hostOrIp string) (string, error) {
	if net.ParseIP(hostOrIp) == nil {
		ips, err := dnsResolver.LookupIPAddr(context.Background(), hostOrIp)
		if err != nil {
			return "", err
		}
		if len(ips) == 0 {
			return "", fmt.Errorf("无法解析 %s", hostOrIp)
		}
		return ips[0].IP.String(), nil
	}
	return hostOrIp, nil
}

func ioStreamKeepAlive(ctx context.Context, stream pb.NezhaService_IOStreamClient) {
	ticker := time.Tick(30 * time.Second)

	for {
		select {
		case <-ctx.Done():
			printf("IOStream KeepAlive stopped: %v", ctx.Err())
			return
		case <-ticker:
			if err := stream.Send(&pb.IOStreamData{Data: []byte{}}); err != nil {
				printf("IOStream KeepAlive failed: %v", err)
				return
			}
		}
	}
}
