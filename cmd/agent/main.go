package main

import (
	"bytes"
	"context"
	"crypto/tls"
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
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/resolver"

	"github.com/nezhahq/agent/cmd/agent/commands"
	"github.com/nezhahq/agent/model"
	fm "github.com/nezhahq/agent/pkg/fm"
	"github.com/nezhahq/agent/pkg/fsnotifyx"
	"github.com/nezhahq/agent/pkg/logger"
	"github.com/nezhahq/agent/pkg/monitor"
	"github.com/nezhahq/agent/pkg/processgroup"
	"github.com/nezhahq/agent/pkg/pty"
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

	hostStatus   atomic.Bool
	ipStatus     atomic.Bool
	reloadStatus atomic.Bool

	dnsResolver = &net.Resolver{PreferGo: true}
	httpClient  = &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Timeout: time.Second * 30,
	}

	reloadSigChan = make(chan struct{})
)

var (
	println = logger.Println
	printf  = logger.Printf
)

const (
	delayWhenError = time.Second * 10 // Agent 重连间隔
	networkTimeOut = time.Second * 5  // 普通网络超时

	minUpdateInterval = 1440
	maxUpdateInterval = 2880

	binaryName = "nezha-agent"
)

func setEnv() {
	resolver.SetDefaultScheme("passthrough")
	net.DefaultResolver.PreferGo = true // 使用 Go 内置的 DNS 解析器解析域名
	net.DefaultResolver.Dial = func(ctx context.Context, network, address string) (net.Conn, error) {
		d := net.Dialer{
			Timeout: time.Second * 5,
		}
		dnsServers := util.DNSServersAll
		if len(agentConfig.DNS) > 0 {
			dnsServers = agentConfig.DNS
		}
		var conn net.Conn
		var err error
		for _, server := range util.RangeRnd(dnsServers) {
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

	monitor.InitConfig(&agentConfig)
	monitor.CustomEndpoints = agentConfig.CustomIPApi

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
	auth := model.AuthHandler{
		ClientSecret: agentConfig.ClientSecret,
		ClientUUID:   agentConfig.UUID,
	}

	// 定时检查更新
	if _, err := semver.Parse(version); err == nil && !agentConfig.DisableAutoUpdate {
		if doSelfUpdate(true) {
			os.Exit(1)
		}
		go func() {
			var interval time.Duration
			if agentConfig.SelfUpdatePeriod > 0 {
				interval = time.Duration(agentConfig.SelfUpdatePeriod) * time.Minute
			} else {
				interval = time.Duration(rand.Intn(maxUpdateInterval-minUpdateInterval)+minUpdateInterval) * time.Minute
			}
			for range time.Tick(interval) {
				if doSelfUpdate(true) {
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
		var securityOption grpc.DialOption
		if agentConfig.TLS {
			if agentConfig.InsecureTLS {
				securityOption = grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: true}))
			} else {
				securityOption = grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{MinVersion: tls.VersionTLS12}))
			}
		} else {
			securityOption = grpc.WithTransportCredentials(insecure.NewCredentials())
		}
		conn, err = grpc.NewClient(agentConfig.Server, securityOption, grpc.WithPerRPCCredentials(&auth))
		if err != nil {
			printf("与面板建立连接失败: %v", err)
			retry()
			continue
		}
		client = pb.NewNezhaServiceClient(conn)
		printf("Connection to %s established", agentConfig.Server)

		timeOutCtx, cancel := context.WithTimeout(context.Background(), networkTimeOut)
		dashboardBootTimeReceipt, err = client.ReportSystemInfo2(timeOutCtx, monitor.GetHost().PB())
		if err != nil {
			printf("上报系统信息失败: %v", err)
			cancel()
			retry()
			continue
		}
		cancel()

		geoipReported = geoipReported && prevDashboardBootTime > 0 && dashboardBootTimeReceipt.GetData() == prevDashboardBootTime
		prevDashboardBootTime = dashboardBootTimeReceipt.GetData()
		initialized = true

		wCtx, wCancel := context.WithCancel(context.Background())

		// 执行 Task
		tasks, err := doWithTimeout(func() (pb.NezhaService_RequestTaskClient, error) {
			return client.RequestTask(wCtx)
		}, networkTimeOut)
		if err != nil {
			printf("请求任务失败: %v", err)
			wCancel()
			retry()
			continue
		}
		go receiveTasksDaemon(tasks, wCancel)

		reportState, err := doWithTimeout(func() (pb.NezhaService_ReportSystemStateClient, error) {
			return client.ReportSystemState(wCtx)
		}, networkTimeOut)
		if err != nil {
			printf("上报状态信息失败: %v", err)
			wCancel()
			retry()
			continue
		}
		go reportStateDaemon(reportState, wCancel)

		select {
		case <-reloadSigChan:
			println("Reloading...")
			wCancel()
		case <-wCtx.Done():
			println("Worker exit...")
		}

		retry()
	}
}

func runService(action string, path string) {
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
		logger.InitDefaultLogger(agentConfig.Debug, service.ConsoleLogger)
	} else {
		logger.InitDefaultLogger(agentConfig.Debug, serviceLogger)
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

func receiveTasksDaemon(tasks pb.NezhaService_RequestTaskClient, cancel context.CancelFunc) {
	var task *pb.Task
	var err error
	for {
		task, err = doWithTimeout(func() (*pb.Task, error) {
			return tasks.Recv()
		}, time.Second*30)
		if err != nil {
			printf("receiveTasks exit: %v", err)
			cancel()
			return
		}
		go func(t *pb.Task) {
			defer func() {
				if err := recover(); err != nil {
					println("task panic", task, err)
				}
			}()
			result := doTask(t)
			if result != nil {
				if err := tasks.Send(result); err != nil {
					printf("send task result exit: %v", err)
					cancel()
				}
			}
		}(task)
	}
}

func doTask(task *pb.Task) *pb.TaskResult {
	var result pb.TaskResult
	result.Id = task.GetId()
	result.Type = task.GetType()
	switch task.GetType() {
	case model.TaskTypeHTTPGet:
		handleHttpGetTask(task, &result)
	case model.TaskTypeICMPPing:
		handleIcmpPingTask(task, &result)
	case model.TaskTypeTCPPing:
		handleTcpPingTask(task, &result)
	case model.TaskTypeCommand:
		handleCommandTask(task, &result)
	case model.TaskTypeUpgrade:
		handleUpgradeTask(task, &result)
	case model.TaskTypeTerminalGRPC:
		handleTerminalTask(task)
		return nil
	case model.TaskTypeNAT:
		handleNATTask(task)
		return nil
	case model.TaskTypeFM:
		handleFMTask(task)
		return nil
	case model.TaskTypeReportConfig:
		handleReportConfigTask(&result)
	case model.TaskTypeApplyConfig:
		handleApplyConfigTask(task)
	case model.TaskTypeKeepalive:
	default:
		printf("不支持的任务: %v", task)
		return nil
	}
	return &result
}

// reportStateDaemon 向server上报状态信息
func reportStateDaemon(stateClient pb.NezhaService_ReportSystemStateClient, cancel context.CancelFunc) {
	var err error
	for {
		lastReportHostInfo, lastReportIPInfo, err = reportState(stateClient, lastReportHostInfo, lastReportIPInfo)
		if err != nil {
			printf("reportStateDaemon exit: %v", err)
			cancel()
			return
		}
		time.Sleep(time.Second * time.Duration(agentConfig.ReportDelay))
	}
}

func reportState(statClient pb.NezhaService_ReportSystemStateClient, host, ip time.Time) (time.Time, time.Time, error) {
	if statClient.Context().Err() != nil {
		return host, ip, statClient.Context().Err()
	}
	if initialized {
		monitor.TrackNetworkSpeed()
		if _, err := doWithTimeout(func() (*pb.Receipt, error) {
			return nil, statClient.Send(monitor.GetState(agentConfig.SkipConnectionCount, agentConfig.SkipProcsCount).PB())
		}, time.Second*10); err != nil {
			return host, ip, err
		}
		_, err := doWithTimeout(statClient.Recv, time.Second*10)
		if err != nil {
			return host, ip, err
		}
	}
	// 每10分钟重新获取一次硬件信息
	if host.Before(time.Now().Add(-10 * time.Minute)) {
		if reportHost() {
			host = time.Now()
		}
	}
	// 更新IP信息
	if time.Since(ip) > time.Second*time.Duration(agentConfig.IPReportPeriod) || !geoipReported {
		if reportGeoIP(agentConfig.UseIPv6CountryCode, !geoipReported) {
			ip = time.Now()
			geoipReported = true
		}
	}
	return host, ip, nil
}

func reportHost() bool {
	if !hostStatus.CompareAndSwap(false, true) {
		return false
	}
	defer hostStatus.Store(false)
	if client != nil && initialized {
		receipt, err := doWithTimeout(func() (*pb.Uint64Receipt, error) {
			return client.ReportSystemInfo2(context.Background(), monitor.GetHost().PB())
		}, time.Second*10)
		if err != nil {
			printf("ReportSystemInfo2 error: %v", err)
			return false
		}
		geoipReported = geoipReported && prevDashboardBootTime > 0 && receipt.GetData() == prevDashboardBootTime
	}
	return true
}

func reportGeoIP(use6, forceUpdate bool) bool {
	if !ipStatus.CompareAndSwap(false, true) {
		return false
	}
	defer ipStatus.Store(false)

	if client == nil || !initialized {
		return false
	}

	pbg := monitor.FetchIP(use6)
	if pbg == nil {
		return false
	}

	if !monitor.GeoQueryIPChanged && !forceUpdate {
		return true
	}

	geoip, err := doWithTimeout(func() (*pb.GeoIP, error) {
		return client.ReportGeoIP(context.Background(), pbg)
	}, time.Second*10)
	if err != nil {
		return false
	}

	prevDashboardBootTime = geoip.GetDashboardBootTime()

	monitor.CachedCountryCode = geoip.GetCountryCode()
	monitor.GeoQueryIPChanged = false

	return true
}

// doSelfUpdate 执行更新检查 如果更新成功则会结束进程
func doSelfUpdate(useLocalVersion bool) (exit bool) {
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
	case agentConfig.UseGiteeToUpgrade:
		updater, erru := selfupdate.NewGiteeUpdater(selfupdate.Config{
			BinaryName: binaryName,
		})
		if erru != nil {
			printf("更新失败: %v", erru)
			return
		}
		latest, err = updater.UpdateSelf(v, "naibahq/agent")
	case agentConfig.UseAtomGitToUpgrade:
		updater, erru := selfupdate.NewAtomGitUpdater(selfupdate.Config{
			BinaryName: binaryName,
		})
		if erru != nil {
			printf("更新失败: %v", erru)
			return
		}
		latest, err = updater.UpdateSelf(v, "naiba/nezha-agent")
	case monitor.CachedCountryCode == "cn":
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

func handleUpgradeTask(*pb.Task, *pb.TaskResult) {
	if agentConfig.DisableForceUpdate {
		return
	}
	if doSelfUpdate(false) {
		os.Exit(1)
	}
}

func handleTcpPingTask(task *pb.Task, result *pb.TaskResult) {
	if agentConfig.DisableSendQuery {
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

func handleIcmpPingTask(task *pb.Task, result *pb.TaskResult) {
	if agentConfig.DisableSendQuery {
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

func handleHttpGetTask(task *pb.Task, result *pb.TaskResult) {
	if agentConfig.DisableSendQuery {
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

func handleCommandTask(task *pb.Task, result *pb.TaskResult) {
	if agentConfig.DisableCommandExecute {
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
		result.Data = err.Error()
		return
	}
	pg.AddProcess(cmd)
	go func() {
		select {
		case <-timeout.C:
			result.Data = "任务执行超时\n"
			close(endCh)
			pg.Dispose()
		case <-endCh:
			timeout.Stop()
		}
	}()
	if err = cmd.Wait(); err != nil {
		result.Data += fmt.Sprintf("%s\n%s", b.String(), err.Error())
	} else {
		close(endCh)
		result.Data = b.String()
		result.Successful = true
	}
	pg.Dispose()
	result.Delay = float32(time.Since(startedAt).Seconds())
}

func handleReportConfigTask(result *pb.TaskResult) {
	if agentConfig.DisableCommandExecute {
		result.Data = "此 Agent 已禁止命令执行"
		return
	}

	if reloadStatus.Load() {
		result.Data = "another reload is in process"
		return
	}

	println("Executing Report Config Task")

	c, err := json.Marshal(agentConfig)
	if err != nil {
		result.Data = err.Error()
		return
	}

	result.Data = string(c)
	result.Successful = true
}

func handleApplyConfigTask(task *pb.Task) {
	if agentConfig.DisableCommandExecute {
		return
	}

	if !reloadStatus.CompareAndSwap(false, true) {
		return
	}

	println("Executing Apply Config Task")

	tmpConfig := agentConfig
	if err := json.Unmarshal([]byte(task.GetData()), &tmpConfig); err != nil {
		printf("Parsing Config failed: %v", err)
		reloadStatus.Store(false)
		return
	}

	if err := model.ValidateConfig(&tmpConfig, true); err != nil {
		printf("Validate Config failed: %v", err)
		reloadStatus.Store(false)
		return
	}

	println("Will reload workers in 10 seconds")
	time.AfterFunc(10*time.Second, func() {
		println("Applying new configuration...")
		agentConfig := tmpConfig
		agentConfig.Save()
		geoipReported = false
		logger.SetEnable(agentConfig.Debug)
		monitor.InitConfig(&agentConfig)
		monitor.CustomEndpoints = agentConfig.CustomIPApi
		reloadStatus.Store(false)
		reloadSigChan <- struct{}{}
	})
}

type WindowSize struct {
	Cols uint32
	Rows uint32
}

func handleTerminalTask(task *pb.Task) {
	if agentConfig.DisableCommandExecute {
		println("此 Agent 已禁止命令执行")
		return
	}
	var terminal model.TerminalTask
	err := json.Unmarshal([]byte(task.GetData()), &terminal)
	if err != nil {
		printf("Terminal 任务解析错误: %v", err)
		return
	}

	remoteIO, err := client.IOStream(context.Background())
	if err != nil {
		printf("Terminal IOStream失败: %v", err)
		return
	}

	// 发送 StreamID
	if err := remoteIO.Send(&pb.IOStreamData{Data: append([]byte{
		0xff, 0x05, 0xff, 0x05,
	}, []byte(terminal.StreamID)...)}); err != nil {
		printf("Terminal 发送StreamID失败: %v", err)
		return
	}

	tty, err := pty.Start()
	if err != nil {
		printf("Terminal pty.Start失败 %v", err)
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go ioStreamKeepAlive(ctx, remoteIO)

	defer func() {
		err := tty.Close()
		errCloseSend := remoteIO.CloseSend()
		println("terminal exit", terminal.StreamID, err, errCloseSend)
	}()
	println("terminal init", terminal.StreamID)

	go func() {
		buf := make([]byte, 10240)
		for {
			read, err := tty.Read(buf)
			if err != nil {
				remoteIO.Send(&pb.IOStreamData{Data: []byte(err.Error())})
				remoteIO.CloseSend()
				return
			}
			remoteIO.Send(&pb.IOStreamData{Data: buf[:read]})
		}
	}()

	for {
		var remoteData *pb.IOStreamData
		if remoteData, err = remoteIO.Recv(); err != nil {
			return
		}
		if len(remoteData.Data) == 0 {
			continue
		}
		switch remoteData.Data[0] {
		case 0:
			tty.Write(remoteData.Data[1:])
		case 1:
			decoder := json.NewDecoder(strings.NewReader(string(remoteData.Data[1:])))
			var resizeMessage WindowSize
			err := decoder.Decode(&resizeMessage)
			if err != nil {
				continue
			}
			tty.Setsize(resizeMessage.Cols, resizeMessage.Rows)
		}
	}
}

func handleNATTask(task *pb.Task) {
	if agentConfig.DisableNat {
		println("This server has disabled NAT traversal")
		return
	}

	var nat model.TaskNAT
	err := json.Unmarshal([]byte(task.GetData()), &nat)
	if err != nil {
		printf("NAT 任务解析错误: %v", err)
		return
	}

	remoteIO, err := client.IOStream(context.Background())
	if err != nil {
		printf("NAT IOStream失败: %v", err)
		return
	}

	// 发送 StreamID
	if err := remoteIO.Send(&pb.IOStreamData{Data: append([]byte{
		0xff, 0x05, 0xff, 0x05,
	}, []byte(nat.StreamID)...)}); err != nil {
		printf("NAT 发送StreamID失败: %v", err)
		return
	}

	conn, err := net.Dial("tcp", nat.Host)
	if err != nil {
		printf("NAT Dial %s 失败：%s", nat.Host, err)
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go ioStreamKeepAlive(ctx, remoteIO)

	defer func() {
		err := conn.Close()
		errCloseSend := remoteIO.CloseSend()
		println("NAT exit", nat.StreamID, err, errCloseSend)
	}()
	println("NAT init", nat.StreamID)

	go func() {
		buf := make([]byte, 10240)
		for {
			read, err := conn.Read(buf)
			if err != nil {
				remoteIO.Send(&pb.IOStreamData{Data: []byte(err.Error())})
				remoteIO.CloseSend()
				return
			}
			remoteIO.Send(&pb.IOStreamData{Data: buf[:read]})
		}
	}()

	for {
		var remoteData *pb.IOStreamData
		if remoteData, err = remoteIO.Recv(); err != nil {
			return
		}
		conn.Write(remoteData.Data)
	}
}

func handleFMTask(task *pb.Task) {
	if agentConfig.DisableCommandExecute {
		println("此 Agent 已禁止命令执行")
		return
	}
	var fmTask model.TaskFM
	err := json.Unmarshal([]byte(task.GetData()), &fmTask)
	if err != nil {
		printf("FM 任务解析错误: %v", err)
		return
	}

	remoteIO, err := client.IOStream(context.Background())
	if err != nil {
		printf("FM IOStream失败: %v", err)
		return
	}

	// 发送 StreamID
	if err := remoteIO.Send(&pb.IOStreamData{Data: append([]byte{
		0xff, 0x05, 0xff, 0x05,
	}, []byte(fmTask.StreamID)...)}); err != nil {
		printf("FM 发送StreamID失败: %v", err)
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go ioStreamKeepAlive(ctx, remoteIO)

	defer func() {
		errCloseSend := remoteIO.CloseSend()
		println("FM exit", fmTask.StreamID, nil, errCloseSend)
	}()
	println("FM init", fmTask.StreamID)

	fmc := fm.NewFMClient(remoteIO, printf)
	for {
		var remoteData *pb.IOStreamData
		if remoteData, err = remoteIO.Recv(); err != nil {
			return
		}
		if len(remoteData.Data) == 0 {
			continue
		}
		fmc.DoTask(remoteData)
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

func doWithTimeout[T any](fn func() (T, error), timeout time.Duration) (T, error) {
	timeoutCtx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	var t T
	var err error
	go func() {
		defer cancel()
		t, err = fn()
	}()
	<-timeoutCtx.Done()
	if timeoutCtx.Err() != context.Canceled {
		return t, fmt.Errorf("context error: %v, fn err: %v", timeoutCtx.Err(), err)
	}
	return t, err
}
