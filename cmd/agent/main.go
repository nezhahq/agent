package main

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"time"

	"github.com/blang/semver"
	"github.com/ebi-yade/altsvc-go"
	"github.com/nezhahq/go-github-selfupdate/selfupdate"
	"github.com/nezhahq/service"
	ping "github.com/prometheus-community/pro-bing"
	"github.com/quic-go/quic-go/http3"
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
	"github.com/nezhahq/agent/pkg/logger"
	"github.com/nezhahq/agent/pkg/monitor"
	"github.com/nezhahq/agent/pkg/processgroup"
	"github.com/nezhahq/agent/pkg/pty"
	"github.com/nezhahq/agent/pkg/util"
	utlsx "github.com/nezhahq/agent/pkg/utls"
	pb "github.com/nezhahq/agent/proto"
)

var (
	version           = monitor.Version // 来自于 GoReleaser 的版本号
	arch              string
	executablePath    string
	defaultConfigPath = loadDefaultConfigPath()
	client            pb.NezhaServiceClient
	initialized       bool
	dnsResolver       = &net.Resolver{PreferGo: true}
	agentConfig       model.AgentConfig
	httpClient        = &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Timeout: time.Second * 30,
	}
	httpClient3 = &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Timeout:   time.Second * 30,
		Transport: &http3.RoundTripper{},
	}

	hostStatus = new(atomic.Bool)
	ipStatus   = new(atomic.Bool)
)

var (
	println = logger.DefaultLogger.Println
	printf  = logger.DefaultLogger.Printf
)

const (
	delayWhenError = time.Second * 10 // Agent 重连间隔
	networkTimeOut = time.Second * 5  // 普通网络超时
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
		index := int(time.Now().Unix()) % int(len(dnsServers))
		queue := generateQueue(index, len(dnsServers))
		var conn net.Conn
		var err error
		for i := 0; i < len(queue); i++ {
			conn, err = d.DialContext(ctx, "udp", dnsServers[queue[i]])
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
		http.DefaultTransport, nil, &headers,
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

	// 下载远程命令执行需要的终端
	if !agentConfig.DisableCommandExecute {
		go func() {
			if err := pty.DownloadDependency(); err != nil {
				printf("pty 下载依赖失败: %v", err)
			}
		}()
	}

	// 定时检查更新
	if _, err := semver.Parse(version); err == nil && !agentConfig.DisableAutoUpdate {
		doSelfUpdate(true)
		go func() {
			for range time.Tick(20 * time.Minute) {
				doSelfUpdate(true)
			}
		}()
	}

	var err error
	var conn *grpc.ClientConn

	retry := func() {
		initialized = false
		println("Error to close connection ...")
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
		// 第一步注册
		timeOutCtx, cancel := context.WithTimeout(context.Background(), networkTimeOut)
		_, err = client.ReportSystemInfo(timeOutCtx, monitor.GetHost().PB())
		if err != nil {
			printf("上报系统信息失败: %v", err)
			cancel()
			retry()
			continue
		}
		cancel()
		initialized = true

		errCh := make(chan error)

		// 执行 Task
		tasks, err := client.RequestTask(context.Background(), monitor.GetHost().PB())
		if err != nil {
			printf("请求任务失败: %v", err)
			retry()
			continue
		}
		go receiveTasks(tasks, errCh)

		reportState, err := client.ReportSystemState(context.Background())
		if err != nil {
			printf("上报状态信息失败: %v", err)
			retry()
			continue
		}
		go reportStateDaemon(reportState, errCh)

		for i := 0; i < 2; i++ {
			err = <-errCh
			if i == 0 {
				tasks.CloseSend()
				reportState.CloseSend()
			}
			printf("worker exit to main: %v", err)
		}
		close(errCh)

		retry()
	}
}

func runService(action string, path string) {
	winConfig := map[string]interface{}{
		"OnFailure": "restart",
	}

	var args []string
	name := filepath.Base(executablePath)
	if path != defaultConfigPath && path != "" {
		args = []string{"-c", path}
		hex := fmt.Sprintf("%x", md5.Sum([]byte(path)))[:7]
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

	serviceLogger, err := s.Logger(nil)
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
		logger.DefaultLogger.Error(err)
	}
}

func receiveTasks(tasks pb.NezhaService_RequestTaskClient, errCh chan<- error) {
	var task *pb.Task
	var err error
	for {
		task, err = tasks.Recv()
		if err != nil {
			errCh <- fmt.Errorf("receiveTasks exit: %v", err)
			return
		}
		go func() {
			defer func() {
				if err := recover(); err != nil {
					println("task panic", task, err)
				}
			}()
			doTask(task)
		}()
	}
}

func doTask(task *pb.Task) {
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
		return
	case model.TaskTypeNAT:
		handleNATTask(task)
		return
	case model.TaskTypeReportHostInfo:
		reportHost()
		monitor.GeoQueryIPChanged = true
		reportGeoIP(agentConfig.UseIPv6CountryCode)
		return
	case model.TaskTypeFM:
		handleFMTask(task)
		return
	case model.TaskTypeKeepalive:
		return
	default:
		printf("不支持的任务: %v", task)
		return
	}
	client.ReportTask(context.Background(), &result)
}

// reportStateDaemon 向server上报状态信息
func reportStateDaemon(stateClient pb.NezhaService_ReportSystemStateClient, errCh chan<- error) {
	var lastReportHostInfo, lastReportIPInfo time.Time
	var err error
	for {
		// 为了更准确的记录时段流量，inited 后再上传状态信息
		lastReportHostInfo, lastReportIPInfo, err = reportState(stateClient, lastReportHostInfo, lastReportIPInfo)
		if err != nil {
			errCh <- fmt.Errorf("reportStateDaemon exit: %v", err)
			return
		}
		time.Sleep(time.Second * time.Duration(agentConfig.ReportDelay))
	}
}

func reportState(statClient pb.NezhaService_ReportSystemStateClient, host, ip time.Time) (time.Time, time.Time, error) {
	monitor.TrackNetworkSpeed()
	if err := statClient.Send(monitor.GetState(agentConfig.SkipConnectionCount, agentConfig.SkipProcsCount).PB()); err != nil {
		return host, ip, err
	}
	_, err := statClient.Recv()
	if err != nil {
		return host, ip, err
	}
	// 每10分钟重新获取一次硬件信息
	if host.Before(time.Now().Add(-10 * time.Minute)) {
		if reportHost() {
			host = time.Now()
		}
	}
	// 更新IP信息
	if time.Since(ip) > time.Second*time.Duration(agentConfig.IPReportPeriod) {
		reportGeoIP(agentConfig.UseIPv6CountryCode)
		ip = time.Now()
	}
	return host, ip, nil
}

func reportHost() bool {
	if !hostStatus.CompareAndSwap(false, true) {
		return false
	}
	defer hostStatus.Store(false)

	if client != nil && initialized {
		client.ReportSystemInfo(context.Background(), monitor.GetHost().PB())
	}

	return true
}

func reportGeoIP(use6 bool) bool {
	if !ipStatus.CompareAndSwap(false, true) {
		return false
	}
	defer ipStatus.Store(false)

	if client != nil && initialized {
		pbg := monitor.FetchIP(use6)
		if pbg != nil && monitor.GeoQueryIPChanged {
			geoip, err := client.ReportGeoIP(context.Background(), pbg)
			if err == nil {
				monitor.CachedCountryCode = geoip.GetCountryCode()
				monitor.GeoQueryIPChanged = false
			}
		} else {
			return false
		}
	}

	return true
}

// doSelfUpdate 执行更新检查 如果更新成功则会结束进程
func doSelfUpdate(useLocalVersion bool) {
	v := semver.MustParse("0.1.0")
	if useLocalVersion {
		v = semver.MustParse(version)
	}
	printf("检查更新: %v", v)
	var latest *selfupdate.Release
	var err error
	if monitor.CachedCountryCode != "cn" && !agentConfig.UseGiteeToUpgrade {
		latest, err = selfupdate.UpdateSelf(v, "nezhahq/agent")
	} else {
		latest, err = selfupdate.UpdateSelfGitee(v, "naibahq/agent")
	}
	if err != nil {
		printf("更新失败: %v", err)
		return
	}
	if !latest.Version.Equals(v) {
		printf("已经更新至: %v, 正在结束进程", latest.Version)
		os.Exit(1)
	}
}

func handleUpgradeTask(*pb.Task, *pb.TaskResult) {
	if agentConfig.DisableForceUpdate {
		return
	}
	doSelfUpdate(false)
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
	if strings.IndexByte(ipAddr, ':') != -1 {
		ipAddr = fmt.Sprintf("[%s]", ipAddr)
	}
	printf("TCP-Ping Task: Pinging %s:%s", ipAddr, port)
	start := time.Now()
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%s", ipAddr, port), time.Second*10)
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
	if err != nil {
		result.Data = err.Error()
		return
	}
	printf("ICMP-Ping Task: Pinging %s", ipAddr)
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
	checkHttpResp(taskUrl, start, resp, err, result)
}

func checkHttpResp(taskUrl string, start time.Time, resp *http.Response, err error, result *pb.TaskResult) {
	if err == nil {
		defer resp.Body.Close()
		_, err = io.Copy(io.Discard, resp.Body)
	}
	if err == nil {
		// 检查 HTTP Response 状态
		result.Delay = float32(time.Since(start).Microseconds()) / 1000.0
		if resp.StatusCode > 399 || resp.StatusCode < 200 {
			err = errors.New("\n应用错误：" + resp.Status)
		}
	}
	if err == nil {
		// 检查 SSL 证书信息
		if resp.TLS != nil && len(resp.TLS.PeerCertificates) > 0 {
			c := resp.TLS.PeerCertificates[0]
			result.Data = c.Issuer.CommonName + "|" + c.NotAfter.String()
		}
		altSvc := resp.Header.Get("Alt-Svc")
		if altSvc != "" {
			checkAltSvc(start, altSvc, taskUrl, result)
		} else {
			result.Successful = true
		}
	} else {
		// HTTP 请求失败
		result.Data = err.Error()
	}
}

func checkAltSvc(start time.Time, altSvcStr string, taskUrl string, result *pb.TaskResult) {
	altSvcList, err := altsvc.Parse(altSvcStr)
	if err != nil {
		result.Data = err.Error()
		result.Successful = false
		return
	}

	parsedUrl, _ := url.Parse(taskUrl)
	originalHost := parsedUrl.Hostname()
	originalPort := parsedUrl.Port()
	if originalPort == "" {
		switch parsedUrl.Scheme {
		case "http":
			originalPort = "80"
		case "https":
			originalPort = "443"
		}
	}

	altAuthorityHost := ""
	altAuthorityPort := ""
	altAuthorityProtocol := ""
	for _, altSvc := range altSvcList {
		altAuthorityPort = altSvc.AltAuthority.Port
		if altSvc.AltAuthority.Host != "" {
			altAuthorityHost = altSvc.AltAuthority.Host
			altAuthorityProtocol = altSvc.ProtocolID
			break
		}
	}
	if altAuthorityHost == "" {
		altAuthorityHost = originalHost
	}
	if altAuthorityHost == originalHost && altAuthorityPort == originalPort {
		result.Successful = true
		return
	}

	altAuthorityUrl := "https://" + altAuthorityHost + ":" + altAuthorityPort + "/"
	req, _ := http.NewRequest("GET", altAuthorityUrl, nil)
	req.Host = originalHost

	client := httpClient
	if strings.HasPrefix(altAuthorityProtocol, "h3") {
		client = httpClient3
	}
	resp, err := client.Do(req)

	checkHttpResp(altAuthorityUrl, start, resp, err, result)
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
	err := util.Json.Unmarshal([]byte(task.GetData()), &terminal)
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

	defer func() {
		err := tty.Close()
		errCloseSend := remoteIO.CloseSend()
		println("terminal exit", terminal.StreamID, err, errCloseSend)
	}()
	println("terminal init", terminal.StreamID)

	go func() {
		for {
			buf := make([]byte, 10240)
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
			return
		}
		switch remoteData.Data[0] {
		case 0:
			tty.Write(remoteData.Data[1:])
		case 1:
			decoder := util.Json.NewDecoder(strings.NewReader(string(remoteData.Data[1:])))
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
	err := util.Json.Unmarshal([]byte(task.GetData()), &nat)
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
	err := util.Json.Unmarshal([]byte(task.GetData()), &fmTask)
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
			return
		}
		fmc.DoTask(remoteData)
	}
}

func generateQueue(start int, size int) []int {
	var result []int
	for i := start; i < start+size; i++ {
		if i < size {
			result = append(result, i)
		} else {
			result = append(result, i-size)
		}
	}
	return result
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
