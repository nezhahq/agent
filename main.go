package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/AlecAivazis/survey/v2"
	bpc "github.com/DaRealFreak/cloudflare-bp-go"
	"github.com/blang/semver"
	"github.com/ebi-yade/altsvc-go"
	"github.com/go-ping/ping"
	"github.com/gorilla/websocket"
	"github.com/nezhahq/go-github-selfupdate/selfupdate"
	"github.com/quic-go/quic-go/http3"
	"github.com/shirou/gopsutil/v3/disk"
	"github.com/shirou/gopsutil/v3/host"
	psnet "github.com/shirou/gopsutil/v3/net"
	flag "github.com/spf13/pflag"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/nezhahq/agent/model"
	"github.com/nezhahq/agent/pkg/monitor"
	"github.com/nezhahq/agent/pkg/processgroup"
	"github.com/nezhahq/agent/pkg/pty"
	"github.com/nezhahq/agent/pkg/util"
	pb "github.com/nezhahq/agent/proto"
)

type AgentCliParam struct {
	SkipConnectionCount   bool   // 跳过连接数检查
	SkipProcsCount        bool   // 跳过进程数量检查
	DisableAutoUpdate     bool   // 关闭自动更新
	DisableForceUpdate    bool   // 关闭强制更新
	DisableCommandExecute bool   // 关闭命令执行
	Debug                 bool   // debug模式
	Server                string // 服务器地址
	ClientSecret          string // 客户端密钥
	ReportDelay           int    // 报告间隔
	TLS                   bool   // 是否使用TLS加密传输至服务端
	Version               bool   // 当前版本号
}

var (
	version string
	arch    string
	client  pb.NezhaServiceClient
	inited  bool
)

var (
	agentCliParam AgentCliParam
	agentConfig   model.AgentConfig
	httpClient    = &http.Client{
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
)

const (
	delayWhenError = time.Second * 10 // Agent 重连间隔
	networkTimeOut = time.Second * 5  // 普通网络超时
	macOSChromeUA  = ""
)

func init() {
	net.DefaultResolver.PreferGo = true // 使用 Go 内置的 DNS 解析器解析域名
	net.DefaultResolver.Dial = func(ctx context.Context, network, address string) (net.Conn, error) {
		d := net.Dialer{
			Timeout: time.Second * 5,
		}
		dnsServers := []string{
			"8.8.4.4:53", "223.5.5.5:53", "94.140.14.140:53", "119.29.29.29:53",
			"[2001:4860:4860::8844]:53", "[2400:3200::1]:53", "[2a10:50c0::1:ff]:53", "[2402:4e00::]:53",
		}
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
	flag.CommandLine.ParseErrorsWhitelist.UnknownFlags = true

	http.DefaultClient.Timeout = time.Second * 5
	httpClient.Transport = bpc.AddCloudFlareByPass(httpClient.Transport, bpc.Options{
		AddMissingHeaders: true,
		Headers: map[string]string{
			"Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8",
			"Accept-Language": "en-US,en;q=0.5",
			"User-Agent":      monitor.MacOSChromeUA,
		},
	})

	ex, err := os.Executable()
	if err != nil {
		panic(err)
	}
	agentConfig.Read(filepath.Dir(ex) + "/config.yml")
}

func main() {
	// windows环境处理
	if runtime.GOOS == "windows" {
		hostArch, err := host.KernelArch()
		if err != nil {
			panic(err)
		}
		if hostArch == "i386" {
			hostArch = "386"
		}
		if hostArch == "i686" || hostArch == "ia64" || hostArch == "x86_64" {
			hostArch = "amd64"
		}
		if hostArch == "aarch64" {
			hostArch = "arm64"
		}
		if arch != hostArch {
			panic(fmt.Sprintf("与当前系统不匹配，当前运行 %s_%s, 需要下载 %s_%s", runtime.GOOS, arch, runtime.GOOS, hostArch))
		}
	}

	// 来自于 GoReleaser 的版本号
	monitor.Version = version

	// 初始化运行参数
	var isEditAgentConfig bool
	flag.BoolVarP(&agentCliParam.Debug, "debug", "d", false, "开启调试信息")
	flag.BoolVarP(&isEditAgentConfig, "edit-agent-config", "c", false, "修改要监控的网卡/分区名单，修改自定义 DNS")
	flag.StringVarP(&agentCliParam.Server, "server", "s", "localhost:5555", "管理面板RPC端口")
	flag.StringVarP(&agentCliParam.ClientSecret, "password", "p", "", "Agent连接Secret")
	flag.IntVar(&agentCliParam.ReportDelay, "report-delay", 1, "系统状态上报间隔")
	flag.BoolVar(&agentCliParam.SkipConnectionCount, "skip-conn", false, "不监控连接数")
	flag.BoolVar(&agentCliParam.SkipProcsCount, "skip-procs", false, "不监控进程数")
	flag.BoolVar(&agentCliParam.DisableCommandExecute, "disable-command-execute", false, "禁止在此机器上执行命令")
	flag.BoolVar(&agentCliParam.DisableAutoUpdate, "disable-auto-update", false, "禁用自动升级")
	flag.BoolVar(&agentCliParam.DisableForceUpdate, "disable-force-update", false, "禁用强制升级")
	flag.BoolVar(&agentCliParam.TLS, "tls", false, "启用SSL/TLS加密")
	flag.BoolVarP(&agentCliParam.Version, "version", "v", false, "查看当前版本号")
	flag.Parse()

	if agentCliParam.Version {
		fmt.Println(version)
		return
	}

	if isEditAgentConfig {
		editAgentConfig()
		return
	}

	if agentCliParam.ClientSecret == "" {
		flag.Usage()
		return
	}

	if agentCliParam.ReportDelay < 1 || agentCliParam.ReportDelay > 4 {
		println("report-delay 的区间为 1-4")
		return
	}

	run()
}

func run() {
	auth := model.AuthHandler{
		ClientSecret: agentCliParam.ClientSecret,
	}

	// 下载远程命令执行需要的终端
	if !agentCliParam.DisableCommandExecute {
		go pty.DownloadDependency()
	}
	// 上报服务器信息
	go reportState()
	// 更新IP信息
	go monitor.UpdateIP()

	// 定时检查更新
	if _, err := semver.Parse(version); err == nil && !agentCliParam.DisableAutoUpdate {
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
		inited = false
		println("Error to close connection ...")
		if conn != nil {
			conn.Close()
		}
		time.Sleep(delayWhenError)
		println("Try to reconnect ...")
	}

	for {
		timeOutCtx, cancel := context.WithTimeout(context.Background(), networkTimeOut)
		var securityOption grpc.DialOption
		if agentCliParam.TLS {
			securityOption = grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{MinVersion: tls.VersionTLS12}))
		} else {
			securityOption = grpc.WithTransportCredentials(insecure.NewCredentials())
		}
		conn, err = grpc.DialContext(timeOutCtx, agentCliParam.Server, securityOption, grpc.WithPerRPCCredentials(&auth))
		if err != nil {
			println("与面板建立连接失败：", err)
			cancel()
			retry()
			continue
		}
		cancel()
		client = pb.NewNezhaServiceClient(conn)
		// 第一步注册
		timeOutCtx, cancel = context.WithTimeout(context.Background(), networkTimeOut)
		_, err = client.ReportSystemInfo(timeOutCtx, monitor.GetHost(&agentConfig).PB())
		if err != nil {
			println("上报系统信息失败：", err)
			cancel()
			retry()
			continue
		}
		cancel()
		inited = true
		// 执行 Task
		tasks, err := client.RequestTask(context.Background(), monitor.GetHost(&agentConfig).PB())
		if err != nil {
			println("请求任务失败：", err)
			retry()
			continue
		}
		err = receiveTasks(tasks)
		println("receiveTasks exit to main：", err)
		retry()
	}
}

func receiveTasks(tasks pb.NezhaService_RequestTaskClient) error {
	var err error
	defer println("receiveTasks exit", time.Now(), "=>", err)
	for {
		var task *pb.Task
		task, err = tasks.Recv()
		if err != nil {
			return err
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
	case model.TaskTypeTerminal:
		handleTerminalTask(task)
	case model.TaskTypeHTTPGET:
		handleHttpGetTask(task, &result)
	case model.TaskTypeICMPPing:
		handleIcmpPingTask(task, &result)
	case model.TaskTypeTCPPing:
		handleTcpPingTask(task, &result)
	case model.TaskTypeCommand:
		handleCommandTask(task, &result)
	case model.TaskTypeUpgrade:
		handleUpgradeTask(task, &result)
	case model.TaskTypeKeepalive:
		return
	default:
		println("不支持的任务：", task)
	}
	client.ReportTask(context.Background(), &result)
}

// reportState 向server上报状态信息
func reportState() {
	var lastReportHostInfo time.Time
	var err error
	defer println("reportState exit", time.Now(), "=>", err)
	for {
		// 为了更准确的记录时段流量，inited 后再上传状态信息
		if client != nil && inited {
			monitor.TrackNetworkSpeed(&agentConfig)
			timeOutCtx, cancel := context.WithTimeout(context.Background(), networkTimeOut)
			_, err = client.ReportSystemState(timeOutCtx, monitor.GetState(&agentConfig, agentCliParam.SkipConnectionCount, agentCliParam.SkipProcsCount).PB())
			cancel()
			if err != nil {
				println("reportState error", err)
				time.Sleep(delayWhenError)
			}
			// 每10分钟重新获取一次硬件信息
			if lastReportHostInfo.Before(time.Now().Add(-10 * time.Minute)) {
				lastReportHostInfo = time.Now()
				client.ReportSystemInfo(context.Background(), monitor.GetHost(&agentConfig).PB())
			}
		}
		time.Sleep(time.Second * time.Duration(agentCliParam.ReportDelay))
	}
}

// doSelfUpdate 执行更新检查 如果更新成功则会结束进程
func doSelfUpdate(useLocalVersion bool) {
	v := semver.MustParse("0.1.0")
	if useLocalVersion {
		v = semver.MustParse(version)
	}
	println("检查更新：", v)
	latest, err := selfupdate.UpdateSelf(v, "nezhahq/agent")
	if err != nil {
		println("更新失败：", err)
		return
	}
	if !latest.Version.Equals(v) {
		println("已经更新至：", latest.Version, " 正在结束进程")
		os.Exit(1)
	}
}

func handleUpgradeTask(task *pb.Task, result *pb.TaskResult) {
	if agentCliParam.DisableForceUpdate {
		return
	}
	doSelfUpdate(false)
}

func handleTcpPingTask(task *pb.Task, result *pb.TaskResult) {
	start := time.Now()
	conn, err := net.DialTimeout("tcp", task.GetData(), time.Second*10)
	if err == nil {
		conn.Write([]byte("ping\n"))
		conn.Close()
		result.Delay = float32(time.Since(start).Microseconds()) / 1000.0
		result.Successful = true
	} else {
		result.Data = err.Error()
	}
}

func handleIcmpPingTask(task *pb.Task, result *pb.TaskResult) {
	pinger, err := ping.NewPinger(task.GetData())
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
	start := time.Now()
	taskUrl := task.GetData()
	resp, err := httpClient.Get(taskUrl)
	checkHttpResp(taskUrl, start, resp, err, result)
}

func checkHttpResp(taskUrl string, start time.Time, resp *http.Response, err error, result *pb.TaskResult) {
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
	if agentCliParam.DisableCommandExecute {
		result.Data = "此 Agent 已禁止命令执行"
		return
	}
	startedAt := time.Now()
	var cmd *exec.Cmd
	var endCh = make(chan struct{})
	pg, err := processgroup.NewProcessExitGroup()
	if err != nil {
		// 进程组创建失败，直接退出
		result.Data = err.Error()
		return
	}
	timeout := time.NewTimer(time.Hour * 2)
	if util.IsWindows() {
		cmd = exec.Command("cmd", "/c", task.GetData()) // #nosec
	} else {
		cmd = exec.Command("sh", "-c", task.GetData()) // #nosec
	}
	cmd.Env = os.Environ()
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
	output, err := cmd.Output()
	if err != nil {
		result.Data += fmt.Sprintf("%s\n%s", string(output), err.Error())
	} else {
		close(endCh)
		result.Data = string(output)
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
	if agentCliParam.DisableCommandExecute {
		println("此 Agent 已禁止命令执行")
		return
	}
	var terminal model.TerminalTask
	err := util.Json.Unmarshal([]byte(task.GetData()), &terminal)
	if err != nil {
		println("Terminal 任务解析错误：", err)
		return
	}
	protocol := "ws"
	if terminal.UseSSL {
		protocol += "s"
	}
	header := http.Header{}
	header.Add("Secret", agentCliParam.ClientSecret)
	// 目前只兼容Cloudflare验证
	// 后续可能需要兼容更多的Cookie验证情况
	if terminal.Cookie != "" {
		cfCookie := fmt.Sprintf("CF_Authorization=%s", terminal.Cookie)
		header.Add("Cookie", cfCookie)
	}
	conn, _, err := websocket.DefaultDialer.Dial(fmt.Sprintf("%s://%s/terminal/%s", protocol, terminal.Host, terminal.Session), header)
	if err != nil {
		println("Terminal 连接失败：", err)
		return
	}
	defer conn.Close()

	tty, err := pty.Start()
	if err != nil {
		println("Terminal pty.Start失败：", err)
		return
	}

	defer func() {
		err := tty.Close()
		conn.Close()
		println("terminal exit", terminal.Session, err)
	}()
	println("terminal init", terminal.Session)

	go func() {
		for {
			buf := make([]byte, 1024)
			read, err := tty.Read(buf)
			if err != nil {
				conn.WriteMessage(websocket.TextMessage, []byte(err.Error()))
				conn.Close()
				return
			}
			conn.WriteMessage(websocket.BinaryMessage, buf[:read])
		}
	}()

	for {
		messageType, reader, err := conn.NextReader()
		if err != nil {
			return
		}

		if messageType == websocket.TextMessage {
			continue
		}

		dataTypeBuf := make([]byte, 1)
		read, err := reader.Read(dataTypeBuf)
		if err != nil {
			conn.WriteMessage(websocket.TextMessage, []byte("Unable to read message type from reader"))
			return
		}

		if read != 1 {
			return
		}

		switch dataTypeBuf[0] {
		case 0:
			io.Copy(tty, reader)
		case 1:
			decoder := util.Json.NewDecoder(reader)
			var resizeMessage WindowSize
			err := decoder.Decode(&resizeMessage)
			if err != nil {
				continue
			}
			tty.Setsize(resizeMessage.Cols, resizeMessage.Rows)
		}
	}
}

// 修改Agent要监控的网卡与硬盘分区
func editAgentConfig() {
	nc, err := psnet.IOCounters(true)
	if err != nil {
		panic(err)
	}
	var nicAllowlistOptions []string
	for _, v := range nc {
		nicAllowlistOptions = append(nicAllowlistOptions, v.Name)
	}

	var diskAllowlistOptions []string
	diskList, err := disk.Partitions(false)
	if err != nil {
		panic(err)
	}
	for _, p := range diskList {
		diskAllowlistOptions = append(diskAllowlistOptions, fmt.Sprintf("%s\t%s\t%s", p.Mountpoint, p.Fstype, p.Device))
	}

	var qs = []*survey.Question{
		{
			Name: "nic",
			Prompt: &survey.MultiSelect{
				Message: "选择要监控的网卡",
				Options: nicAllowlistOptions,
			},
		},
		{
			Name: "disk",
			Prompt: &survey.MultiSelect{
				Message: "选择要监控的硬盘分区",
				Options: diskAllowlistOptions,
			},
		},
		{
			Name: "dns",
			Prompt: &survey.Input{
				Message: "自定义 DNS，可输入空格跳过，如 1.1.1.1:53,1.0.0.1:53",
				Default: strings.Join(agentConfig.DNS, ","),
			},
		},
	}

	answers := struct {
		Nic  []string
		Disk []string
		DNS  string
	}{}

	err = survey.Ask(qs, &answers, survey.WithValidator(survey.Required))
	if err != nil {
		fmt.Println("选择错误", err.Error())
		return
	}

	agentConfig.HardDrivePartitionAllowlist = []string{}
	for _, v := range answers.Disk {
		agentConfig.HardDrivePartitionAllowlist = append(agentConfig.HardDrivePartitionAllowlist, strings.Split(v, "\t")[0])
	}

	agentConfig.NICAllowlist = make(map[string]bool)
	for _, v := range answers.Nic {
		agentConfig.NICAllowlist[v] = true
	}

	dnsServers := strings.TrimSpace(answers.DNS)

	if dnsServers != "" {
		agentConfig.DNS = strings.Split(dnsServers, ",")
		for _, s := range agentConfig.DNS {
			host, _, err := net.SplitHostPort(s)
			if err == nil {
				if net.ParseIP(host) == nil {
					err = errors.New("格式错误")
				}
			}
			if err != nil {
				panic(fmt.Sprintf("自定义 DNS 格式错误：%s %v", s, err))
			}
		}
	} else {
		agentConfig.DNS = []string{}
	}

	if err = agentConfig.Save(); err != nil {
		panic(err)
	}

	fmt.Println("修改自定义配置成功，重启 Agent 后生效")
}

func println(v ...interface{}) {
	if agentCliParam.Debug {
		fmt.Printf("NEZHA@%s>> ", time.Now().Format("2006-01-02 15:04:05"))
		fmt.Println(v...)
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
