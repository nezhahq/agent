package disk

import (
	"context"
	"os/exec"
	"runtime"
	"strconv"
	"strings"

	psDisk "github.com/shirou/gopsutil/v4/disk"

	"github.com/nezhahq/agent/pkg/util"
)

type DiskKeyType string

const DiskKey DiskKeyType = "disk"

var expectDiskFsTypes = []string{
	"apfs", "ext4", "ext3", "ext2", "f2fs", "reiserfs", "jfs", "btrfs",
	"fuseblk", "zfs", "simfs", "ntfs", "fat32", "exfat", "xfs", "fuse.rclone",
}

func GetHost(ctx context.Context) (uint64, error) {
	devices, err := getDevices(ctx)
	if err != nil {
		return 0, err
	}

	var total uint64
	for _, mountPath := range devices {
		diskUsageOf, err := psDisk.Usage(mountPath)
		if err == nil {
			total += diskUsageOf.Total
		}
	}

	// Fallback 到这个方法,仅统计根路径,适用于OpenVZ之类的.
	if runtime.GOOS == "linux" && total == 0 {
		cmd := exec.Command("df")
		out, err := cmd.CombinedOutput()
		if err == nil {
			s := strings.Split(string(out), "\n")
			for _, c := range s {
				info := strings.Fields(c)
				if len(info) == 6 {
					if info[5] == "/" {
						total, _ = strconv.ParseUint(info[1], 0, 64)
						// 默认获取的是1K块为单位的.
						total = total * 1024
					}
				}
			}
		}
	}

	return total, nil
}

func GetState(ctx context.Context) (uint64, error) {
	devices, err := getDevices(ctx)
	if err != nil {
		return 0, err
	}

	var used uint64
	for _, mountPath := range devices {
		diskUsageOf, err := psDisk.Usage(mountPath)
		if err == nil {
			used += diskUsageOf.Used
		}
	}

	// Fallback 到这个方法,仅统计根路径,适用于OpenVZ之类的.
	if runtime.GOOS == "linux" && used == 0 {
		cmd := exec.Command("df")
		out, err := cmd.CombinedOutput()
		if err == nil {
			s := strings.Split(string(out), "\n")
			for _, c := range s {
				info := strings.Fields(c)
				if len(info) == 6 {
					if info[5] == "/" {
						used, _ = strconv.ParseUint(info[2], 0, 64)
						// 默认获取的是1K块为单位的.
						used = used * 1024
					}
				}
			}
		}
	}

	return used, nil
}

func getDevices(ctx context.Context) (map[string]string, error) {
	devices := make(map[string]string)

	// 如果配置了白名单，使用白名单的列表
	if s, ok := ctx.Value(DiskKey).([]string); ok && len(s) > 0 {
		for i, v := range s {
			devices[strconv.Itoa(i)] = v
		}
		return devices, nil
	}

	// 否则使用默认过滤规则
	diskList, err := psDisk.Partitions(false)
	if err != nil {
		return nil, err
	}

	for _, d := range diskList {
		fsType := strings.ToLower(d.Fstype)
		// 不统计 K8s 的虚拟挂载点：https://github.com/shirou/gopsutil/issues/1007
		if devices[d.Device] == "" && util.ContainsStr(expectDiskFsTypes, fsType) && !strings.Contains(d.Mountpoint, "/var/lib/kubelet") {
			devices[d.Device] = d.Mountpoint
		}
	}

	return devices, nil
}
