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
	"apfs", "ext4", "ext3", "ext2", "f2fs", "reiserfs", "jfs", "bcachefs", "btrfs",
	"fuseblk", "zfs", "simfs", "ntfs", "fat32", "exfat", "xfs", "fuse.rclone",
}

func getLinuxRootDFFallback(ctx context.Context, fieldIndex int) (uint64, bool) {
	if runtime.GOOS != "linux" {
		return 0, false
	}

	out, err := exec.CommandContext(ctx, "df", "-P", "-k", "/").CombinedOutput()
	if err != nil {
		return 0, false
	}

	for _, c := range strings.Split(string(out), "\n") {
		info := strings.Fields(c)
		if len(info) == 6 && info[5] == "/" {
			v, err := strconv.ParseUint(info[fieldIndex], 10, 64)
			if err == nil {
				// 默认获取的是1K块为单位的.
				return v * 1024, true
			}
		}
	}

	return 0, false
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
	if total == 0 {
		if v, ok := getLinuxRootDFFallback(ctx, 1); ok {
			total = v
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
	if used == 0 {
		if v, ok := getLinuxRootDFFallback(ctx, 2); ok {
			used = v
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
