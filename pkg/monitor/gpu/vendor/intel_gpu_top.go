package vendor

import (
	"bufio"
	"bytes"
	"errors"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/tidwall/gjson"
)

const (
	intelVendorID = "0x8086"
)

// Cache for Intel GPU detection and model info (these don't change at runtime)
var (
	intelGPUDetected     bool
	intelGPUDetectedOnce sync.Once
	intelGPUModels       []string
	intelGPUModelsOnce   sync.Once
	intelGPUTopPath      string
	intelGPUTopPathOnce  sync.Once
)

type IntelGPUTop struct {
	BinPath string
	data    []byte
}

// IsAvailable performs a lightweight check for Intel GPU presence without spawning processes.
// This is used for vendor detection and is much faster than calling Start().
func (igt *IntelGPUTop) IsAvailable() bool {
	intelGPUDetectedOnce.Do(func() {
		intelGPUDetected = igt.hasIntelGPU() && igt.hasIntelGPUTopTool()
	})
	return intelGPUDetected
}

// hasIntelGPUTopTool checks if intel_gpu_top binary is available
func (igt *IntelGPUTop) hasIntelGPUTopTool() bool {
	intelGPUTopPathOnce.Do(func() {
		if _, err := os.Stat(igt.BinPath); err == nil {
			intelGPUTopPath = igt.BinPath
			return
		}
		if path, err := exec.LookPath("intel_gpu_top"); err == nil {
			intelGPUTopPath = path
		}
	})
	return intelGPUTopPath != ""
}

func (igt *IntelGPUTop) GatherModel() ([]string, error) {
	// Cache model info since it doesn't change at runtime
	var modelErr error
	intelGPUModelsOnce.Do(func() {
		intelGPUModels, modelErr = igt.gatherModel()
	})
	if modelErr != nil {
		return nil, modelErr
	}
	if len(intelGPUModels) == 0 {
		return nil, errors.New("no Intel GPU model found")
	}
	return intelGPUModels, nil
}

func (igt *IntelGPUTop) GatherUsage() ([]float64, error) {
	return igt.gatherUsage()
}

func (igt *IntelGPUTop) Start() error {
	// Use cached detection result
	if !igt.IsAvailable() {
		return errors.New("Intel GPU or intel_gpu_top not available")
	}

	// Use cached binary path
	if intelGPUTopPath != "" {
		igt.BinPath = intelGPUTopPath
	}

	igt.data = igt.pollIntelGPUTop()
	return nil
}

// hasIntelGPU checks if an Intel GPU is present in the system
func (igt *IntelGPUTop) hasIntelGPU() bool {
	// Check for Intel vendor ID in DRM devices
	entries, err := os.ReadDir("/sys/class/drm")
	if err != nil {
		return false
	}

	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), "card") {
			continue
		}
		// Skip render nodes like "card0-DP-1"
		if strings.Contains(entry.Name(), "-") {
			continue
		}

		vendorPath := "/sys/class/drm/" + entry.Name() + "/device/vendor"
		data, err := os.ReadFile(vendorPath)
		if err != nil {
			continue
		}

		vendor := strings.TrimSpace(string(data))
		if vendor == intelVendorID {
			return true
		}
	}

	// Also check for render devices
	if _, err := os.Stat("/dev/dri/renderD128"); err == nil {
		// renderD128 exists, might be Intel GPU - check with lspci
		return igt.checkLspciForIntelGPU()
	}

	return false
}

// checkLspciForIntelGPU uses lspci to detect Intel GPU
func (igt *IntelGPUTop) checkLspciForIntelGPU() bool {
	cmd := exec.Command("lspci", "-nn")
	output, err := cmd.Output()
	if err != nil {
		return false
	}

	// Look for Intel VGA or Display controllers
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		lower := strings.ToLower(line)
		if (strings.Contains(lower, "vga") || strings.Contains(lower, "display")) &&
			strings.Contains(line, "[8086:") {
			return true
		}
	}

	return false
}

func (igt *IntelGPUTop) pollIntelGPUTop() []byte {
	// Run intel_gpu_top with JSON output for ~500ms sampling period
	// -J: JSON output
	// -o -: output to stdout
	// -s 500: 500ms sampling period
	cmd := exec.Command(igt.BinPath, "-J", "-o", "-", "-s", "500")

	var stdout bytes.Buffer
	cmd.Stdout = &stdout

	if err := cmd.Start(); err != nil {
		return nil
	}

	// Wait for enough time to get at least one complete sample
	// The first sample is typically incomplete, we need the second one
	time.Sleep(600 * time.Millisecond)

	// Kill the process since intel_gpu_top runs continuously
	_ = cmd.Process.Kill()
	_ = cmd.Wait()

	return stdout.Bytes()
}

func (igt *IntelGPUTop) gatherModel() ([]string, error) {
	// Use lspci to get Intel GPU model name
	cmd := exec.Command("lspci", "-nn")
	output, err := cmd.Output()
	if err != nil {
		return nil, errors.New("failed to run lspci")
	}

	var models []string
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		lower := strings.ToLower(line)
		if (strings.Contains(lower, "vga") || strings.Contains(lower, "display")) &&
			strings.Contains(line, "[8086:") {
			// Extract the model name
			// Format: "13:00.0 VGA compatible controller [0300]: Intel Corporation TigerLake GT2 [Iris Xe Graphics] [8086:9a49] (rev 01)"
			model := extractIntelModelName(line)
			if model != "" {
				models = append(models, model)
			}
		}
	}

	if len(models) == 0 {
		return nil, errors.New("no Intel GPU model found")
	}

	return models, nil
}

// extractIntelModelName extracts the GPU model name from lspci output
func extractIntelModelName(line string) string {
	// Look for the pattern after "Intel Corporation" or similar
	// Example: "Intel Corporation TigerLake GT2 [Iris Xe Graphics]"
	re := regexp.MustCompile(`Intel Corporation\s+(.+?)\s+\[8086:`)
	matches := re.FindStringSubmatch(line)
	if len(matches) > 1 {
		return "Intel " + strings.TrimSpace(matches[1])
	}

	// Fallback: try to get anything between the controller type and [8086:
	re = regexp.MustCompile(`:\s+(.+?)\s+\[8086:`)
	matches = re.FindStringSubmatch(line)
	if len(matches) > 1 {
		return strings.TrimSpace(matches[1])
	}

	return "Intel GPU"
}

func (igt *IntelGPUTop) gatherUsage() ([]float64, error) {
	if igt.data == nil {
		return nil, errors.New("no data collected from intel_gpu_top")
	}

	usage, err := parseIntelUsage(igt.data)
	if err != nil {
		return nil, err
	}

	return usage, nil
}

// parseIntelUsage parses the JSON output from intel_gpu_top and extracts GPU usage
func parseIntelUsage(jsonData []byte) ([]float64, error) {
	if len(jsonData) == 0 {
		return nil, errors.New("empty data from intel_gpu_top")
	}

	// intel_gpu_top outputs a stream of JSON objects separated by },{ or newlines
	// We need to find and parse individual JSON objects
	// Look for complete JSON objects by finding matching braces

	objects := extractJSONObjects(jsonData)
	if len(objects) == 0 {
		return nil, errors.New("no valid JSON objects found in intel_gpu_top output")
	}

	// Use the last complete object (most recent sample)
	// Skip the first object as it may be incomplete initialization data
	var lastValidObject []byte
	for i := len(objects) - 1; i >= 0; i-- {
		obj := objects[i]
		result := gjson.ParseBytes(obj)
		if result.Get("engines").Exists() {
			lastValidObject = obj
			break
		}
	}

	if lastValidObject == nil {
		return nil, errors.New("no valid engine data found in intel_gpu_top output")
	}

	result := gjson.ParseBytes(lastValidObject)
	engines := result.Get("engines")
	if !engines.Exists() {
		return nil, errors.New("no engines data in intel_gpu_top output")
	}

	// Calculate overall GPU usage by taking the maximum busy percentage across all engines
	// This is similar to how other tools report "GPU utilization"
	var maxBusy float64
	var totalBusy float64
	var engineCount int

	engines.ForEach(func(key, value gjson.Result) bool {
		busy := value.Get("busy").Float()
		if busy > maxBusy {
			maxBusy = busy
		}
		totalBusy += busy
		engineCount++
		return true
	})

	// For Intel iGPU, we report the max busy value as the primary usage metric
	// This provides a better indication of GPU load than averaging
	// (e.g., when video encoding is at 80% but 3D is at 0%, report ~80%)
	if maxBusy == 0 && engineCount > 0 {
		// If all engines report 0, return 0
		return []float64{0}, nil
	}

	return []float64{maxBusy}, nil
}

// extractJSONObjects extracts individual JSON objects from a stream of JSON data
func extractJSONObjects(data []byte) [][]byte {
	var objects [][]byte
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)

	var currentObject bytes.Buffer
	braceCount := 0
	inObject := false

	for scanner.Scan() {
		line := scanner.Text()
		for _, char := range line {
			if char == '{' {
				if !inObject {
					inObject = true
					currentObject.Reset()
				}
				braceCount++
				currentObject.WriteRune(char)
			} else if char == '}' {
				braceCount--
				currentObject.WriteRune(char)
				if braceCount == 0 && inObject {
					// Complete object found
					obj := make([]byte, currentObject.Len())
					copy(obj, currentObject.Bytes())
					objects = append(objects, obj)
					inObject = false
					currentObject.Reset()
				}
			} else if inObject {
				currentObject.WriteRune(char)
			}
		}
		if inObject {
			currentObject.WriteRune('\n')
		}
	}

	return objects
}
