package vendor

// GPUStat carries per-card figures. Memory is in MiB and is left zero by
// vendors that do not report it, so callers must treat MemoryTotal == 0 as
// "memory unknown" rather than "no memory".
type GPUStat struct {
	Utilization float64
	MemoryUsed  uint64
	MemoryTotal uint64
}
