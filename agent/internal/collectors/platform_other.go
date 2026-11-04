//go:build !windows && !darwin

package collectors

// registerPlatform is a no-op on unsupported operating systems: every
// collector stays UNSUPPORTED. Linux endpoints are out of scope (see
// docs/SUPPORTED_PLATFORMS.md).
func registerPlatform(reg map[string]Collector) {}
