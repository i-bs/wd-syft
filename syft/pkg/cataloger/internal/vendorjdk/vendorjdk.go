package vendorjdk

import (
	"fmt"
	"path"
	"sort"
	"sync"

	osvjdk "github.com/bell-sw/osv-internal/vendorjdk"

	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/linux"
)

// Runtime is the module's detection result.
type Runtime = osvjdk.Runtime

// Vendor is the module's vendor string (re-exported for the catalogers).
const Vendor = osvjdk.Vendor

type probeKey struct {
	resolver string
	home     string
}

var (
	probeCache   = map[probeKey]*Runtime{}
	probeCacheMu sync.Mutex
)

func cacheKey(resolver file.Resolver, home string) probeKey {
	return probeKey{resolver: fmt.Sprintf("%p", resolver), home: home}
}

// ProbeHome runs the module's detector on a runtime home (resolver path or fs.FS name) and caches the verdict per
// resolver and home. It returns nil for runtimes of other vendors and non-runtimes; a NIK is returned with
// IsNIK set.
func ProbeHome(resolver file.Resolver, home string) (*Runtime, error) {
	name := ToFSName(home)
	key := cacheKey(resolver, name)
	probeCacheMu.Lock()
	rt, ok := probeCache[key]
	probeCacheMu.Unlock()
	if ok {
		return rt, nil
	}
	rt, err := osvjdk.DetectHome(NewFS(resolver), name)
	if err != nil {
		return nil, err
	}
	probeCacheMu.Lock()
	probeCache[key] = rt
	probeCacheMu.Unlock()
	return rt, nil
}

// Detect runs the module's detector anchored on a libjvm.so location and caches the verdict by the runtime home.
func Detect(resolver file.Resolver, libjvm file.Location) (*Runtime, error) {
	name := ToFSName(libjvm.RealPath)
	home, ok := osvjdk.HomeOf(name)
	if ok {
		probeCacheMu.Lock()
		rt, cached := probeCache[cacheKey(resolver, home)]
		probeCacheMu.Unlock()
		if cached {
			return rt, nil
		}
	}
	rt, err := osvjdk.Detect(NewFS(resolver), name)
	if err != nil {
		return nil, err
	}
	if rt != nil {
		home = rt.Home
		ok = true
	}
	if ok {
		probeCacheMu.Lock()
		probeCache[cacheKey(resolver, home)] = rt
		probeCacheMu.Unlock()
	}
	return rt, nil
}

// IsRuntimeHome reports whether the runtime rooted at home (resolver path) is a vendor runtime, so that
// the generic JVM catalogers can leave it to the vendor JDK cataloger.
func IsRuntimeHome(resolver file.Resolver, home string) bool {
	rt, err := ProbeHome(resolver, home)
	if err != nil {
		log.WithFields("home", home, "error", err).Debug("unable to probe JVM home for a vendor runtime")
		return false
	}
	return rt != nil
}

// HomeFromPath returns the runtime home (resolver path) a candidate file belongs to, by layout; "" when the path is
// not a runtime candidate (libjvm.so, release, rt.jar, bin/java...).
func HomeFromPath(p string) string {
	home, ok := osvjdk.HomeOf(ToFSName(p))
	if !ok {
		return ""
	}
	return ToResolverPath(home)
}

// ManagedByAPK reports whether a runtime home must be left to the apk ecosystem: the vendor distributions
// install their runtimes under /usr/lib/jvm as apk packages.
func ManagedByAPK(release *linux.Release, home string) bool {
	if release == nil {
		return false
	}
	if !osvjdk.ManagedByAPK(ToFSName(home)) {
		return false
	}
	return isVendorDistro(release.ID)
}

// OwnedFiles lists every file below a runtime home (resolver paths), for file-ownership relationships.
func OwnedFiles(resolver file.Resolver, home string) []string {
	locs, err := resolver.FilesByGlob(path.Join(ToResolverPath(home), "**"))
	if err != nil {
		log.WithFields("home", home, "error", err).Trace("unable to list runtime files")
	}
	var out []string
	for _, loc := range locs {
		out = append(out, loc.RealPath)
	}
	sort.Strings(out)
	return out
}
