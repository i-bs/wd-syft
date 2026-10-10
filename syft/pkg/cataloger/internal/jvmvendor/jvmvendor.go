/*
Package jvmvendor identifies the vendor and product of an installed Java runtime from its own files: the java.vm.vendor
constant and the HotSpot banner of the JVM library (libjvm.so, libjvm.dylib, jvm.dll), the IMPLEMENTOR of the release
file, and the GraalVM markers that tell a Native Image Kit from a plain JDK. It lets the JVM catalogers agree on which
of them owns a runtime.
*/
package jvmvendor

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"path"
	"regexp"
	"sort"
	"strings"
	"sync"

	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/file"
)

// Vendor is the vendor string compiled into every runtime of the vendor (java.vm.vendor, IMPLEMENTOR).
const Vendor = "BellSoft"

// JVMLibraryGlob matches the JVM shared library of a runtime on Linux, macOS and Windows.
const JVMLibraryGlob = "**/{libjvm.so,libjvm.dylib,jvm.dll}"

const (
	scanChunkSize   = 1 << 20
	scanOverlapSize = 4096
	releaseLimit    = 512 * 1024
	maxHomeDepth    = 5
)

var (
	// knownVendors are the NUL-terminated java.vm.vendor constants looked for in the JVM library, in lookup order.
	knownVendors = []string{Vendor}
	// OpenJDK 64-Bit Server VM (21.0.2+14-LTS) for linux-amd64 JRE (21.0.2+14-LTS), built on ...
	// OpenJDK 64-Bit Server VM (25.402-b07) for linux-amd64 JRE (1.8.0_402-b07), built on ...
	bannerPattern = regexp.MustCompile(`JRE \((?P<version>[0-9][^)\x00]*)\)`)
	// java.vendor.version of the vendor's Native Image Kit (lib/modules, bin/native-image): Liberica-NIK-23.1.0-1
	nikVersionPattern = regexp.MustCompile(`Liberica-NIK-(?P<version>[0-9]+(?:\.[0-9]+)*)-(?P<build>[0-9]+)`)
)

// Runtime is what the inspection of a runtime home yields.
type Runtime struct {
	Home string
	// Vendor is the known vendor identified ("" for other vendors or no evidence).
	Vendor string
	// Version is the version as written in the HotSpot banner ("21.0.2+14-LTS", "1.8.0_402-b07") or, when the JVM
	// library carried no banner, the release file's JAVA_RUNTIME_VERSION / JAVA_VERSION.
	Version string
	// Library is the JVM library the banner/vendor were read from ("" when none was readable).
	Library string
	// NIK is set for a GraalVM-based vendor runtime (Native Image Kit): release GRAALVM_VERSION, lib/svm/
	// or bin/native-image present. NIKVersion is "A.B.C+D" from the Liberica-NIK-A.B.C-D vendor version, falling back
	// to GRAALVM_VERSION.
	NIK        bool
	NIKVersion string
}

// RuntimeHome returns the root of the runtime a file belongs to: the first ancestor directory (at most five levels
// up) holding bin/java (or bin/java.exe) or a release file. For the Java 8 JDK layout, where <home>/jre/bin/java is
// met first, the enclosing JDK directory is returned when it holds bin/java too. "" when no runtime root is found.
func RuntimeHome(resolver file.Resolver, p string) string {
	dir := path.Dir(p)
	for i := 0; i < maxHomeDepth && dir != "" && dir != "/" && dir != "."; i++ {
		if hasLauncher(resolver, dir) || resolver.HasPath(path.Join(dir, "release")) {
			if path.Base(dir) == "jre" {
				parent := path.Dir(dir)
				if hasLauncher(resolver, parent) {
					return parent
				}
			}
			return dir
		}
		dir = path.Dir(dir)
	}
	return ""
}

func hasLauncher(resolver file.Resolver, dir string) bool {
	return resolver.HasPath(path.Join(dir, "bin", "java")) || resolver.HasPath(path.Join(dir, "bin", "java.exe"))
}

// LibraryCandidates lists the JVM library locations of a runtime home: lib/<vm>/ for Java 9+ on Linux and macOS,
// bin/<vm>/jvm.dll on Windows, jre/lib/<arch>/<vm>/ or lib/<arch>/<vm>/ (Java 8).
func LibraryCandidates(resolver file.Resolver, home string) []file.Location {
	locs, err := resolver.FilesByGlob(
		path.Join(home, "lib", "*", "{libjvm.so,libjvm.dylib}"),
		path.Join(home, "bin", "*", "jvm.dll"),
		path.Join(home, "jre", "lib", "*", "*", "{libjvm.so,libjvm.dylib}"),
		path.Join(home, "jre", "lib", "*", "libjvm.dylib"),
		path.Join(home, "jre", "bin", "*", "jvm.dll"),
		path.Join(home, "lib", "*", "*", "{libjvm.so,libjvm.dylib}"),
	)
	if err != nil {
		log.WithFields("home", home, "error", err).Trace("unable to look up the JVM library")
	}
	sort.Slice(locs, func(i, j int) bool { return locs[i].RealPath < locs[j].RealPath })
	return locs
}

// ScanLibrary reads a JVM library and returns the known vendor whose NUL-terminated constant is present ("" when
// none) and the version of the HotSpot "JRE (<version>)" banner ("" when absent).
func ScanLibrary(r io.Reader) (vendor, version string, err error) {
	br := bufio.NewReaderSize(r, scanChunkSize)
	buf := make([]byte, scanChunkSize+scanOverlapSize)
	var tail []byte
	for {
		n, rerr := io.ReadFull(br, buf[len(tail):scanChunkSize+len(tail)])
		chunk := buf[:len(tail)+n]
		if vendor == "" {
			for _, v := range knownVendors {
				if bytes.Contains(chunk, []byte("\x00"+v+"\x00")) {
					vendor = v
					break
				}
			}
		}
		if version == "" {
			if m := bannerPattern.FindSubmatch(chunk); m != nil {
				version = string(m[1])
			}
		}
		if rerr != nil {
			if rerr == io.EOF || rerr == io.ErrUnexpectedEOF {
				return vendor, version, nil
			}
			return vendor, version, rerr
		}
		// keep an overlap so that a string crossing the chunk boundary is still found
		if len(chunk) > scanOverlapSize {
			tail = chunk[len(chunk)-scanOverlapSize:]
		} else {
			tail = chunk
		}
		copy(buf, tail)
		tail = buf[:len(tail)]
	}
}

// ReadRelease parses <home>/release (KEY="value" lines) into a map; nil when the file is absent.
func ReadRelease(resolver file.Resolver, home string) map[string]string {
	locs, err := resolver.FilesByPath(path.Join(home, "release"))
	if err != nil || len(locs) == 0 {
		return nil
	}
	rc, err := resolver.FileContentsByLocation(locs[0])
	if err != nil {
		return nil
	}
	defer internal.CloseAndLogError(rc, locs[0].RealPath)
	out := map[string]string{}
	scanner := bufio.NewScanner(io.LimitReader(rc, releaseLimit))
	scanner.Buffer(make([]byte, 64*1024), releaseLimit)
	for scanner.Scan() {
		key, value, ok := strings.Cut(scanner.Text(), "=")
		if ok {
			out[strings.TrimSpace(key)] = strings.Trim(strings.TrimSpace(value), `"`)
		}
	}
	return out
}

type cacheKey struct {
	resolver string
	home     string
}

var (
	runtimeCache   = map[cacheKey]*Runtime{}
	runtimeCacheMu sync.Mutex
)

// Inspect identifies the runtime rooted at home. Vendor is set only for a known vendor: the release file's
// IMPLEMENTOR when present (another vendor there means "not ours" whatever the library says), else the java.vm.vendor
// constant of the JVM library. Results are cached per resolver and home.
func Inspect(resolver file.Resolver, home string) *Runtime {
	key := cacheKey{resolver: fmt.Sprintf("%p", resolver), home: home}
	runtimeCacheMu.Lock()
	rt, ok := runtimeCache[key]
	runtimeCacheMu.Unlock()
	if ok {
		return rt
	}
	rt = inspect(resolver, home)
	runtimeCacheMu.Lock()
	runtimeCache[key] = rt
	runtimeCacheMu.Unlock()
	return rt
}

func inspect(resolver file.Resolver, home string) *Runtime {
	rt := &Runtime{Home: home}
	release := ReadRelease(resolver, home)

	for _, loc := range LibraryCandidates(resolver, home) {
		rc, err := resolver.FileContentsByLocation(loc)
		if err != nil {
			log.WithFields("path", loc.RealPath, "error", err).Debug("unable to read the JVM library")
			continue
		}
		vendor, version, err := ScanLibrary(rc)
		internal.CloseAndLogError(rc, loc.RealPath)
		if err != nil {
			log.WithFields("path", loc.RealPath, "error", err).Debug("unable to scan the JVM library")
			continue
		}
		rt.Library = loc.RealPath
		rt.Vendor = vendor
		rt.Version = version
		break
	}

	if impl := strings.TrimSpace(release["IMPLEMENTOR"]); impl != "" {
		rt.Vendor = ""
		for _, v := range knownVendors {
			if strings.EqualFold(impl, v) {
				rt.Vendor = v
			}
		}
	}
	if rt.Version == "" {
		rt.Version = release["JAVA_RUNTIME_VERSION"]
	}
	if rt.Version == "" {
		rt.Version = release["JAVA_VERSION"]
	}

	if rt.Vendor == Vendor {
		if _, ok := release["GRAALVM_VERSION"]; ok || resolver.HasPath(path.Join(home, "lib", "svm")) ||
			resolver.HasPath(path.Join(home, "bin", "native-image")) || resolver.HasPath(path.Join(home, "bin", "native-image.cmd")) {
			rt.NIK = true
			rt.NIKVersion = nikVersion(resolver, home, release)
		}
	}
	return rt
}

// nikVersion returns "A.B.C+D" from the Liberica-NIK-A.B.C-D vendor version found in lib/modules or bin/native-image,
// falling back to the release file's GRAALVM_VERSION.
func nikVersion(resolver file.Resolver, home string, release map[string]string) string {
	for _, candidate := range []string{path.Join(home, "lib", "modules"), path.Join(home, "bin", "native-image")} {
		locs, err := resolver.FilesByPath(candidate)
		if err != nil || len(locs) == 0 {
			continue
		}
		rc, err := resolver.FileContentsByLocation(locs[0])
		if err != nil {
			continue
		}
		m, err := internal.MatchNamedCaptureGroupsFromReader(nikVersionPattern, rc)
		internal.CloseAndLogError(rc, locs[0].RealPath)
		if err != nil || m == nil || m["version"] == "" {
			continue
		}
		return m["version"] + "+" + strings.TrimLeft(m["build"], "0")
	}
	return release["GRAALVM_VERSION"]
}

// IsVendorRuntime reports whether the runtime a file belongs to is the vendor's JDK/JRE or NIK.
func IsVendorRuntime(resolver file.Resolver, p string) bool {
	home := RuntimeHome(resolver, p)
	if home == "" {
		return false
	}
	return Inspect(resolver, home).Vendor == Vendor
}
