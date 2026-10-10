package java

import (
	"context"
	"path"
	"sort"
	"strconv"
	"strings"

	"github.com/go-viper/mapstructure/v2"

	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/linux"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/vendorjdk"
)

const vendorJDKCatalogerName = "java-vendor-jdk-cataloger"

// releaseTypeKey prefixes the release type in JavaVMRelease.BuildInfo: "vendor-release-type=cspu".
const releaseTypeKey = "vendor-release-type"

// anchorNames are the JVM libraries a runtime is identified from (Linux, macOS and Windows layouts) and
// releaseName the release file of the fallback path. File names are compared case-insensitively: Windows
// file systems are, and a runtime copied from one may carry JVM.DLL or RELEASE. syft's indexed globs are
// case-sensitive, so the candidates are selected from the resolver's locations by lower-cased base name.
var anchorNames = map[string]bool{"libjvm.so": true, "libjvm.dylib": true, "jvm.dll": true}

const releaseName = "release"

// runtimeCandidates returns the JVM library and release file locations of the source, each sorted by path.
func runtimeCandidates(ctx context.Context, resolver file.Resolver) (libs, releases []file.Location) {
	for loc := range resolver.AllLocations(ctx) {
		switch base := strings.ToLower(path.Base(loc.RealPath)); {
		case anchorNames[base]:
			libs = append(libs, loc)
		case base == releaseName:
			releases = append(releases, loc)
		}
	}
	sort.Slice(libs, func(i, j int) bool { return libs[i].RealPath < libs[j].RealPath })
	sort.Slice(releases, func(i, j int) bool { return releases[i].RealPath < releases[j].RealPath })
	return libs, releases
}

// NewVendorJDKCataloger returns a cataloger that reports standalone vendor runtimes with the identity of the shared
// osv-internal module: JDK/JRE as pkg.VendorJdkPkg (purl pkg:generic/<namespace>/<jdk name>, name = variant,
// version in product notation, ecosystem "<JDK family>:<major>") and the Native Image Kit as pkg.VendorNikPkg
// (pkg:generic/<namespace>/<nik name>, name = bundle, ecosystem "<NIK family>:<nik major>-<java major>"); a NIK is
// reported once, as NIK. Detection is the module's, anchored on the JVM library with the release file as fallback;
// other vendors are left to the JVM release cataloger and the binary classifiers, and runtimes under /usr/lib/jvm on
// the vendor distributions to apk. The packages carry no CPE (see cpegenerate).
func NewVendorJDKCataloger() pkg.Cataloger {
	return vendorJDKCataloger{}
}

type vendorJDKCataloger struct{}

func (c vendorJDKCataloger) Name() string {
	return vendorJDKCatalogerName
}

func (c vendorJDKCataloger) Catalog(ctx context.Context, resolver file.Resolver) ([]pkg.Package, []artifact.Relationship, error) {
	release := linux.IdentifyRelease(resolver)

	// anchor: every JVM library in the source
	libs, releases := runtimeCandidates(ctx, resolver)

	runtimes := map[string]*vendorjdk.Runtime{}
	anchors := map[string]file.Location{}
	for _, loc := range libs {
		rt, err := vendorjdk.Detect(resolver, loc)
		if err != nil {
			log.WithFields("path", loc.RealPath, "error", err).Debug("unable to inspect JVM library")
			continue
		}
		if rt == nil {
			continue
		}
		if _, seen := runtimes[rt.Home]; seen {
			continue
		}
		runtimes[rt.Home] = rt
		anchors[rt.Home] = loc
	}

	// fallback: a release file declaring the vendor whose JVM library is unreadable or absent
	for _, loc := range releases {
		home := vendorjdk.ToFSName(path.Dir(loc.RealPath))
		if _, seen := runtimes[home]; seen {
			continue
		}
		rt, err := vendorjdk.ProbeHome(resolver, home)
		if err != nil {
			log.WithFields("home", home, "error", err).Debug("unable to inspect JVM home")
			continue
		}
		if rt != nil {
			runtimes[rt.Home] = rt
		}
	}

	var homes []string
	for home := range runtimes {
		homes = append(homes, home)
	}
	sort.Strings(homes)

	var pkgs []pkg.Package
	for _, home := range homes {
		rt := runtimes[home]
		if vendorjdk.ManagedByAPK(release, home) {
			log.WithFields("home", home, "distro", release.ID).Trace("vendor runtime is an apk package; left to the apk ecosystem")
			continue
		}
		var anchor *file.Location
		if loc, ok := anchors[home]; ok {
			anchor = &loc
		}
		pkgs = append(pkgs, newRuntimePackage(resolver, rt, anchor))
	}
	return pkgs, nil, nil
}

func newRuntimePackage(resolver file.Resolver, rt *vendorjdk.Runtime, libjvm *file.Location) pkg.Package {
	locations := file.NewLocationSet()
	var releaseLoc *file.Location
	if locs, err := resolver.FilesByPath(vendorjdk.ToResolverPath(path.Join(rt.Home, "release"))); err == nil && len(locs) > 0 {
		releaseLoc = &locs[0]
	}
	if libjvm == nil && rt.LibJVM != "" {
		if locs, err := resolver.FilesByPath(vendorjdk.ToResolverPath(rt.LibJVM)); err == nil && len(locs) > 0 {
			libjvm = &locs[0]
		}
	}
	switch {
	case releaseLoc != nil && libjvm != nil:
		locations.Add(releaseLoc.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation))
		locations.Add(libjvm.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.SupportingEvidenceAnnotation))
	case releaseLoc != nil:
		locations.Add(releaseLoc.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation))
	case libjvm != nil:
		locations.Add(libjvm.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation))
	}

	typ := pkg.VendorJdkPkg
	if rt.IsNIK {
		typ = pkg.VendorNikPkg
	}
	p := pkg.Package{
		Name:      rt.Variant,
		Version:   rt.Version,
		Locations: locations,
		Language:  pkg.Java,
		Type:      typ,
		PURL:      rt.PURL(),
		Licenses:  pkg.NewLicenseSet(),
		Metadata: pkg.JavaVMInstallation{
			Release: runtimeReleaseInfo(rt),
			Files:   vendorjdk.OwnedFiles(resolver, rt.Home),
		},
	}
	p.SetID()
	return p
}

func runtimeReleaseInfo(rt *vendorjdk.Runtime) pkg.JavaVMRelease {
	data := make(map[string]any, len(rt.Release))
	for k, v := range rt.Release {
		data[k] = v
	}
	if mods, ok := rt.Release["MODULES"]; ok {
		data["MODULES"] = splitFields(mods)
	}
	var ri pkg.JavaVMRelease
	if err := mapstructure.Decode(data, &ri); err != nil {
		log.WithFields("home", rt.Home, "error", err).Debug("unable to decode release info")
	}
	if ri.Implementor == "" {
		ri.Implementor = rt.Vendor
	}
	if ri.JavaRuntimeVersion == "" {
		ri.JavaRuntimeVersion = rt.Version
	}
	if ri.JavaVersion == "" || rt.IsNIK {
		// the bundled Java line; consumers derive the "<NIK family>:<nik major>-<java major>" ecosystem from it
		ri.JavaVersion = strconv.Itoa(rt.Major)
		if rt.JavaVersion != "" {
			ri.JavaVersion = rt.JavaVersion
		}
	}
	if ri.BuildInfo == "" && !rt.IsNIK {
		// the module's release type of a JDK update (psu, cpu, cspu); the release file has no field for it,
		// so it is exposed through the otherwise unused BUILD_INFO slot of the JVM release metadata
		if t := rt.ReleaseType.String(); t != "" && t != "unknown" {
			ri.BuildInfo = releaseTypeKey + "=" + t
		}
	}
	return ri
}

func splitFields(s string) []string {
	return strings.Fields(s)
}
