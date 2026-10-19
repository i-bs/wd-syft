package java_test

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	_ "modernc.org/sqlite" // the default cataloger set includes the rpm cataloger

	osvinternal "github.com/bell-sw/osv-internal"
	"github.com/bell-sw/osv-internal/testfix"
	osvjdk "github.com/bell-sw/osv-internal/vendorjdk"

	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source/directorysource"
)

// The runtimes of these tests are built by the module's testfix package.

// catalog writes the files (paths relative to the root, forward slashes) and the runtimes into a temporary
// directory and runs the full default cataloging pipeline over it (binary classifiers, JVM release cataloger, vendor
// JDK cataloger, relationship exclusions, CPE generation).
func catalog(t *testing.T, files map[string][]byte, runtimes ...testfix.Runtime) *sbom.SBOM {
	t.Helper()
	dir := t.TempDir()
	testfix.WriteFiles(t, dir, files)
	testfix.Write(t, dir, runtimes...)
	src, err := directorysource.NewFromPath(dir)
	require.NoError(t, err)
	s, err := syft.CreateSBOM(context.Background(), src, syft.DefaultCreateSBOMConfig())
	require.NoError(t, err)
	return s
}

// upperCaseWindows returns the files of a Windows runtime with upper-case names below bin/ (BIN/SERVER/JVM.DLL,
// BIN/JAVA.EXE), as installers sometimes leave them.
func upperCaseWindows(rt testfix.Runtime) map[string][]byte {
	out := map[string][]byte{}
	for p, data := range rt.Files() {
		if rel, ok := strings.CutPrefix(p, rt.Home+"/bin/"); ok {
			p = rt.Home + "/BIN/" + strings.ToUpper(rel)
		}
		out[p] = data
	}
	return out
}

func packagesOfType(s *sbom.SBOM, t pkg.Type) []pkg.Package {
	var out []pkg.Package
	for p := range s.Artifacts.Packages.Enumerate(t) {
		out = append(out, p)
	}
	return out
}

// runtimePackages drops the jar archives syft's java archive cataloger reports from inside a runtime (rt.jar of a
// Java 8 install is cataloged as java-archive "rt", as for every other vendor); everything else describes the runtime.
func runtimePackages(s *sbom.SBOM) []pkg.Package {
	var out []pkg.Package
	for _, p := range s.Artifacts.Packages.Sorted() {
		if p.Type == pkg.JavaPkg {
			continue
		}
		out = append(out, p)
	}
	return out
}

// underHome reports whether a resolver path lies below a runtime home (directory sources yield relative paths).
func underHome(p, home string) bool {
	return strings.HasPrefix(strings.TrimPrefix(p, "/"), strings.TrimPrefix(home, "/")+"/")
}

func describe(pkgs []pkg.Package) []string {
	var out []string
	for _, p := range pkgs {
		out = append(out, string(p.Type)+":"+p.Name+"@"+p.Version+" purl="+p.PURL)
	}
	return out
}

// The first JDK and NIK families of the module: the fixtures are theirs.
var (
	jdkProduct    = testfix.Product(osvinternal.KindJDK)
	nikProduct    = testfix.Product(osvinternal.KindNIK)
	jdkType       = pkg.VendorRuntimeType(jdkProduct.Family)
	nikType       = pkg.VendorRuntimeType(nikProduct.Family)
	jdkPURLPrefix = "pkg:generic/" + osvjdk.PURLNamespace + "/" + jdkProduct.PURLName + "@"
	nikPURLPrefix = "pkg:generic/" + osvjdk.PURLNamespace + "/" + nikProduct.PURLName + "@"
)

// vendorRuntimePackages are the packages of every runtime type of the module.
func vendorRuntimePackages(s *sbom.SBOM) []pkg.Package {
	var out []pkg.Package
	for _, t := range pkg.VendorRuntimeTypes() {
		out = append(out, packagesOfType(s, t)...)
	}
	return out
}

// A vendor runtime is reported once, as the vendor's JDK (purl from the shared module, no generic CPE), and the
// generic java classifiers / JVM release cataloger do not emit a second package for the same runtime.
func TestVendorJDKCataloger_OneRuntimeOnePackage(t *testing.T) {
	tests := []struct {
		name        string
		runtime     testfix.Runtime
		files       map[string][]byte // instead of runtime
		wantVariant string
		wantVersion string
		wantHome    string
		wantRelease string
	}{
		{
			name:        "jdk 21 (release IMPLEMENTOR + libjvm.so)",
			runtime:     testfix.Runtime{Home: "usr/lib/jvm/jdk-21.0.2-x86_64", Version: "21.0.2+14-LTS", JDK: true},
			wantVariant: osvjdk.VariantJDK,
			wantVersion: "21.0.2+14",
			wantHome:    "/usr/lib/jvm/jdk-21.0.2-x86_64",
			wantRelease: "vendor-release-type=psu",
		},
		{
			name:        "jdk 21 CSPU (four-component version passed through unchanged)",
			runtime:     testfix.Runtime{Home: "opt/jdk-21.0.12.1", Version: "21.0.12.1+1-LTS", JDK: true},
			wantVariant: osvjdk.VariantJDK,
			wantVersion: "21.0.12.1+1",
			wantHome:    "/opt/jdk-21.0.12.1",
			wantRelease: "vendor-release-type=cspu",
		},
		{
			name:        "jdk 8 (rt.jar manifest + libjvm.so, no IMPLEMENTOR)",
			runtime:     testfix.Runtime{Home: "opt/jdk8u402", Version: "1.8.0_402-b07", JDK: true, Java8: true},
			wantVariant: osvjdk.VariantJDK,
			wantVersion: "8u402+7",
			wantHome:    "/opt/jdk8u402",
		},
		{
			name:        "jre 21 lite",
			runtime:     testfix.Runtime{Home: "opt/jre-21.0.2-lite", Version: "21.0.2+14-LTS"},
			wantVariant: osvjdk.VariantJRELite,
			wantVersion: "21.0.2+14",
			wantHome:    "/opt/jre-21.0.2-lite",
		},
		{
			name:        "jdk 21 full",
			runtime:     testfix.Runtime{Home: "opt/jdk-21.0.2-full", Version: "21.0.2+14-LTS", JDK: true, Full: true},
			wantVariant: osvjdk.VariantJDKFull,
			wantVersion: "21.0.2+14",
			wantHome:    "/opt/jdk-21.0.2-full",
		},
		{
			name:        "jdk 21 on macOS (libjvm.dylib in a .jdk bundle)",
			runtime:     testfix.Runtime{Home: "Library/Java/JavaVirtualMachines/jdk-21.0.2.jdk", Version: "21.0.2+14-LTS", JDK: true, OS: "darwin"},
			wantVariant: osvjdk.VariantJDK,
			wantVersion: "21.0.2+14",
			wantHome:    "/Library/Java/JavaVirtualMachines/jdk-21.0.2.jdk",
		},
		{
			name:        "jdk 21 on Windows (bin/server/jvm.dll)",
			runtime:     testfix.Runtime{Home: "Program Files/Java/jdk-21.0.2", Version: "21.0.2+14-LTS", JDK: true, OS: "windows"},
			wantVariant: osvjdk.VariantJDK,
			wantVersion: "21.0.2+14",
			wantHome:    "/Program Files/Java/jdk-21.0.2",
		},
		{
			name:        "jdk 21 on Windows with upper-case file names (BIN/SERVER/JVM.DLL)",
			files:       upperCaseWindows(testfix.Runtime{Home: "Program Files/Java/JDK-21.0.2", Version: "21.0.2+14-LTS", JDK: true, OS: "windows"}),
			wantVariant: osvjdk.VariantJDK,
			wantVersion: "21.0.2+14",
			wantHome:    "/Program Files/Java/JDK-21.0.2",
		},
		{
			name:        "jdk 21 from the release file alone",
			runtime:     testfix.Runtime{Home: "opt/jdk-21.0.2", Version: "21.0.2+14-LTS", JDK: true, NoLibrary: true},
			wantVariant: osvjdk.VariantJDK,
			wantVersion: "21.0.2+14",
			wantHome:    "/opt/jdk-21.0.2",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var s *sbom.SBOM
			if tt.files != nil {
				s = catalog(t, tt.files)
			} else {
				s = catalog(t, nil, tt.runtime)
			}
			all := runtimePackages(s)
			require.Len(t, all, 1, "exactly one package for one runtime: %v", describe(all))

			p := all[0]
			assert.Equal(t, jdkType, p.Type)
			assert.Equal(t, tt.wantVariant, p.Name)
			assert.Equal(t, tt.wantVersion, p.Version)
			assert.Equal(t, osvjdk.PURL(jdkProduct.Family, tt.wantVariant, tt.wantVersion), p.PURL)
			assert.True(t, strings.HasPrefix(p.PURL, jdkPURLPrefix), p.PURL)
			assert.Contains(t, p.PURL, "package_type="+tt.wantVariant)
			assert.Empty(t, p.CPEs, "a vendor runtime must not carry a generic (oracle:openjdk) or generated CPE")
			assert.Equal(t, pkg.Java, p.Language)
			assert.Equal(t, "java-vendor-jdk-cataloger", p.FoundBy)

			md, ok := p.Metadata.(pkg.JavaVMInstallation)
			require.True(t, ok, "metadata type %T", p.Metadata)
			assert.Equal(t, osvjdk.Vendor, md.Release.Implementor)
			if tt.wantRelease != "" {
				assert.Equal(t, tt.wantRelease, md.Release.BuildInfo)
			}
			assert.NotEmpty(t, md.Files)
			for _, loc := range p.Locations.ToSlice() {
				assert.True(t, underHome(loc.RealPath, tt.wantHome), loc.RealPath)
			}
			for _, f := range md.Files {
				assert.True(t, underHome(f, tt.wantHome), f)
			}
		})
	}
}

// Other vendors keep today's behaviour: Zulu is reported by the generic catalogers with its own CPEs and never as the
// vendor's JDK.
func TestVendorJDKCataloger_OtherVendorsUntouched(t *testing.T) {
	s := catalog(t, nil, testfix.Runtime{Home: "usr/lib/jvm/zulu21-ca-amd64", Version: "21.0.2+13-LTS", JDK: true, Vendor: "Azul Systems, Inc."})
	assert.Empty(t, packagesOfType(s, jdkType), "a Zulu runtime must never be reported as the vendor's JDK")

	binaries := packagesOfType(s, pkg.BinaryPkg)
	require.NotEmpty(t, binaries, "the generic java catalogers must still report the Zulu runtime")
	var sawZulu bool
	for _, p := range binaries {
		if p.Name != "zulu" {
			continue
		}
		sawZulu = true
		assert.Equal(t, "21.0.2+13-LTS", p.Version)
		var cpes []string
		for _, c := range p.CPEs {
			cpes = append(cpes, c.Attributes.BindToFmtString())
		}
		assert.Contains(t, strings.Join(cpes, " "), "cpe:2.3:a:azul:zulu:", "zulu keeps its CPEs")
	}
	assert.True(t, sawZulu, "expected a zulu binary package, got %v", describe(binaries))
}

// A Native Image Kit is reported once, as NIK (bundle name, NIK version, the NIK purl), never as a JDK, and the
// bundled Java line is kept in the metadata for the "<NIK family>:<nik major>-<java major>" ecosystem.
func TestVendorJDKCataloger_NIK(t *testing.T) {
	tests := []struct {
		name        string
		runtime     testfix.Runtime
		wantBundle  string
		wantVersion string
		wantJava    string
		wantHome    string
	}{
		{
			name:        "nik 23.1.0 core (java.vendor.version string)",
			runtime:     testfix.Runtime{Home: "opt/nik-core-openjdk21-23.1.0", Version: "21+37-LTS", JDK: true, NIK: "23.1.0+1"},
			wantBundle:  osvjdk.BundleCore,
			wantVersion: "23.1.0+1",
			wantJava:    "21+37",
			wantHome:    "/opt/nik-core-openjdk21-23.1.0",
		},
		{
			name: "graalvm-based runtime without the vendor version string (GRAALVM_VERSION fallback)",
			runtime: testfix.Runtime{Home: "opt/nik-23", Version: "21.0.2+14-LTS", JDK: true, NIK: "23.1.2",
				Extra: map[string]string{"lib/modules": "\x00" + osvinternal.RuntimeVendor + "\x00", "bin/native-image": "#!/bin/sh\n"}},
			wantBundle:  osvjdk.BundleCore,
			wantVersion: "23.1.2",
			wantJava:    "21.0.2+14",
			wantHome:    "/opt/nik-23",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := catalog(t, nil, tt.runtime)
			assert.Empty(t, describe(packagesOfType(s, jdkType)), "a NIK must never be reported as a JDK")
			all := runtimePackages(s)
			require.Len(t, all, 1, "exactly one package for one runtime: %v", describe(all))

			p := all[0]
			assert.Equal(t, nikType, p.Type)
			assert.Equal(t, tt.wantBundle, p.Name)
			assert.Equal(t, tt.wantVersion, p.Version)
			assert.Equal(t, osvjdk.PURL(nikProduct.Family, tt.wantBundle, tt.wantVersion), p.PURL)
			assert.True(t, strings.HasPrefix(p.PURL, nikPURLPrefix), p.PURL)
			assert.Empty(t, p.CPEs)
			assert.Equal(t, "java-vendor-jdk-cataloger", p.FoundBy)

			md, ok := p.Metadata.(pkg.JavaVMInstallation)
			require.True(t, ok, "metadata type %T", p.Metadata)
			assert.Equal(t, osvjdk.Vendor, md.Release.Implementor)
			assert.Equal(t, tt.wantJava, md.Release.JavaVersion)
			for _, loc := range p.Locations.ToSlice() {
				assert.True(t, underHome(loc.RealPath, tt.wantHome), loc.RealPath)
			}
		})
	}
}

// A runtime of any product family of the module is reported with the family's own package type and purl.
func TestVendorJDKCataloger_EveryFamily(t *testing.T) {
	for _, product := range osvinternal.Products {
		t.Run(product.Family, func(t *testing.T) {
			rt := testfix.Runtime{Product: product.Family, Home: "opt/runtime", Version: "21.0.2+14-LTS", JDK: true}
			if product.Kind == osvinternal.KindNIK {
				rt.NIK = "23.1.0+1"
			}
			s := catalog(t, nil, rt)
			all := runtimePackages(s)
			require.Len(t, all, 1, "exactly one package for one runtime: %v", describe(all))
			p := all[0]
			assert.Equal(t, pkg.VendorRuntimeType(product.Family), p.Type)
			assert.Equal(t, osvjdk.PURL(product.Family, p.Name, p.Version), p.PURL)
			assert.Empty(t, p.CPEs)
		})
	}
}

// Runtimes that are not the vendor's produce no vendor package: vendor mismatches between the JVM library and the
// structured sources, a stripped release file without binary evidence.
func TestVendorJDKCataloger_NegativeCases(t *testing.T) {
	for _, tc := range []struct {
		name    string
		runtime testfix.Runtime
	}{
		{"release of another vendor, vendor library", testfix.Runtime{Home: "opt/jdk-x", Version: "21.0.2+13-LTS", JDK: true, Vendor: "Azul Systems, Inc.", LibraryVendor: osvinternal.RuntimeVendor}},
		{"java 8 manifest of another vendor, vendor library", testfix.Runtime{Home: "opt/jdk8", Version: "1.8.0_402-b07", JDK: true, Java8: true, Vendor: "Oracle Corporation", LibraryVendor: osvinternal.RuntimeVendor}},
		{"stripped release file, no library", testfix.Runtime{Home: "opt/jdk", Version: "21.0.2+14-LTS", StrippedRelease: true, NoLibrary: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := catalog(t, nil, tc.runtime)
			assert.Empty(t, describe(vendorRuntimePackages(s)))
		})
	}
}

// On the vendor's distributions the runtime under /usr/lib/jvm is an apk package covered by the apk ecosystem: the
// vendor JDK cataloger leaves it alone and the generic classifiers do not resurrect it either.
func TestVendorJDKCataloger_ApkManagedRuntimeSkipped(t *testing.T) {
	s := catalog(t,
		map[string][]byte{"etc/os-release": []byte(testfix.OSRelease(osvinternal.EcosystemLinux, "23"))},
		testfix.Runtime{Home: "usr/lib/jvm/jdk21-lite", Version: "21.0.2+14-LTS", JDK: true, StrippedRelease: true},
	)
	require.NotNil(t, s.Artifacts.LinuxDistribution)
	assert.Equal(t, osvinternal.OSReleaseIDLinux, s.Artifacts.LinuxDistribution.ID)
	assert.Empty(t, describe(vendorRuntimePackages(s)))
	assert.Empty(t, describe(packagesOfType(s, pkg.BinaryPkg)), "no generic java package for a vendor runtime")
}

// File names are matched case-insensitively: the JVM library of the upper-case Windows layout anchors the package.
func TestVendorJDKCataloger_CaseInsensitiveNames(t *testing.T) {
	s := catalog(t, upperCaseWindows(testfix.Runtime{Home: "Program Files/Java/JDK-21.0.2", Version: "21.0.2+14-LTS", JDK: true, OS: "windows"}))
	libs := packagesOfType(s, jdkType)
	require.Len(t, libs, 1)
	var paths []string
	for _, loc := range libs[0].Locations.ToSlice() {
		paths = append(paths, loc.RealPath)
	}
	assert.Contains(t, strings.Join(paths, " "), "BIN/SERVER/JVM.DLL")
}
