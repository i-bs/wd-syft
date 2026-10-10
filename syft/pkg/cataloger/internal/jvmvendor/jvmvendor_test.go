package jvmvendor

import (
	"bytes"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/source"
	"github.com/anchore/syft/syft/source/directorysource"
)

const fixtures = "../../binary/test-fixtures/vendorjdk"

func TestScanLibrary(t *testing.T) {
	vendor, version, err := ScanLibrary(strings.NewReader("abc\x00BellSoft\x00OpenJDK 64-Bit Server VM (21.0.2+14-LTS) for linux-amd64 JRE (21.0.2+14-LTS), built on\x00"))
	require.NoError(t, err)
	assert.Equal(t, Vendor, vendor)
	assert.Equal(t, "21.0.2+14-LTS", version)

	vendor, version, err = ScanLibrary(strings.NewReader("abc\x00Azul Systems, Inc.\x00JRE (21.0.2+13-LTS)\x00"))
	require.NoError(t, err)
	assert.Equal(t, "", vendor)
	assert.Equal(t, "21.0.2+13-LTS", version)

	vendor, _, err = ScanLibrary(strings.NewReader("BellSoft is mentioned without NUL delimiters"))
	require.NoError(t, err)
	assert.Equal(t, "", vendor)

	// a constant straddling the chunk boundary is still found
	big := append(bytes.Repeat([]byte{'x'}, scanChunkSize-4), []byte("\x00BellSoft\x00JRE (1.8.0_402-b07)\x00")...)
	vendor, version, err = ScanLibrary(bytes.NewReader(big))
	require.NoError(t, err)
	assert.Equal(t, Vendor, vendor)
	assert.Equal(t, "1.8.0_402-b07", version)

	// security-only builds: a CSPU carries a fourth version component, a CPU five (the previous update plus ".0.1");
	// the banner version is taken whole, never truncated
	vendor, version, err = ScanLibrary(strings.NewReader("\x00BellSoft\x00OpenJDK 64-Bit Server VM (21.0.12.1+1-LTS) for linux-amd64 JRE (21.0.12.1+1-LTS), built on\x00"))
	require.NoError(t, err)
	assert.Equal(t, Vendor, vendor)
	assert.Equal(t, "21.0.12.1+1-LTS", version)

	_, version, err = ScanLibrary(strings.NewReader("\x00BellSoft\x00OpenJDK 64-Bit Server VM (21.0.9.0.1+1-LTS) for linux-amd64 JRE (21.0.9.0.1+1-LTS), built on\x00"))
	require.NoError(t, err)
	assert.Equal(t, "21.0.9.0.1+1-LTS", version)

	vendor, version, err = ScanLibrary(strings.NewReader("\x00BellSoft\x00JRE (1.8.0_504-b01)\x00"))
	require.NoError(t, err)
	assert.Equal(t, Vendor, vendor)
	assert.Equal(t, "1.8.0_504-b01", version)
}

func resolverFor(t *testing.T, dir string) file.Resolver {
	t.Helper()
	src, err := directorysource.NewFromPath(dir)
	require.NoError(t, err)
	r, err := src.FileResolver(source.SquashedScope)
	require.NoError(t, err)
	return r
}

func TestInspect(t *testing.T) {
	tests := []struct {
		fixture     string
		file        string
		wantHome    string
		wantVendor  string
		wantVersion string
		wantNIK     bool
		wantNIKVer  string
	}{
		{"jdk-21", "/usr/lib/jvm/jdk-21.0.2-bellsoft-x86_64/lib/server/libjvm.so", "/usr/lib/jvm/jdk-21.0.2-bellsoft-x86_64", Vendor, "21.0.2+14-LTS", false, ""},
		{"jdk-21", "/usr/lib/jvm/jdk-21.0.2-bellsoft-x86_64/bin/java", "/usr/lib/jvm/jdk-21.0.2-bellsoft-x86_64", Vendor, "21.0.2+14-LTS", false, ""},
		{"jdk-8", "/opt/jdk8u402/jre/lib/amd64/server/libjvm.so", "/opt/jdk8u402", Vendor, "1.8.0_402-b07", false, ""},
		{"jdk-8", "/opt/jdk8u402/jre/bin/java", "/opt/jdk8u402", Vendor, "1.8.0_402-b07", false, ""},
		{"zulu-21", "/usr/lib/jvm/zulu21-ca-amd64/bin/java", "/usr/lib/jvm/zulu21-ca-amd64", "", "21.0.2+13-LTS", false, ""},
		{"nik-23", "/opt/bellsoft-liberica-vm-core-openjdk21-23.1.0/lib/server/libjvm.so", "/opt/bellsoft-liberica-vm-core-openjdk21-23.1.0", Vendor, "21+37-LTS", true, "23.1.0+1"},
		{"macos-21", "/Library/Java/JavaVirtualMachines/jdk-21.0.2.jdk/lib/server/libjvm.dylib", "/Library/Java/JavaVirtualMachines/jdk-21.0.2.jdk", Vendor, "21.0.2+14-LTS", false, ""},
		{"windows-21", "/Program Files/BellSoft/jdk-21.0.2/bin/server/jvm.dll", "/Program Files/BellSoft/jdk-21.0.2", Vendor, "21.0.2+14-LTS", false, ""},
	}
	for _, tt := range tests {
		t.Run(tt.fixture+" "+tt.file, func(t *testing.T) {
			r := resolverFor(t, fixtures+"/"+tt.fixture)
			home := RuntimeHome(r, tt.file)
			assert.Equal(t, tt.wantHome, home)
			rt := Inspect(r, home)
			assert.Equal(t, tt.wantVendor, rt.Vendor)
			assert.Equal(t, tt.wantVersion, rt.Version)
			assert.Equal(t, tt.wantNIK, rt.NIK)
			assert.Equal(t, tt.wantNIKVer, rt.NIKVersion)
			assert.Equal(t, tt.wantVendor == Vendor, IsVendorRuntime(r, tt.file))
		})
	}
}
