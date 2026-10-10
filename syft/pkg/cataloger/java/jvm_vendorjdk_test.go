package java

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/bell-sw/osv-internal/testfix"

	"github.com/anchore/syft/syft/source"
	"github.com/anchore/syft/syft/source/directorysource"
)

// The JVM release cataloger leaves the vendor's runtimes to the java-vendor-jdk-cataloger, so that a runtime is not
// reported a second time as a generic OpenJDK package; other vendors keep being catalogued.
func TestJvmDistributionCataloger_LeavesVendorRuntimesToTheVendorCataloger(t *testing.T) {
	tests := []struct {
		name     string
		runtime  testfix.Runtime
		wantPkgs []string
	}{
		{name: "jdk 21", runtime: testfix.Runtime{Home: "usr/lib/jvm/jdk-21.0.2-x86_64", Version: "21.0.2+14-LTS", JDK: true}},
		{name: "jdk 8", runtime: testfix.Runtime{Home: "opt/jdk8u402", Version: "1.8.0_402-b07", JDK: true, Java8: true}},
		{name: "nik 23", runtime: testfix.Runtime{Home: "opt/nik-core-openjdk21-23.1.0", Version: "21+37-LTS", JDK: true, NIK: "23.1.0+1"}},
		{name: "zulu 21", runtime: testfix.Runtime{Home: "usr/lib/jvm/zulu21-ca-amd64", Version: "21.0.2+13-LTS", JDK: true, Vendor: "Azul Systems, Inc."}, wantPkgs: []string{"zulu@21.0.2+13-LTS"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			testfix.Write(t, dir, tt.runtime)
			src, err := directorysource.NewFromPath(dir)
			require.NoError(t, err)
			resolver, err := src.FileResolver(source.SquashedScope)
			require.NoError(t, err)
			pkgs, _, err := NewJvmDistributionCataloger().Catalog(context.Background(), resolver)
			require.NoError(t, err)
			var got []string
			for _, p := range pkgs {
				got = append(got, p.Name+"@"+p.Version)
			}
			assert.Equal(t, tt.wantPkgs, got)
		})
	}
}
