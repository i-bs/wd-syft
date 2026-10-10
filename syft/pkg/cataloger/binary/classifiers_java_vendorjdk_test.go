package binary

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/bell-sw/osv-internal/testfix"

	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/source"
	"github.com/anchore/syft/syft/source/directorysource"
)

// The vendor's runtimes are catalogued by the java-vendor-jdk-cataloger; the binary classifiers emit nothing for
// them. Other vendors are untouched.
func TestVendorJDKClassifier(t *testing.T) {
	tests := []struct {
		name     string
		runtime  testfix.Runtime
		wantPkgs []string // "name@version"
		wantPURL string
	}{
		{name: "jdk 21", runtime: testfix.Runtime{Home: "usr/lib/jvm/jdk-21.0.2-x86_64", Version: "21.0.2+14-LTS", JDK: true}},
		{name: "jdk 8", runtime: testfix.Runtime{Home: "opt/jdk8u402", Version: "1.8.0_402-b07", JDK: true, Java8: true}},
		{name: "nik 23", runtime: testfix.Runtime{Home: "opt/nik-core-openjdk21-23.1.0", Version: "21+37-LTS", JDK: true, NIK: "23.1.0+1"}},
		{name: "jdk 21 on macOS", runtime: testfix.Runtime{Home: "Library/Java/JavaVirtualMachines/jdk-21.0.2.jdk", Version: "21.0.2+14-LTS", JDK: true, OS: "darwin"}},
		{name: "jdk 21 on Windows", runtime: testfix.Runtime{Home: "Program Files/Java/jdk-21.0.2", Version: "21.0.2+14-LTS", JDK: true, OS: "windows"}},
		{
			name:     "zulu 21 (another vendor)",
			runtime:  testfix.Runtime{Home: "usr/lib/jvm/zulu21-ca-amd64", Version: "21.0.2+13-LTS", JDK: true, Vendor: "Azul Systems, Inc."},
			wantPkgs: []string{"zulu@21.0.2+13-LTS"},
			wantPURL: "pkg:generic/azul/zulu@21.0.2%2B13-LTS",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			testfix.Write(t, dir, tt.runtime)
			src, err := directorysource.NewFromPath(dir)
			require.NoError(t, err)
			resolver, err := src.FileResolver(source.SquashedScope)
			require.NoError(t, err)

			c := NewClassifierCataloger(DefaultClassifierCatalogerConfig())
			packages, _, err := c.Catalog(context.Background(), resolver)
			require.NoError(t, err)

			var got []string
			for _, p := range packages {
				got = append(got, p.Name+"@"+p.Version)
			}
			require.Equal(t, tt.wantPkgs, got, "one runtime, one package")
			if len(packages) == 0 {
				return
			}
			p := packages[0]
			assert.Equal(t, pkg.BinaryPkg, p.Type)
			assert.Equal(t, tt.wantPURL, p.PURL)
			require.NotEmpty(t, p.CPEs, "another vendor keeps its CPEs")
			for _, c := range p.CPEs {
				assert.NotContains(t, c.Attributes.BindToFmtString(), "oracle:openjdk", "no generic OpenJDK CPE")
			}
		})
	}
}
