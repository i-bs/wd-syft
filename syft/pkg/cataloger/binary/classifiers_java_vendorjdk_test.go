package binary

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/source"
	"github.com/anchore/syft/syft/source/directorysource"
)

// A vendor runtime is classified once, from libjvm.so, with the vendor purl and no (Oracle) CPE; the
// generic java-binary classes do not emit a second package for its launcher. Other vendors are untouched.
func TestVendorJDKClassifier(t *testing.T) {
	tests := []struct {
		fixture  string
		wantPkgs []string // "name@version"
		wantPURL string
	}{
		{
			fixture:  "test-fixtures/vendorjdk/jdk-21",
			wantPkgs: []string{"liberica-jdk@21.0.2+14-LTS"},
			wantPURL: "pkg:generic/bellsoft/liberica-jdk@21.0.2%2B14-LTS",
		},
		{
			fixture:  "test-fixtures/vendorjdk/jdk-8",
			wantPkgs: []string{"liberica-jdk@1.8.0_402-b07"},
			wantPURL: "pkg:generic/bellsoft/liberica-jdk@1.8.0_402-b07",
		},
		{
			fixture:  "test-fixtures/vendorjdk/nik-23",
			wantPkgs: []string{"liberica-nik@23.1.0+1"},
			wantPURL: "pkg:generic/bellsoft/liberica-nik@23.1.0%2B1",
		},
		{
			fixture:  "test-fixtures/vendorjdk/macos-21",
			wantPkgs: []string{"liberica-jdk@21.0.2+14-LTS"},
			wantPURL: "pkg:generic/bellsoft/liberica-jdk@21.0.2%2B14-LTS",
		},
		{
			fixture:  "test-fixtures/vendorjdk/windows-21",
			wantPkgs: []string{"liberica-jdk@21.0.2+14-LTS"},
			wantPURL: "pkg:generic/bellsoft/liberica-jdk@21.0.2%2B14-LTS",
		},
		{
			fixture:  "test-fixtures/vendorjdk/zulu-21",
			wantPkgs: []string{"zulu@21.0.2+13-LTS"},
			wantPURL: "pkg:generic/azul/zulu@21.0.2%2B13-LTS",
		},
	}
	for _, tt := range tests {
		t.Run(tt.fixture, func(t *testing.T) {
			src, err := directorysource.NewFromPath(tt.fixture)
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
			p := packages[0]
			assert.Equal(t, pkg.BinaryPkg, p.Type)
			assert.Equal(t, tt.wantPURL, p.PURL)
			for _, c := range p.CPEs {
				assert.NotContains(t, c.Attributes.BindToFmtString(), "oracle:openjdk", "no generic OpenJDK CPE")
			}
			if strings.HasPrefix(p.Name, "liberica") {
				assert.Empty(t, p.CPEs, "no CPE is declared for the vendor runtime (none exists in the NVD dictionary)")
				md, ok := p.Metadata.(pkg.BinarySignature)
				require.True(t, ok)
				require.NotEmpty(t, md.Matches)
				assert.True(t, strings.HasPrefix(md.Matches[0].Classifier, "java-binary-vendor-"), md.Matches[0].Classifier)
				lib := md.Matches[0].Location.RealPath
				assert.True(t, strings.HasSuffix(lib, "/libjvm.so") || strings.HasSuffix(lib, "/libjvm.dylib") || strings.HasSuffix(lib, "/jvm.dll"), lib)
			} else {
				require.NotEmpty(t, p.CPEs, "zulu keeps its CPEs")
			}
		})
	}
}
