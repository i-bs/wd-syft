package java

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/source"
	"github.com/anchore/syft/syft/source/directorysource"
)

// The JVM release cataloger leaves the vendor's runtimes to the binary classifier (java-binary-vendor-jdk) so that
// the runtime is not reported a second time as a generic OpenJDK package; other vendors keep being catalogued.
func TestJvmDistributionCataloger_LeavesVendorRuntimesToTheClassifier(t *testing.T) {
	tests := []struct {
		fixture  string
		wantPkgs []string
	}{
		{fixture: "../binary/test-fixtures/vendorjdk/jdk-21", wantPkgs: nil},
		{fixture: "../binary/test-fixtures/vendorjdk/jdk-8", wantPkgs: nil},
		{fixture: "../binary/test-fixtures/vendorjdk/nik-23", wantPkgs: nil},
		{fixture: "../binary/test-fixtures/vendorjdk/zulu-21", wantPkgs: []string{"zulu@21.0.2+13-LTS"}},
	}
	for _, tt := range tests {
		t.Run(tt.fixture, func(t *testing.T) {
			src, err := directorysource.NewFromPath(tt.fixture)
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
