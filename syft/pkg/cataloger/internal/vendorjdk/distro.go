package vendorjdk

import bsdistro "github.com/bell-sw/osv-internal/distro"

func isVendorDistro(id string) bool {
	return bsdistro.IsVendor(id)
}
