/*
filter handles filtering and categorizing CVEs for VulnHound.

Last Updated: 2025-09-01
*/

package filter

import (
	"strings"

	"github.com/livingdotone/vulnhound/internal/fetcher"
)

// CVEType returns the type/category of a CVE based on its description
// Possible return values: "web", "linux", "windows", "other"
func CVEType(desc string) string {
	desc = strings.ToLower(desc)

	// Web-related keywords
	webKeywords := []string{"wordpress", "drupal", "joomla", "php", "xss", "csrf", "rce", "sql"}

	for _, kw := range webKeywords {
		if strings.Contains(desc, kw) {
			return "web"
		}
	}

	// Linux-related keywords
	linuxKeywords := []string{"linux", "kernel", "glibc", "systemd", "ubuntu", "debian", "rpm"}
	for _, kw := range linuxKeywords {
		if strings.Contains(desc, kw) {
			return "linux"
		}
	}

	// Windows-related keywords
	windowsKeywords := []string{"windows", "iis", "microsoft", "powershell", "exchange"}
	for _, kw := range windowsKeywords {
		if strings.Contains(desc, kw) {
			return "windows"
		}
	}

	return "other"
}

func FilterCVEs(cves []fetcher.CVE) []fetcher.CVE {
	var filtered []fetcher.CVE
	for _, cve := range cves {
		if CVEType(cve.Description) == "web" {
			filtered = append(filtered, cve)
		}
	}
	return filtered
}

// FilterByKeywords filters CVEs that contain any of the provided keywords
func FilterByKeywords(cves []fetcher.CVE, keywords []string) []fetcher.CVE {
	var filtered []fetcher.CVE
	for _, cve := range cves {
		desc := strings.ToLower(cve.Description)
		for _, kw := range keywords {
			if strings.Contains(desc, strings.ToLower(kw)) {
				filtered = append(filtered, cve)
				break
			}
		}
	}
	return filtered
}
