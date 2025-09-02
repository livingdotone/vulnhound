/*
filter handles filtering and categorizing CVEs for VulnHound.

Last Updated: 2025-09-01
*/

package filter

import (
	"strings"
)

const (
	ColorCritical = 0xFF0000 // Red
	ColorHigh     = 0xFFA500 // Orange
	ColorMedium   = 0xFFFF00 // Yellow
	ColorLow      = 0x00FF00 // Green
	ColorInfo     = 0x808080 // Gray
)

type CveInfo struct {
	ID          string
	Description string
	Score       float64
	Severity    string
	Color       int
	Category    string
}

func GetSeverity(score float64) (string, int) {
	switch {
	case score >= 9.0:
		return "Critical", ColorCritical
	case score >= 7.0:
		return "High", ColorHigh
	case score >= 4.0:
		return "Medium", ColorMedium
	case score > 0.0:
		return "Low", ColorLow
	default:
		return "Info", ColorInfo
	}
}

func Categorize(desc string) string {
	d := strings.ToLower(desc)

	switch {
	case strings.Contains(d, "sql injection"):
		return "Web/SQLi 🌐"
	case strings.Contains(d, "xss"):
		return "Web/XSS 🌐"
	case strings.Contains(d, "csrf"):
		return "Web/CSRF 🌐"
	case strings.Contains(d, "deserialization"):
		return "Web/Deserialization 🌐"
	case strings.Contains(d, "linux"):
		return "Linux 🐧"
	case strings.Contains(d, "windows"):
		return "Windows 🪟"
	case strings.Contains(d, "macos"), strings.Contains(d, "os x"):
		return "Mac 🍏"
	default:
		return "Other"
	}
}

func BuildCveInfo(id, desc string, score float64) CveInfo {
	severity, color := GetSeverity(score)
	category := Categorize(desc)

	return CveInfo{
		ID:          id,
		Description: desc,
		Score:       score,
		Severity:    severity,
		Color:       color,
		Category:    category,
	}
}
