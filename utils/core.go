package utils

import (
	"strings"
)

// ContainsI func
// case insensitive Contains
func ContainsI(str, substr string) bool {
	return strings.Contains(
		strings.ToLower(str),
		strings.ToLower(substr),
	)
}

// ContainsAnyof function - TBI: use maps
// returns true if string contains anyof specified items
func ContainsAnyof(str string, items []string) bool {
	for _, entry := range items {
		if ContainsI(str, entry) {
			return true
		}
	}
	return false
}
