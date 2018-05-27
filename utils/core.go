package utils

import (
	"strings"
)

// ContainsAnyof function - TBI: use maps
// returns true if string contains anyof specified items
func ContainsAnyof(str string, items []string) bool {
	for _, entry := range items {
		if strings.Contains(str, entry) {
			return true
		}
	}
	return false
}
