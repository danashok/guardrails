package engine

import "strings"

// Luhn validates a credit-card-shaped string using the Luhn checksum.
// Strips spaces and dashes; returns false for input outside 13–19 digits
// or containing non-digits after stripping.
func Luhn(card string) bool {
	stripped := strings.NewReplacer(" ", "", "-", "").Replace(card)
	n := len(stripped)
	if n < 13 || n > 19 {
		return false
	}
	total := 0
	for i := 0; i < n; i++ {
		ch := stripped[n-1-i]
		if ch < '0' || ch > '9' {
			return false
		}
		d := int(ch - '0')
		if i%2 == 1 {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		total += d
	}
	return total%10 == 0
}
