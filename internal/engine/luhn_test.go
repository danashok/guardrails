package engine

import "testing"

func TestLuhn_ValidVisa(t *testing.T) {
	if !Luhn("4532015112830366") {
		t.Fatal("expected valid Luhn for known-good Visa number")
	}
}

func TestLuhn_StripsDashesAndSpaces(t *testing.T) {
	if !Luhn("4532-0151-1283-0366") {
		t.Fatal("expected dashes to be stripped")
	}
	if !Luhn("4532 0151 1283 0366") {
		t.Fatal("expected spaces to be stripped")
	}
}

func TestLuhn_InvalidNumber(t *testing.T) {
	if Luhn("1234567890123456") {
		t.Fatal("expected Luhn to fail on contrived bad number")
	}
}

func TestLuhn_TooShort(t *testing.T) {
	if Luhn("12345") {
		t.Fatal("expected Luhn to reject under-13-digit input")
	}
}

func TestLuhn_TooLong(t *testing.T) {
	if Luhn("12345678901234567890") {
		t.Fatal("expected Luhn to reject over-19-digit input")
	}
}

func TestLuhn_NonDigit(t *testing.T) {
	if Luhn("4532-01a1-1283-0366") {
		t.Fatal("expected non-digit to fail Luhn")
	}
}
