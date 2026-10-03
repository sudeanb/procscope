package syscalls

import "testing"

func TestKnownNumbers(t *testing.T) {
	if Name(59) != "execve" || Name(257) != "openat" || Name(1) != "write" {
		t.Fatal("core syscalls misnamed")
	}
	if Name(999999) != "sys_999999" {
		t.Fatal("unknown numbers must fall back to sys_<n>")
	}
	if Count() < 200 {
		t.Fatalf("table suspiciously small: %d", Count())
	}
	if !Known(62) || Known(1000) {
		t.Fatal("Known inconsistent with table")
	}
}
