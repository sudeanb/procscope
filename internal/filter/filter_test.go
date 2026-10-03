package filter

import "testing"

func TestParseEmptyMatchesAll(t *testing.T) {
	f, err := Parse("")
	if err != nil {
		t.Fatal(err)
	}
	if !f.MatchSyscall(1, "any", "read", "/x") {
		t.Fatal("empty filter must match everything")
	}
}

func TestParseErrors(t *testing.T) {
	for _, bad := range []string{"nonsense", "pid=abc", "weird=1"} {
		if _, err := Parse(bad); err == nil {
			t.Errorf("Parse(%q) must fail", bad)
		}
	}
}

func TestMatchPIDAndSyscallGlob(t *testing.T) {
	f, err := Parse("pid=42 syscall=open*")
	if err != nil {
		t.Fatal(err)
	}
	if !f.MatchSyscall(42, "cat", "openat", "/etc/passwd") {
		t.Fatal("want match")
	}
	if f.MatchSyscall(43, "cat", "openat", "/etc/passwd") {
		t.Fatal("wrong pid matched")
	}
	if f.MatchSyscall(42, "cat", "close", "/etc/passwd") {
		t.Fatal("non-open matched")
	}
}

func TestMatchPathSemantics(t *testing.T) {
	f, _ := Parse("path=/etc/**")
	if !f.MatchSyscall(1, "cat", "openat", "/etc/passwd") {
		t.Fatal("** must cross slashes")
	}
	if f.MatchSyscall(1, "cat", "openat", "/var/log/x") {
		t.Fatal("wrong prefix matched")
	}
	nameOnly, _ := Parse("path=passwd")
	if !nameOnly.MatchSyscall(1, "cat", "openat", "/etc/passwd") {
		t.Fatal("bare name pattern matches the basename")
	}
	conf, _ := Parse("path=*.conf")
	if !conf.MatchSyscall(1, "cat", "openat", "/etc/hosts.conf") {
		t.Fatal("glob basename should match")
	}
}

func TestMatchComm(t *testing.T) {
	f, _ := Parse("comm=cu*")
	if !f.MatchSyscall(1, "curl", "read", "") {
		t.Fatal("comm glob failed")
	}
	if f.MatchSyscall(1, "cat", "read", "") {
		t.Fatal("wrong comm matched")
	}
}
