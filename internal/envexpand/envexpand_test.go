package envexpand

import (
	"errors"
	"testing"
)

func TestExpand_ReplacesSetVariables(t *testing.T) {
	t.Setenv("ENVEXPAND_TEST_ONE", "first")
	t.Setenv("ENVEXPAND_TEST_TWO", "second")

	got, err := Expand("a=${ENVEXPAND_TEST_ONE} b=${ENVEXPAND_TEST_TWO} c=${ENVEXPAND_TEST_ONE}")
	if err != nil {
		t.Fatalf("Expand() error = %v", err)
	}
	want := "a=first b=second c=first"
	if got != want {
		t.Errorf("Expand() = %q, want %q", got, want)
	}
}

func TestExpand_NoReferencesIsPassthrough(t *testing.T) {
	const in = "plain: value\nnested:\n  key: 42\n"
	got, err := Expand(in)
	if err != nil {
		t.Fatalf("Expand() error = %v", err)
	}
	if got != in {
		t.Errorf("Expand() = %q, want it unchanged", got)
	}
}

func TestExpand_EmptyVariableValueIsAllowed(t *testing.T) {
	// An explicitly-empty variable is set, so it expands to "" rather than
	// counting as missing. Whether an empty credential is acceptable is the
	// caller's validation problem, not this package's.
	t.Setenv("ENVEXPAND_TEST_EMPTY", "")

	got, err := Expand("x=${ENVEXPAND_TEST_EMPTY}")
	if err != nil {
		t.Fatalf("Expand() error = %v", err)
	}
	if got != "x=" {
		t.Errorf("Expand() = %q, want %q", got, "x=")
	}
}

func TestExpand_MissingVariablesAreReportedTogether(t *testing.T) {
	t.Setenv("ENVEXPAND_TEST_PRESENT", "here")

	_, err := Expand("${ENVEXPAND_TEST_ABSENT_A} ${ENVEXPAND_TEST_PRESENT} ${ENVEXPAND_TEST_ABSENT_B}")
	if err == nil {
		t.Fatal("Expand() error = nil, want an error naming the unset variables")
	}

	var missing *MissingVarsError
	if !errors.As(err, &missing) {
		t.Fatalf("Expand() error = %v, want a *MissingVarsError", err)
	}

	want := []string{"ENVEXPAND_TEST_ABSENT_A", "ENVEXPAND_TEST_ABSENT_B"}
	if len(missing.Names) != len(want) {
		t.Fatalf("Names = %v, want %v", missing.Names, want)
	}
	for i, name := range want {
		if missing.Names[i] != name {
			t.Errorf("Names[%d] = %q, want %q", i, missing.Names[i], name)
		}
	}
}

func TestExpand_MissingVariableListedOnlyOnce(t *testing.T) {
	_, err := Expand("${ENVEXPAND_TEST_REPEATED} and again ${ENVEXPAND_TEST_REPEATED}")

	var missing *MissingVarsError
	if !errors.As(err, &missing) {
		t.Fatalf("Expand() error = %v, want a *MissingVarsError", err)
	}
	if len(missing.Names) != 1 {
		t.Errorf("Names = %v, want the repeated variable reported once", missing.Names)
	}
}

func TestExpand_IgnoresNonMatchingSyntax(t *testing.T) {
	// $VAR without braces and ${...} with a non-identifier body are left
	// alone — this package deliberately implements one narrow syntax.
	const in = "$NOT_EXPANDED ${9invalid} ${} $"
	got, err := Expand(in)
	if err != nil {
		t.Fatalf("Expand() error = %v", err)
	}
	if got != in {
		t.Errorf("Expand() = %q, want it unchanged", got)
	}
}
