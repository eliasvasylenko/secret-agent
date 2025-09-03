package command

import "testing"

func TestExpand(t *testing.T) {
	e := Environment{
		"dogs": "cats",
		"bad":  "good",
	}
	expanded := e.Expand("$dogs are $bad")
	expected := "cats are good"

	if expanded != expected {
		t.Errorf("expected '%v', got '%v'", expected, expanded)
	}
}

func TestExpandNested(t *testing.T) {
	e := Environment{
		"animals": "all $dogs",
		"dogs":    "cats",
	}
	expanded := e.Expand("$animals are great")
	expected := "all cats are great"

	if expanded != expected {
		t.Errorf("expected '%v', got '%v'", expected, expanded)
	}
}

func TestExpandRecursive(t *testing.T) {
	e := Environment{
		"dogs": "$dogs cats",
	}
	expanded := e.Expand("$dogs are the best")
	expected := "${dogs} cats are the best"

	if expanded != expected {
		t.Errorf("expected '%v', got '%v'", expected, expanded)
	}
}

func TestExpandMutuallyRecursive(t *testing.T) {
	e := Environment{
		"thereare": "there $arethere",
		"arethere": "are $thereare",
	}
	expanded := e.Expand("$thereare good cats, $arethere good dogs")
	expected := "there are ${thereare} good cats, are there ${arethere} good dogs"

	if expanded != expected {
		t.Errorf("expected '%v', got '%v'", expected, expanded)
	}
}
