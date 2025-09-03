package command

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"reflect"
	"testing"
)

const marshalObject = `{"environment":{"VAR1":"abc","VAR2":"xyz"},"script":"program -argument1 -argument2=$VAR1 $VAR2"}`

const marshalArray = `"program -argument1 -argument2=var1 var2"`

func TestMarshalJSON(t *testing.T) {
	tests := []struct {
		name     string
		command  *Command
		expected string
	}{
		{
			name: "object",
			command: &Command{
				Environment: Environment{
					"VAR1": "abc",
					"VAR2": "xyz",
				},
				Script: "program -argument1 -argument2=$VAR1 $VAR2",
			},
			expected: marshalObject,
		},
		{
			name: "string",
			command: &Command{
				Script: "program -argument1 -argument2=var1 var2",
			},
			expected: marshalArray,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			bytes, err := json.Marshal(tc.command)

			if err != nil {
				t.Errorf("expected no error, got '%v'", err)
			}
			if string(bytes) != tc.expected {
				t.Errorf("expected '%v', got '%v'", tc.expected, string(bytes))
			}
		})
	}
}

func TestUnmarshalJSON(t *testing.T) {
	tests := []struct {
		name     string
		json     string
		expected Command
	}{
		{
			name: "object",
			json: marshalObject,
			expected: Command{
				Environment: Environment{
					"VAR1": "abc",
					"VAR2": "xyz",
				},
				Script: "program -argument1 -argument2=$VAR1 $VAR2",
				exec:   &execCommand,
			},
		},
		{
			name: "array",
			json: marshalArray,
			expected: Command{
				Script: "program -argument1 -argument2=var1 var2",
				exec:   &execCommand,
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var command Command
			err := json.Unmarshal([]byte(tc.json), &command)
			if err != nil {
				t.Errorf("expected no error, got '%v'", err)
			}
			if !reflect.DeepEqual(command, tc.expected) {
				t.Errorf("expected '%v', got '%v'", tc.expected, command)
			}
		})
	}
}

func TestProcess(t *testing.T) {
	tests := []struct {
		fakeCommand
		name string
	}{
		{
			name: "process command",
			fakeCommand: fakeCommand{
				expectedScript: "test-cmd",
			},
		},
		{
			name: "process command input",
			fakeCommand: fakeCommand{
				expectedInput:  "test-input",
				expectedScript: "test-cmd",
			},
		},
		{
			name: "process command output",
			fakeCommand: fakeCommand{
				mockOutput:     "test-output",
				expectedScript: "test-cmd",
			},
		},
		{
			name: "process command input and output",
			fakeCommand: fakeCommand{
				expectedInput:  "test-input",
				mockOutput:     "test-output",
				expectedScript: "test-cmd",
			},
		},
		{
			name: "process command environment",
			fakeCommand: fakeCommand{
				expectedInput: "test-input",
				mockOutput:    "test-output",
				expectedEnvironment: Environment{
					"VAR1": "abc",
					"VAR2": "xyz",
				},
				expectedScript: "test-cmd",
			},
		},
	}

	for _, tc := range tests {
		tc.testExec(t, tc.name, func(t *testing.T, fakeExecCommand func(name string, arg ...string) *exec.Cmd) {
			command := Command{
				Environment: tc.expectedEnvironment,
				Script:      tc.expectedScript,
				exec:        &fakeExecCommand,
			}
			output, err := command.Process(tc.expectedInput, Environment{})
			if err != nil {
				t.Errorf("unexpected error '%v'", err)
			}
			if output != tc.mockOutput {
				t.Errorf("expected '%v', got '%v'", tc.mockOutput, output)
			}
		})
	}
}

type fakeCommand struct {
	mockOutput          string
	expectedScript      string
	expectedEnvironment Environment
	expectedInput       string
}

// Intercept sub-process calls
func (f *fakeCommand) testExec(t *testing.T, name string, test func(t *testing.T, fakeExecCommand func(name string, arg ...string) *exec.Cmd)) {
	t.Run(name, func(t *testing.T) {
		if os.Getenv("SECRET_AGENT_TEST_FAKE_PROCESS") != "1" {
			test(t, fakeExecCommand(t.Name()))
			return
		}

		bytes, err := io.ReadAll(os.Stdin)
		if err != nil {
			fmt.Printf("error reading input %v", err)
		} else if f.expectedInput != string(bytes) {
			fmt.Printf("expected input '%v', got '%v'", f.expectedInput, string(bytes))
		}
		commandLine := os.Args[3:]
		expectedCommandLine := []string{"bash", "-c", f.expectedScript}
		if !reflect.DeepEqual(expectedCommandLine, commandLine) {
			fmt.Printf("expected command '%v', got '%v'", expectedCommandLine, commandLine)
		}
		for key, value := range f.expectedEnvironment {
			if value != os.Getenv(key) {
				fmt.Printf("expected env %v = '%v'", key, value)
			}
		}

		fmt.Fprint(os.Stdout, f.mockOutput)
		os.Exit(0)
	})
}

func fakeExecCommand(testName string) func(command string, args ...string) *exec.Cmd {
	testRun := fmt.Sprintf("-test.run=%v", testName)
	return func(command string, args ...string) *exec.Cmd {
		cs := []string{testRun, "--", command}
		cs = append(cs, args...)
		cmd := exec.Command(os.Args[0], cs...)
		cmd.Env = []string{"SECRET_AGENT_TEST_FAKE_PROCESS=1"}
		return cmd
	}
}
