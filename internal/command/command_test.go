package command

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"testing"

	"github.com/google/go-cmp/cmp"
)

const marshalObject = `{"script":"program -argument1 -argument2=$VAR1 $VAR2","environment":{"VAR1":"abc","VAR2":"xyz"},"shell":""}`

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
			},
		},
		{
			name: "array",
			json: marshalArray,
			expected: Command{
				Script: "program -argument1 -argument2=var1 var2",
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
			if !cmp.Equal(command, tc.expected) {
				t.Errorf("UnmarshalJSON mismatch:\n%s", cmp.Diff(tc.expected, command))
			}
		})
	}
}

func TestProcess(t *testing.T) {
	tests := []struct {
		fakeCommand
		script        string
		expectedShell string
		shell         string
	}{
		{
			script: "process command",
			fakeCommand: fakeCommand{
				expectedCommand: []string{"bash", "-c", "process command"},
			},
			expectedShell: "bash",
		},
		{
			script: "process command input",
			fakeCommand: fakeCommand{
				expectedInput:   "test-input",
				expectedCommand: []string{"bash", "-c", "process command input"},
			},
			expectedShell: "bash",
		},
		{
			script: "process command output",
			fakeCommand: fakeCommand{
				mockOutput:      "test-output",
				expectedCommand: []string{"bash", "-c", "process command output"},
			},
			expectedShell: "bash",
		},
		{
			script: "process command input and output",
			fakeCommand: fakeCommand{
				expectedInput:   "test-input",
				mockOutput:      "test-output",
				expectedCommand: []string{"bash", "-c", "process command input and output"},
			},
			expectedShell: "bash",
		},
		{
			script: "process command environment",
			fakeCommand: fakeCommand{
				expectedInput: "test-input",
				mockOutput:    "test-output",
				expectedEnvironment: Environment{
					"VAR1": "abc",
					"VAR2": "xyz",
				},
				expectedCommand: []string{"bash", "-c", "process command environment"},
			},
			expectedShell: "bash",
		},
		{
			script: "process command shell",
			fakeCommand: fakeCommand{
				expectedInput:   "test-input",
				mockOutput:      "test-output",
				expectedCommand: []string{"bash", "-c", "process command shell"},
			},
			shell:         "",
			expectedShell: defaultShell,
		},
	}

	for _, tc := range tests {
		tc.testExec(t, tc.script, func(t *testing.T, fakeExecCommand func(ctx context.Context, name string, arg ...string) *exec.Cmd) {
			saved := execCommand
			execCommand = fakeExecCommand
			defer func() { execCommand = saved }()
			command := Command{
				Environment: tc.expectedEnvironment,
				Script:      tc.script,
				Shell:       tc.shell,
			}
			output, err := command.Process(context.Background(), tc.expectedInput, Environment{})
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
	expectedCommand     []string
	expectedEnvironment Environment
	expectedInput       string
}

// Intercept sub-process calls
func (f *fakeCommand) testExec(t *testing.T, name string, test func(t *testing.T, fakeExecCommand func(ctx context.Context, name string, arg ...string) *exec.Cmd)) {
	t.Run(name, func(t *testing.T) {
		if os.Getenv("SECRET_AGENT_TEST_FAKE_PROCESS") != "1" {
			test(t, fakeExecCommand(t.Name()))
			return
		}

		bytes, err := io.ReadAll(os.Stdin)
		if err != nil {
			fmt.Printf("error reading input %v\n", err)
		} else if f.expectedInput != string(bytes) {
			fmt.Printf("expected input '%v', got '%v'\n", f.expectedInput, string(bytes))
		}
		commandLine := os.Args[3:]
		if !cmp.Equal(f.expectedCommand, commandLine) {
			fmt.Printf("expected command mismatch:\n%s", cmp.Diff(f.expectedCommand, commandLine))
		}
		for key, value := range f.expectedEnvironment {
			if value != os.Getenv(key) {
				fmt.Printf("expected env %v = '%v', got '%v'\n", key, value, os.Getenv(key))
			}
		}

		fmt.Fprint(os.Stdout, f.mockOutput)
		os.Exit(0)
	})
}

func fakeExecCommand(testName string) func(ctx context.Context, command string, args ...string) *exec.Cmd {
	testRun := fmt.Sprintf("-test.run=%v", testName)
	return func(ctx context.Context, command string, args ...string) *exec.Cmd {
		cs := []string{testRun, "--", command}
		cs = append(cs, args...)
		cmd := exec.CommandContext(ctx, os.Args[0], cs...)
		cmd.Env = []string{"SECRET_AGENT_TEST_FAKE_PROCESS=1"}
		return cmd
	}
}
