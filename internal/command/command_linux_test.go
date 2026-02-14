//go:build linux

package command

import (
	"os/exec"
	"syscall"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestCommandOptions_Apply(t *testing.T) {
	tests := []struct {
		name    string
		options CommandOptions
		want    *syscall.Credential
	}{
		{
			name:    "no credential",
			options: CommandOptions{Credential: nil},
			want:    nil,
		},
		{
			name: "with credential",
			options: CommandOptions{
				Credential: &syscall.Credential{
					Uid: 1000,
					Gid: 1000,
				},
			},
			want: &syscall.Credential{
				Uid: 1000,
				Gid: 1000,
			},
		},
		{
			name: "with credential including supplementary groups",
			options: CommandOptions{
				Credential: &syscall.Credential{
					Uid:    2000,
					Gid:    2000,
					Groups: []uint32{2001, 2002},
				},
			},
			want: &syscall.Credential{
				Uid:    2000,
				Gid:    2000,
				Groups: []uint32{2001, 2002},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cmd := exec.Command("echo", "test")
			tc.options.Apply(cmd)

			if cmd.SysProcAttr == nil {
				t.Fatal("SysProcAttr should be initialized")
			}

			if tc.want == nil {
				if cmd.SysProcAttr.Credential != nil {
					t.Errorf("expected Credential to be nil, got %v", cmd.SysProcAttr.Credential)
				}
			} else {
				if cmd.SysProcAttr.Credential == nil {
					t.Fatal("Credential should be set")
				}

				got := cmd.SysProcAttr.Credential
				if !cmp.Equal(got, tc.want) {
					t.Errorf("Credential mismatch:\n%s", cmp.Diff(tc.want, got))
				}
			}
		})
	}
}
