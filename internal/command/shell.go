package command

import "fmt"

func BuildShellExec(script string, shell string) (string, []string, error) {
	if shell == "" {
		shell = defaultShell
	}
	switch shell {
	case "bash":
		return "bash", []string{"-c", script}, nil
	default:
		return "", nil, fmt.Errorf("Unknown shell %s", shell)
	}
}
