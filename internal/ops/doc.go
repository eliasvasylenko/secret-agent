// Package ops provides typed porcelain helpers for secret instance operations.
//
// It sits above internal/backend (Catalog and Runner) and below the CLI. Callers pass
// a backend.Runner scoped to a secret; ops calls Run, then handle.Wait(ctx) to join
// (background already running).
//
// Example shape:
//
//	inst, handle, err := runner.Run(...)
//	final, err := handle.Wait(ctx)
//	final, err := ops.Create(ctx, runner, params, proposer, stdio)
//
// If handle.Wait(ctx) returns because ctx was canceled, ops calls handle.Cancel so a
// CLI Ctrl+C stops the op. Abandoning wait alone (without ops) does not stop execution;
// the same handle can be Wait'd again until completion.
//
// ops does not import server or client; it depends only on backend and secrets.
package ops
