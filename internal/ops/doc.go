// Package ops provides typed porcelain helpers for secret instance operations.
//
// It sits above internal/store (Catalog and Runner) and below the CLI. Callers pass
// a store.Runner scoped to a secret; ops calls Run, then wait(ctx) to join (background already running).
//
// Example shape (implemented in Phase 2):
//
//	inst, wait, err := runner.Run(...)
//	final, err := wait(ctx)
//	final, err := ops.Create(ctx, runner, params, proposer, stdio)
//
// ops does not import server or client; it depends only on store and secrets.
package ops
