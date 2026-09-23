package server

import (
	"context"
	"fmt"
	"net/http"

	"github.com/eliasvasylenko/secret-agent/internal/backend"
)

type attachSlotKey struct {
	secretId  string
	principal string
}

// attachSlot is a one-shot set of attached streams consumed by one POST.
type attachSlot struct {
	key    attachSlotKey
	pipes  *attachPipes
	ctx    context.Context
	cancel context.CancelFunc

	claimed map[attachStream]bool
}

func newAttachSlot(key attachSlotKey) *attachSlot {
	ctx, cancel := context.WithCancel(context.Background())
	return &attachSlot{
		key:     key,
		pipes:   newAttachPipes(),
		ctx:     ctx,
		cancel:  cancel,
		claimed: make(map[attachStream]bool, 3),
	}
}

// claim is called with Controller.slotsMu held.
func (slot *attachSlot) claim(stream attachStream) error {
	if slot.claimed[stream] {
		return NewErrorResponse(http.StatusConflict, fmt.Errorf("%s already attached", stream))
	}
	slot.claimed[stream] = true
	return nil
}

// take is called with Controller.slotsMu held.
func (slot *attachSlot) take() error {
	if len(slot.claimed) != 3 {
		return NewErrorResponse(http.StatusConflict, fmt.Errorf("attach slot not ready"))
	}
	return nil
}

func (slot *attachSlot) close() {
	slot.cancel()
	closeAttachPipes(slot.pipes)
}

func (slot *attachSlot) watch(handle backend.Handle) {
	go func() {
		_, _ = handle.Wait(slot.ctx)
		if slot.ctx.Err() != nil {
			_ = handle.Cancel(context.Background())
			_, _ = handle.Wait(context.Background())
		}
		slot.close()
	}()
}

func (c *Controller) claimSlot(secretId, principal string, stream attachStream) (*attachSlot, error) {
	key := attachSlotKey{secretId: secretId, principal: principal}
	c.slotsMu.Lock()
	defer c.slotsMu.Unlock()
	slot := c.slots[key]
	if slot == nil {
		slot = newAttachSlot(key)
		c.slots[key] = slot
	}
	if err := slot.claim(stream); err != nil {
		return nil, err
	}
	return slot, nil
}

func (c *Controller) takeSlot(secretId, principal string) (*attachSlot, error) {
	key := attachSlotKey{secretId: secretId, principal: principal}
	c.slotsMu.Lock()
	defer c.slotsMu.Unlock()
	slot := c.slots[key]
	if slot == nil {
		return nil, errNoAttachSlot
	}
	if err := slot.take(); err != nil {
		return nil, err
	}
	delete(c.slots, key)
	return slot, nil
}

func (c *Controller) removePendingSlot(slot *attachSlot) bool {
	c.slotsMu.Lock()
	defer c.slotsMu.Unlock()
	if c.slots[slot.key] == slot {
		delete(c.slots, slot.key)
		return true
	}
	return false
}

func (c *Controller) closeSlot(slot *attachSlot) {
	c.removePendingSlot(slot)
	slot.close()
}

func (c *Controller) attachFinished(slot *attachSlot, stream attachStream, copyErr error) {
	if stream == attachStreamStdin && copyErr == nil {
		if c.removePendingSlot(slot) {
			slot.close()
		}
		return
	}
	c.closeSlot(slot)
}
