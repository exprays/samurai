package samurai

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// EventManager manages plugin events
type EventManager struct {
	mu          sync.RWMutex
	host        HostInterface
	listeners   map[string][]EventListener
	eventQueue  chan *Event
	stopChan    chan struct{}
	maxQueue    int
	initialized bool
}

// EventListener represents an event listener function
type EventListener func(ctx context.Context, event *Event) error

// NewEventManager creates a new event manager
func NewEventManager(host HostInterface) *EventManager {
	return &EventManager{
		host:       host,
		listeners:  make(map[string][]EventListener),
		eventQueue: make(chan *Event, 1000),
		stopChan:   make(chan struct{}),
		maxQueue:   1000,
	}
}

// Initialize initializes the event manager
func (em *EventManager) Initialize(ctx context.Context) error {
	em.mu.Lock()
	defer em.mu.Unlock()

	if em.initialized {
		return nil
	}

	// Start event processing goroutine
	go em.processEvents()

	em.initialized = true
	return nil
}

// OnEvent registers an event listener
func (em *EventManager) OnEvent(eventType string, listener EventListener) {
	em.mu.Lock()
	defer em.mu.Unlock()

	if em.listeners[eventType] == nil {
		em.listeners[eventType] = []EventListener{}
	}
	em.listeners[eventType] = append(em.listeners[eventType], listener)
}

// EmitEvent emits an event
func (em *EventManager) EmitEvent(ctx context.Context, event *Event) error {
	// Send to host first
	if err := em.host.EmitEvent(ctx, event); err != nil {
		return fmt.Errorf("failed to emit event to host: %w", err)
	}

	// Queue for local processing
	select {
	case em.eventQueue <- event:
		return nil
	default:
		return fmt.Errorf("event queue is full")
	}
}

// processEvents processes events from the queue
func (em *EventManager) processEvents() {
	for {
		select {
		case event := <-em.eventQueue:
			em.handleEvent(event)
		case <-em.stopChan:
			return
		}
	}
}

// handleEvent handles a single event
func (em *EventManager) handleEvent(event *Event) {
	em.mu.RLock()
	listeners := em.listeners[event.Type]
	em.mu.RUnlock()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	for _, listener := range listeners {
		if err := listener(ctx, event); err != nil {
			// Log error but continue processing other listeners
			continue
		}
	}
}

// Shutdown shuts down the event manager
func (em *EventManager) Shutdown(ctx context.Context) error {
	em.mu.Lock()
	defer em.mu.Unlock()

	if !em.initialized {
		return nil
	}

	close(em.stopChan)
	em.initialized = false
	return nil
}
