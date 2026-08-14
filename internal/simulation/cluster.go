package simulation

import (
	"errors"
	"sort"
	"sync"
)

type Fence struct {
	Region string
	Epoch  uint64
}

type Handler func(Envelope) error

type regionNode struct {
	epoch   uint64
	running bool
	handler Handler
}

// Cluster models process/network failure and fencing only.  It deliberately
// contains no balances, ledger, inbox, outbox, or saga progress.
type Cluster struct {
	mu      sync.Mutex
	network *Network
	nodes   map[string]regionNode
}

func NewCluster(network *Network, regions ...string) (*Cluster, error) {
	if network == nil || len(regions) == 0 {
		return nil, errors.New("simulation: invalid cluster")
	}
	cluster := &Cluster{network: network, nodes: make(map[string]regionNode, len(regions))}
	for _, region := range regions {
		if region == "" {
			return nil, errors.New("simulation: empty region")
		}
		if _, exists := cluster.nodes[region]; exists {
			return nil, errors.New("simulation: duplicate region")
		}
		cluster.nodes[region] = regionNode{epoch: 1, running: true}
	}
	return cluster, nil
}

func (c *Cluster) Register(region string, handler Handler) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	node, ok := c.nodes[region]
	if !ok || handler == nil {
		return errors.New("simulation: unknown region or nil handler")
	}
	node.handler = handler
	c.nodes[region] = node
	return nil
}

func (c *Cluster) Fence(region string) (Fence, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	node, ok := c.nodes[region]
	if !ok || !node.running {
		return Fence{}, ErrNodeDown
	}
	return Fence{Region: region, Epoch: node.epoch}, nil
}

func (c *Cluster) Valid(fence Fence) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	node, ok := c.nodes[fence.Region]
	return ok && node.running && node.epoch == fence.Epoch
}

func (c *Cluster) Crash(region string) error {
	c.mu.Lock()
	node, ok := c.nodes[region]
	if !ok {
		c.mu.Unlock()
		return errors.New("simulation: unknown region")
	}
	node.running = false
	c.nodes[region] = node
	c.mu.Unlock()
	c.network.Crash(region)
	return nil
}

func (c *Cluster) Restart(region string) error {
	c.mu.Lock()
	node, ok := c.nodes[region]
	if !ok {
		c.mu.Unlock()
		return errors.New("simulation: unknown region")
	}
	node.epoch++
	node.running = true
	c.nodes[region] = node
	c.mu.Unlock()
	c.network.Restart(region)
	return nil
}

func (c *Cluster) Partition(a, b string) { c.network.Partition(a, b) }
func (c *Cluster) Heal(a, b string)      { c.network.Heal(a, b) }

func (c *Cluster) Send(fence Fence, envelope Envelope) error {
	if !c.Valid(fence) || fence.Region != envelope.From {
		return ErrStaleFence
	}
	return c.network.Send(envelope)
}

var ErrStaleFence = errors.New("simulation: stale worker fence")

// Deliver invokes handlers outside the cluster lock; handler retries and
// durable deduplication are the responsibility of messaging.Inbox.
func (c *Cluster) Deliver() []error {
	envelopes := c.network.Drain()
	var failures []error
	for _, envelope := range envelopes {
		c.mu.Lock()
		node, ok := c.nodes[envelope.To]
		c.mu.Unlock()
		if !ok || !node.running {
			failures = append(failures, ErrNodeDown)
			continue
		}
		if node.handler == nil {
			failures = append(failures, errors.New("simulation: no handler"))
			continue
		}
		if err := node.handler(envelope); err != nil {
			failures = append(failures, err)
		}
	}
	return failures
}

func (c *Cluster) Regions() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	regions := make([]string, 0, len(c.nodes))
	for region := range c.nodes {
		regions = append(regions, region)
	}
	sort.Strings(regions)
	return regions
}
