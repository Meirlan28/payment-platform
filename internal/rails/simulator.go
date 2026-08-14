package rails

import (
	"context"
	"errors"
	"fmt"
	"sync"
)

type BehaviorMode string

const (
	BehaviorSuccess             BehaviorMode = "SUCCESS"
	BehaviorSuccessLostResponse BehaviorMode = "SUCCESS_LOST_RESPONSE"
	BehaviorTimeoutNoEffect     BehaviorMode = "TIMEOUT_NO_EFFECT"
	BehaviorUnknown             BehaviorMode = "UNKNOWN"
	BehaviorFailure             BehaviorMode = "FAILURE"
	BehaviorDelayedSuccess      BehaviorMode = "DELAYED_SUCCESS"
	BehaviorDuplicateWebhook    BehaviorMode = "DUPLICATE_WEBHOOK"
)

type Behavior struct {
	Mode        BehaviorMode
	Code        string
	Payload     []byte
	DelayTicks  uint64
	LateVerdict *Webhook
}

type Webhook struct {
	EventID           string
	ProviderReference string
	Outcome           Outcome
	Code              string
	Payload           []byte
	Duplicate         bool
}

type simulatedRecord struct {
	response Response
	readyAt  uint64
	ready    bool
}

// ScriptedSimulator is intentionally in-memory: it is a deterministic failure
// instrument, never production financial storage.
type ScriptedSimulator struct {
	mu       sync.Mutex
	rail     Rail
	tick     uint64
	defaultB Behavior
	scripts  map[string][]Behavior
	records  map[string]simulatedRecord
	webhooks []Webhook
	late     map[uint64][]Webhook
	submits  map[string]int
}

func NewScriptedSimulator(rail Rail) *ScriptedSimulator {
	return &ScriptedSimulator{
		rail: rail, defaultB: Behavior{Mode: BehaviorSuccess, Code: "APPROVED"},
		scripts: make(map[string][]Behavior), records: make(map[string]simulatedRecord),
		late: make(map[uint64][]Webhook), submits: make(map[string]int),
	}
}

func NewCardSimulator() *ScriptedSimulator       { return NewScriptedSimulator(Card) }
func NewBankSimulator() *ScriptedSimulator       { return NewScriptedSimulator(Bank) }
func NewBlockchainSimulator() *ScriptedSimulator { return NewScriptedSimulator(Blockchain) }
func NewAntifraudSimulator() *ScriptedSimulator  { return NewScriptedSimulator(Antifraud) }

func (s *ScriptedSimulator) SupportsIdempotentReference() bool { return true }

func (s *ScriptedSimulator) Script(operationID string, behaviors ...Behavior) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.scripts[operationID] = append([]Behavior(nil), behaviors...)
}

func (s *ScriptedSimulator) SetDefault(behavior Behavior) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.defaultB = behavior
}

func (s *ScriptedSimulator) Submit(_ context.Context, request Request) (Response, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if request.Rail != s.rail || request.ProviderReference == "" {
		return Response{}, ErrInvalidRequest
	}
	s.submits[request.ProviderReference]++
	if existing, ok := s.records[request.ProviderReference]; ok && existing.ready {
		response := cloneResponse(existing.response)
		response.Duplicate = true
		return response, nil
	}
	behavior := s.nextBehavior(request.OperationID)
	response := Response{
		Outcome: OutcomeSucceeded, ProviderReference: request.ProviderReference,
		ProviderCode: behavior.Code, Payload: append([]byte(nil), behavior.Payload...),
	}
	if response.ProviderCode == "" {
		response.ProviderCode = "APPROVED"
	}
	if behavior.LateVerdict != nil {
		verdict := cloneWebhook(*behavior.LateVerdict)
		verdict.ProviderReference = request.ProviderReference
		if verdict.EventID == "" {
			verdict.EventID = fmt.Sprintf("late/%s/%d", request.ProviderReference, s.tick+behavior.DelayTicks)
		}
		s.late[s.tick+behavior.DelayTicks] = append(s.late[s.tick+behavior.DelayTicks], verdict)
	}
	switch behavior.Mode {
	case BehaviorSuccess:
		s.records[request.ProviderReference] = simulatedRecord{response: response, ready: true}
		s.webhooks = append(s.webhooks, webhookFor(response, false))
		return cloneResponse(response), nil
	case BehaviorSuccessLostResponse:
		s.records[request.ProviderReference] = simulatedRecord{response: response, ready: true}
		s.webhooks = append(s.webhooks, webhookFor(response, false))
		return Response{}, ErrRailTimeout
	case BehaviorTimeoutNoEffect:
		return Response{}, ErrRailTimeout
	case BehaviorUnknown:
		return Response{Outcome: OutcomeUnknown, ProviderReference: request.ProviderReference, ProviderCode: behavior.Code}, nil
	case BehaviorFailure:
		response.Outcome = OutcomeFailed
		if response.ProviderCode == "APPROVED" {
			response.ProviderCode = "DECLINED"
		}
		s.records[request.ProviderReference] = simulatedRecord{response: response, ready: true}
		return cloneResponse(response), nil
	case BehaviorDelayedSuccess:
		readyAt := s.tick + behavior.DelayTicks
		if behavior.DelayTicks == 0 {
			readyAt++
		}
		s.records[request.ProviderReference] = simulatedRecord{response: response, readyAt: readyAt}
		return Response{}, ErrRailTimeout
	case BehaviorDuplicateWebhook:
		s.records[request.ProviderReference] = simulatedRecord{response: response, ready: true}
		s.webhooks = append(s.webhooks, webhookFor(response, false), webhookFor(response, true))
		return cloneResponse(response), nil
	default:
		return Response{}, errors.New("rails simulator: unknown behavior")
	}
}

func (s *ScriptedSimulator) Lookup(_ context.Context, providerReference string) (Response, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.records[providerReference]
	if !ok {
		return Response{Outcome: OutcomeUnknown, ProviderReference: providerReference}, ErrUnknownOutcome
	}
	if !record.ready && s.tick >= record.readyAt {
		record.ready = true
		s.records[providerReference] = record
		s.webhooks = append(s.webhooks, webhookFor(record.response, false))
	}
	if !record.ready {
		return Response{Outcome: OutcomeUnknown, ProviderReference: providerReference}, ErrUnknownOutcome
	}
	return cloneResponse(record.response), nil
}

func (s *ScriptedSimulator) Advance(ticks uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for n := uint64(0); n < ticks; n++ {
		s.tick++
		if events := s.late[s.tick]; len(events) > 0 {
			for _, event := range events {
				s.webhooks = append(s.webhooks, cloneWebhook(event))
			}
			delete(s.late, s.tick)
		}
	}
}

func (s *ScriptedSimulator) DrainWebhooks() []Webhook {
	s.mu.Lock()
	defer s.mu.Unlock()
	result := make([]Webhook, len(s.webhooks))
	for index, event := range s.webhooks {
		result[index] = cloneWebhook(event)
	}
	s.webhooks = nil
	return result
}

func (s *ScriptedSimulator) SubmitCount(providerReference string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.submits[providerReference]
}

func (s *ScriptedSimulator) nextBehavior(operationID string) Behavior {
	queue := s.scripts[operationID]
	if len(queue) == 0 {
		return s.defaultB
	}
	result := queue[0]
	s.scripts[operationID] = queue[1:]
	return result
}

func webhookFor(response Response, duplicate bool) Webhook {
	return Webhook{
		EventID:           "webhook/" + response.ProviderReference,
		ProviderReference: response.ProviderReference, Outcome: response.Outcome,
		Code: response.ProviderCode, Payload: append([]byte(nil), response.Payload...),
		Duplicate: duplicate,
	}
}

func cloneResponse(value Response) Response {
	value.Payload = append([]byte(nil), value.Payload...)
	return value
}

func cloneWebhook(value Webhook) Webhook {
	value.Payload = append([]byte(nil), value.Payload...)
	return value
}
