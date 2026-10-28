package miner

import (
	"context"
	"testing"
	"time"

	"github.com/ivseb/traffic-twin/internal/graphql/graphqltest"
	"github.com/ivseb/traffic-twin/internal/intake"
)

type gqlSource []*intake.StoredEvent

func (s gqlSource) Scan(_ context.Context, _ intake.Query, fn func(*intake.StoredEvent) error) error {
	for _, e := range s {
		if err := fn(e); err != nil {
			return err
		}
	}
	return nil
}

// GraphQL operations are mined like REST ones (event.md 6): the mutation
// creates the entity (id in $.data.createOrder.id), the query reads it,
// selected by the variable $.variables.id; the query is a read although it
// is a POST.
func TestMineGraphQLEntities(t *testing.T) {
	evs, err := graphqltest.Events(graphqltest.Exchanges(40))
	if err != nil {
		t.Fatal(err)
	}
	var src gqlSource
	for i, ev := range evs {
		src = append(src, &intake.StoredEvent{ID: int64(i + 1), ReceivedAt: ev.Time, Event: ev})
	}
	res, err := Mine(context.Background(), src, time.Time{}, time.Time{}, nil, DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	var found *Entity
	for i := range res.Entities {
		if c := res.Entities[i].CreatedBy; c != nil && c.Op == "POST /graphql#CreateOrder" {
			found = &res.Entities[i]
		}
	}
	if found == nil {
		t.Fatalf("no entity created by the mutation: %+v", res.Entities)
	}
	if found.Name != "order" || found.CreatedBy.ID.Path != "$.data.createOrder.id" {
		t.Fatalf("entity: %+v %+v", found, found.CreatedBy)
	}
	var read *ReadBy
	for i := range found.ReadBy {
		if found.ReadBy[i].Op == "POST /graphql#GetOrder" {
			read = &found.ReadBy[i]
		}
	}
	if read == nil || read.By == nil || read.By.From != "req.body" || read.By.Path != "$.variables.id" || read.At.Path != "$.data.order" {
		t.Fatalf("read: %+v (by %+v)", read, read)
	}
}
