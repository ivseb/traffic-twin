package world

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"sort"
	"strings"
)

// Customers of a world, for the world explorer in the console: a page of
// the synthetic customers (id, invented name and e-mail, archetype and how
// many entities each owns). Everything here is synthetic data read back from
// the stored world.jsonl; nothing is derived from stored events.

const (
	// DefaultCustomerPage and MaxCustomerPage bound the page size.
	DefaultCustomerPage = 50
	MaxCustomerPage     = 200
)

// CustomerSummary is one synthetic customer of a world.
type CustomerSummary struct {
	ID        string `json:"id"`
	Name      string `json:"name,omitempty"`
	Email     string `json:"email,omitempty"`
	Archetype string `json:"archetype,omitempty"`
	// Entities counts the customer's entities per kind ("order": 3, ...).
	Entities map[string]int `json:"entities"`
}

// CustomerPage is the answer of GET /api/v1/worlds/{world_id}/customers.
type CustomerPage struct {
	WorldID string `json:"world_id"`
	// Total is the number of customers matching the search, All those of the world.
	Total     int               `json:"total"`
	All       int               `json:"all"`
	Offset    int               `json:"offset"`
	Limit     int               `json:"limit"`
	Customers []CustomerSummary `json:"customers"`
}

// PageCustomers reads the customers out of world.jsonl, keeps those whose id,
// name, e-mail or archetype contain q (case-insensitive; empty: all) and
// returns the page [offset, offset+limit).
func PageCustomers(world []byte, q string, offset, limit int) (*CustomerPage, error) {
	if offset < 0 {
		offset = 0
	}
	if limit <= 0 {
		limit = DefaultCustomerPage
	}
	if limit > MaxCustomerPage {
		limit = MaxCustomerPage
	}
	q = strings.ToLower(strings.TrimSpace(q))
	var all []*CustomerSummary
	byID := map[string]*CustomerSummary{}
	sc := bufio.NewScanner(bytes.NewReader(world))
	sc.Buffer(make([]byte, 1<<20), 8<<20)
	for sc.Scan() {
		var l struct {
			Type       string  `json:"type"`
			ID         string  `json:"id"`
			Entity     string  `json:"entity"`
			Archetype  *string `json:"archetype"`
			CustomerID *string `json:"customer_id"`
			Profile    struct {
				Name  string `json:"name"`
				Email string `json:"email"`
			} `json:"profile"`
		}
		if json.Unmarshal(sc.Bytes(), &l) != nil {
			continue
		}
		switch l.Type {
		case "customer":
			c := &CustomerSummary{ID: l.ID, Name: l.Profile.Name, Email: l.Profile.Email, Entities: map[string]int{}}
			if l.Archetype != nil {
				c.Archetype = *l.Archetype
			}
			all = append(all, c)
			byID[c.ID] = c
		case "entity":
			if l.CustomerID != nil {
				if c := byID[*l.CustomerID]; c != nil {
					c.Entities[l.Entity]++
				}
			}
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	sort.SliceStable(all, func(i, j int) bool { return all[i].ID < all[j].ID })
	page := &CustomerPage{All: len(all), Offset: offset, Limit: limit, Customers: []CustomerSummary{}}
	matches := all
	if q != "" {
		matches = nil
		for _, c := range all {
			if strings.Contains(strings.ToLower(c.ID+"\x00"+c.Name+"\x00"+c.Email+"\x00"+c.Archetype), q) {
				matches = append(matches, c)
			}
		}
	}
	page.Total = len(matches)
	for i := offset; i < len(matches) && i < offset+limit; i++ {
		page.Customers = append(page.Customers, *matches[i])
	}
	return page, nil
}

// Customers returns a page of the customers of a stored world.
func (s *Service) Customers(ctx context.Context, id, q string, offset, limit int) (*CustomerPage, error) {
	rec, err := s.Record(ctx, id)
	if err != nil {
		return nil, err
	}
	page, err := PageCustomers(rec.World, q, offset, limit)
	if err != nil {
		return nil, err
	}
	page.WorldID = rec.WorldID
	return page, nil
}
