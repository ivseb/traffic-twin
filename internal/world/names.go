package world

import (
	"fmt"
	"strings"
)

// Invented personal-looking data. The lists are written here by hand; no
// observed value is ever used. Contacts use reserved names only: e-mail on
// example.com/.org/.net (RFC 2606), phones +39 555… (docs/spec/pack.md 5).

var firstNames = map[string][]string{
	"it": {"Giulia", "Marco", "Anna", "Luca", "Sara", "Paolo", "Chiara", "Andrea", "Elena", "Matteo",
		"Francesca", "Davide", "Laura", "Simone", "Marta", "Stefano", "Silvia", "Alessandro", "Valentina", "Fabio",
		"Irene", "Tommaso", "Beatrice", "Lorenzo", "Alice", "Nicola", "Federica", "Riccardo", "Noemi", "Giorgio"},
	"en": {"Alice", "Ben", "Clara", "Daniel", "Emma", "Frank", "Grace", "Henry", "Isla", "Jack",
		"Kate", "Liam", "Mia", "Noah", "Olivia", "Peter", "Ruby", "Sam", "Tom", "Zoe",
		"Amelia", "Oscar", "Lucy", "Harry", "Ella", "George", "Freya", "Leo", "Holly", "Max"},
}

var lastNames = map[string][]string{
	"it": {"Rossi", "Bianchi", "Neri", "Verdi", "Ferrari", "Russo", "Romano", "Colombo", "Ricci", "Marino",
		"Greco", "Bruno", "Gallo", "Conti", "Costa", "Fontana", "Moretti", "Barbieri", "Lombardi", "Mancini",
		"Rinaldi", "Caruso", "Ferri", "Galli", "Martini", "Leone", "Longo", "Gentile", "Vitale", "Serra"},
	"en": {"Smith", "Jones", "Taylor", "Brown", "Wilson", "Evans", "Thomas", "Roberts", "Walker", "Wright",
		"Green", "Hall", "Wood", "Clarke", "Hughes", "Turner", "Hill", "Moore", "Baker", "Cooper",
		"Ward", "King", "Scott", "Adams", "Baker", "Carter", "Mills", "Price", "Bell", "Fox"},
}

var words = []string{"alfa", "brava", "corda", "delta", "eco", "fiore", "gamma", "isola", "luna", "mare",
	"nodo", "onda", "piano", "quarzo", "rosa", "sole", "terra", "uva", "vento", "zeta"}

var emailDomains = []string{"example.com", "example.org", "example.net"}

// person is one invented identity.
type person struct {
	first, last, email, phone string
}

// people generates unique invented identities.
type people struct {
	locale string
	r      *rng
	used   map[string]int
}

func newPeople(locale string, r *rng) *people {
	if _, ok := firstNames[locale]; !ok {
		locale = "it"
	}
	return &people{locale: locale, r: r, used: map[string]int{}}
}

func (p *people) next() person {
	fn := firstNames[p.locale]
	ln := lastNames[p.locale]
	f := fn[p.r.intn(int64(len(fn)))]
	l := ln[p.r.intn(int64(len(ln)))]
	dom := emailDomains[p.r.intn(int64(len(emailDomains)))]
	local := strings.ToLower(f) + "." + strings.ToLower(l)
	key := local + "@" + dom
	n := p.used[key]
	p.used[key] = n + 1
	if n > 0 {
		local = fmt.Sprintf("%s%d", local, n+1)
	}
	phone := fmt.Sprintf("+39 555 %03d %04d", p.r.intn(1000), p.r.intn(10000))
	return person{first: f, last: l, email: local + "@" + dom, phone: phone}
}

func (p person) name() string { return p.first + " " + p.last }
