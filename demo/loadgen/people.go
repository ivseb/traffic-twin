package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"strings"
)

// Every value below is invented. Emails use the reserved example.com domain
// and phone numbers use the fictional 555 range.
var (
	firstNames = []string{"Giulia", "Marco", "Chiara", "Luca", "Sara", "Matteo", "Elena", "Davide",
		"Francesca", "Alessio", "Martina", "Pietro", "Valentina", "Simone", "Anna", "Tommaso",
		"Irene", "Nicola", "Beatrice", "Fabio"}
	lastNames = []string{"Neri", "Bianchi", "Ferraro", "Galli", "Conti", "Marini", "Fontana", "Rinaldi",
		"Barbieri", "Lombardo", "Moretti", "Testa", "Gentile", "Serra", "Vitale", "Fabbri",
		"Pellegrini", "Caruso", "Sala", "Orlando"}
	streets = []string{"Via delle Rose", "Via dei Tigli", "Corso Immaginario", "Via del Mulino",
		"Viale dei Pini", "Via Lunga", "Piazza della Fontana", "Via degli Orti", "Vicolo Stretto"}
	cities = []struct{ name, postcode string }{
		{"Milano", "20121"}, {"Torino", "10121"}, {"Bologna", "40121"}, {"Firenze", "50122"},
		{"Napoli", "80133"}, {"Bari", "70121"}, {"Verona", "37121"}, {"Padova", "35121"},
		{"Genova", "16121"}, {"Trento", "38122"},
	}
	noteTemplates = []string{
		"Citofonare %s, interno %d",
		"Lasciare al portiere, grazie",
		"Consegna dopo le 18, chiamare il %s",
		"Il campanello non funziona, bussare forte (scala %d)",
		"È un regalo per %s, non mettere la fattura nel pacco",
		"Se assente lasciare dal vicino al piano %d",
	}
	skus    = []string{"SKU-MUG-001", "SKU-TEA-014", "SKU-BAG-203", "SKU-PEN-077", "SKU-LMP-310", "SKU-BKS-120", "SKU-SCK-045", "SKU-PLT-388"}
	coupons = []string{"WELCOME10", "AUTUMN15"}
)

type address struct {
	FullName string `json:"fullName"`
	Line1    string `json:"line1"`
	Line2    string `json:"line2,omitempty"`
	City     string `json:"city"`
	Postcode string `json:"postcode"`
	Country  string `json:"country"`
}

type identity struct {
	ID      string
	First   string
	Last    string
	Email   string
	Phone   string // empty for ~40% of customers
	Address address
	Token   string
}

func pick[T any](r *rand.Rand, xs []T) T { return xs[r.IntN(len(xs))] }

func newIdentity(r *rand.Rand, n int) identity {
	first, last := pick(r, firstNames), pick(r, lastNames)
	c := pick(r, cities)
	id := identity{
		ID:    fmt.Sprintf("CUS-%06d", n),
		First: first,
		Last:  last,
		Email: strings.ToLower(fmt.Sprintf("%s.%s.%d@example.com", first, last, n)),
		Address: address{
			FullName: first + " " + last,
			Line1:    fmt.Sprintf("%s %d", pick(r, streets), 1+r.IntN(180)),
			City:     c.name,
			Postcode: c.postcode,
			Country:  "IT",
		},
	}
	if r.Float64() < 0.60 {
		id.Phone = fmt.Sprintf("+39 555 %07d", r.IntN(10_000_000))
	}
	if r.Float64() < 0.25 {
		id.Address.Line2 = fmt.Sprintf("Scala %c, interno %d", 'A'+rune(r.IntN(4)), 1+r.IntN(30))
	}
	id.Token = fakeJWT(map[string]any{"sub": id.ID, "name": id.Address.FullName, "email": id.Email, "iat": 1760000000})
	return id
}

// fakeJWT builds an unsigned token ("alg": "none"); the shop only reads sub.
func fakeJWT(claims map[string]any) string {
	enc := base64.RawURLEncoding
	h, _ := json.Marshal(map[string]string{"alg": "none", "typ": "JWT"})
	p, _ := json.Marshal(claims)
	return enc.EncodeToString(h) + "." + enc.EncodeToString(p) + "."
}

func (id identity) note(r *rand.Rand) string {
	t := pick(r, noteTemplates)
	switch {
	case !strings.Contains(t, "%"):
		return t
	case strings.Contains(t, "Citofonare"):
		return fmt.Sprintf(t, id.Last, 1+r.IntN(40))
	case strings.Contains(t, "chiamare"):
		phone := id.Phone
		if phone == "" {
			phone = fmt.Sprintf("+39 555 %07d", r.IntN(10_000_000))
		}
		return fmt.Sprintf(t, phone)
	case strings.Contains(t, "regalo"):
		return fmt.Sprintf(t, pick(r, firstNames))
	default:
		return fmt.Sprintf(t, 1+r.IntN(9))
	}
}

type orderItem struct {
	SKU string `json:"sku"`
	Qty int    `json:"qty"`
}

type orderBody struct {
	Items           []orderItem `json:"items"`
	Email           string      `json:"email,omitempty"`
	Phone           string      `json:"phone,omitempty"`
	ShippingAddress address     `json:"shippingAddress"`
	Note            *string     `json:"note,omitempty"`
	CouponCode      string      `json:"couponCode,omitempty"`
	GiftWrap        *bool       `json:"giftWrap,omitempty"`
}

// newOrder builds a valid order body with the documented optional-field rates:
// note 30%, couponCode 15%, giftWrap 10%; phone and address line2 follow the
// customer (60% and 25% of customers).
func (id identity) newOrder(r *rand.Rand) orderBody {
	n := 1 + r.IntN(4)
	b := orderBody{Email: id.Email, Phone: id.Phone, ShippingAddress: id.Address}
	for range n {
		b.Items = append(b.Items, orderItem{SKU: pick(r, skus), Qty: 1 + r.IntN(3)})
	}
	if r.Float64() < 0.30 {
		s := id.note(r)
		b.Note = &s
	}
	if r.Float64() < 0.15 {
		b.CouponCode = pick(r, coupons)
	}
	if r.Float64() < 0.10 {
		g := r.IntN(2) == 0
		b.GiftWrap = &g
	}
	return b
}

// breakOrder makes a valid body invalid in one of four realistic ways.
func breakOrder(r *rand.Rand, b orderBody) orderBody {
	switch r.IntN(4) {
	case 0:
		b.Email = "" // VALIDATION_ERROR on email
	case 1:
		b.Items = append([]orderItem{}, b.Items...)
		b.Items[0].Qty = 0 // VALIDATION_ERROR on items[0].qty
	case 2:
		b.Items = append([]orderItem{}, b.Items...)
		b.Items[0].SKU = "SKU-OLD-999" // UNKNOWN_SKU
	default:
		b.CouponCode = "SUMMER50" // INVALID_COUPON
	}
	return b
}
