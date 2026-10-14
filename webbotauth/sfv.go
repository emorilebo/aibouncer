package webbotauth

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// This file implements the subset of RFC 8941 (Structured Field Values for HTTP) needed to
// read Signature-Input, Signature and Signature-Agent headers and to serialise signature
// parameters exactly as RFC 9421 requires.

type sfKind int

const (
	sfInteger sfKind = iota
	sfDecimal
	sfString
	sfToken
	sfBytes
	sfBoolean
)

type sfBareItem struct {
	kind    sfKind
	integer int64
	text    string // decimal (as written), string, or token
	bytes   []byte
	boolean bool
}

type sfParam struct {
	key   string
	value sfBareItem
}

type sfItem struct {
	value  sfBareItem
	params []sfParam
}

type sfInnerList struct {
	items  []sfItem
	params []sfParam
}

// sfMember is a dictionary member: either an item or an inner list.
type sfMember struct {
	key       string
	item      *sfItem
	innerList *sfInnerList
}

var errSyntax = errors.New("structured field syntax error")

type sfParser struct {
	s   string
	pos int
}

func (p *sfParser) eof() bool  { return p.pos >= len(p.s) }
func (p *sfParser) peek() byte { return p.s[p.pos] }

func (p *sfParser) skipSP() {
	for !p.eof() && p.peek() == ' ' {
		p.pos++
	}
}

func (p *sfParser) skipOWS() {
	for !p.eof() && (p.peek() == ' ' || p.peek() == '\t') {
		p.pos++
	}
}

func parseDictionary(s string) ([]sfMember, error) {
	p := &sfParser{s: strings.Trim(s, " \t")}
	var members []sfMember
	for !p.eof() {
		key, err := p.parseKey()
		if err != nil {
			return nil, err
		}
		member := sfMember{key: key}
		if !p.eof() && p.peek() == '=' {
			p.pos++
			if err := p.parseItemOrInnerList(&member); err != nil {
				return nil, err
			}
		} else {
			params, err := p.parseParams()
			if err != nil {
				return nil, err
			}
			member.item = &sfItem{value: sfBareItem{kind: sfBoolean, boolean: true}, params: params}
		}
		// A later member with the same key replaces an earlier one (RFC 8941 section 4.2.2).
		replaced := false
		for i := range members {
			if members[i].key == key {
				members[i] = member
				replaced = true
			}
		}
		if !replaced {
			members = append(members, member)
		}
		p.skipOWS()
		if p.eof() {
			break
		}
		if p.peek() != ',' {
			return nil, fmt.Errorf("%w: expected ',' at offset %d", errSyntax, p.pos)
		}
		p.pos++
		p.skipOWS()
		if p.eof() {
			return nil, fmt.Errorf("%w: trailing comma", errSyntax)
		}
	}
	return members, nil
}

func parseItem(s string) (sfItem, error) {
	p := &sfParser{s: strings.Trim(s, " \t")}
	item, err := p.parseItem()
	if err != nil {
		return sfItem{}, err
	}
	if !p.eof() {
		return sfItem{}, fmt.Errorf("%w: trailing characters", errSyntax)
	}
	return item, nil
}

func (p *sfParser) parseItemOrInnerList(member *sfMember) error {
	if !p.eof() && p.peek() == '(' {
		list, err := p.parseInnerList()
		if err != nil {
			return err
		}
		member.innerList = &list
		return nil
	}
	item, err := p.parseItem()
	if err != nil {
		return err
	}
	member.item = &item
	return nil
}

func (p *sfParser) parseInnerList() (sfInnerList, error) {
	var list sfInnerList
	p.pos++ // '('
	for {
		p.skipSP()
		if p.eof() {
			return list, fmt.Errorf("%w: unterminated inner list", errSyntax)
		}
		if p.peek() == ')' {
			p.pos++
			params, err := p.parseParams()
			list.params = params
			return list, err
		}
		item, err := p.parseItem()
		if err != nil {
			return list, err
		}
		list.items = append(list.items, item)
		if p.eof() || (p.peek() != ' ' && p.peek() != ')') {
			return list, fmt.Errorf("%w: bad inner list at offset %d", errSyntax, p.pos)
		}
	}
}

func (p *sfParser) parseItem() (sfItem, error) {
	value, err := p.parseBareItem()
	if err != nil {
		return sfItem{}, err
	}
	params, err := p.parseParams()
	return sfItem{value: value, params: params}, err
}

func (p *sfParser) parseParams() ([]sfParam, error) {
	var params []sfParam
	for !p.eof() && p.peek() == ';' {
		p.pos++
		p.skipSP()
		key, err := p.parseKey()
		if err != nil {
			return nil, err
		}
		value := sfBareItem{kind: sfBoolean, boolean: true}
		if !p.eof() && p.peek() == '=' {
			p.pos++
			if value, err = p.parseBareItem(); err != nil {
				return nil, err
			}
		}
		replaced := false
		for i := range params {
			if params[i].key == key {
				params[i].value = value
				replaced = true
			}
		}
		if !replaced {
			params = append(params, sfParam{key: key, value: value})
		}
	}
	return params, nil
}

func (p *sfParser) parseKey() (string, error) {
	start := p.pos
	if p.eof() || !(p.peek() >= 'a' && p.peek() <= 'z' || p.peek() == '*') {
		return "", fmt.Errorf("%w: bad key at offset %d", errSyntax, p.pos)
	}
	for !p.eof() {
		c := p.peek()
		if c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_' || c == '-' || c == '.' || c == '*' {
			p.pos++
			continue
		}
		break
	}
	return p.s[start:p.pos], nil
}

func (p *sfParser) parseBareItem() (sfBareItem, error) {
	if p.eof() {
		return sfBareItem{}, fmt.Errorf("%w: missing value", errSyntax)
	}
	switch c := p.peek(); {
	case c == '-' || c >= '0' && c <= '9':
		return p.parseNumber()
	case c == '"':
		return p.parseString()
	case c == ':':
		return p.parseBytes()
	case c == '?':
		return p.parseBoolean()
	case c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c == '*':
		return p.parseToken(), nil
	default:
		return sfBareItem{}, fmt.Errorf("%w: unexpected %q at offset %d", errSyntax, c, p.pos)
	}
}

func (p *sfParser) parseNumber() (sfBareItem, error) {
	start := p.pos
	if p.peek() == '-' {
		p.pos++
	}
	decimal := false
	for !p.eof() {
		c := p.peek()
		if c >= '0' && c <= '9' {
			p.pos++
		} else if c == '.' && !decimal {
			decimal = true
			p.pos++
		} else {
			break
		}
	}
	text := p.s[start:p.pos]
	if decimal {
		return sfBareItem{kind: sfDecimal, text: text}, nil
	}
	n, err := strconv.ParseInt(text, 10, 64)
	if err != nil || len(strings.TrimPrefix(text, "-")) > 15 {
		return sfBareItem{}, fmt.Errorf("%w: bad integer %q", errSyntax, text)
	}
	return sfBareItem{kind: sfInteger, integer: n}, nil
}

func (p *sfParser) parseString() (sfBareItem, error) {
	p.pos++ // opening quote
	var b strings.Builder
	for !p.eof() {
		c := p.peek()
		p.pos++
		switch {
		case c == '\\':
			if p.eof() || (p.peek() != '"' && p.peek() != '\\') {
				return sfBareItem{}, fmt.Errorf("%w: bad escape in string", errSyntax)
			}
			b.WriteByte(p.peek())
			p.pos++
		case c == '"':
			return sfBareItem{kind: sfString, text: b.String()}, nil
		case c < 0x20 || c > 0x7e:
			return sfBareItem{}, fmt.Errorf("%w: invalid character in string", errSyntax)
		default:
			b.WriteByte(c)
		}
	}
	return sfBareItem{}, fmt.Errorf("%w: unterminated string", errSyntax)
}

func (p *sfParser) parseToken() sfBareItem {
	start := p.pos
	for !p.eof() {
		c := p.peek()
		if c > 0x20 && c < 0x7f && !strings.ContainsRune(`"(),;<=>?@[\]{}`, rune(c)) {
			p.pos++
			continue
		}
		break
	}
	return sfBareItem{kind: sfToken, text: p.s[start:p.pos]}
}

func (p *sfParser) parseBytes() (sfBareItem, error) {
	p.pos++ // ':'
	end := strings.IndexByte(p.s[p.pos:], ':')
	if end < 0 {
		return sfBareItem{}, fmt.Errorf("%w: unterminated byte sequence", errSyntax)
	}
	encoded := p.s[p.pos : p.pos+end]
	p.pos += end + 1
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return sfBareItem{}, fmt.Errorf("%w: bad base64 in byte sequence", errSyntax)
	}
	return sfBareItem{kind: sfBytes, bytes: decoded}, nil
}

func (p *sfParser) parseBoolean() (sfBareItem, error) {
	if p.pos+1 >= len(p.s) || (p.s[p.pos+1] != '0' && p.s[p.pos+1] != '1') {
		return sfBareItem{}, fmt.Errorf("%w: bad boolean", errSyntax)
	}
	value := p.s[p.pos+1] == '1'
	p.pos += 2
	return sfBareItem{kind: sfBoolean, boolean: value}, nil
}

func serializeBareItem(v sfBareItem) string {
	switch v.kind {
	case sfInteger:
		return strconv.FormatInt(v.integer, 10)
	case sfDecimal, sfToken:
		return v.text
	case sfString:
		return strconv.Quote(v.text) // printable ASCII only, so Go quoting matches RFC 8941
	case sfBytes:
		return ":" + base64.StdEncoding.EncodeToString(v.bytes) + ":"
	default:
		if v.boolean {
			return "?1"
		}
		return "?0"
	}
}

func serializeParams(params []sfParam) string {
	var b strings.Builder
	for _, param := range params {
		b.WriteByte(';')
		b.WriteString(param.key)
		if param.value.kind == sfBoolean && param.value.boolean {
			continue
		}
		b.WriteByte('=')
		b.WriteString(serializeBareItem(param.value))
	}
	return b.String()
}

func serializeItem(item sfItem) string {
	return serializeBareItem(item.value) + serializeParams(item.params)
}

func serializeInnerList(list sfInnerList) string {
	parts := make([]string, len(list.items))
	for i, item := range list.items {
		parts[i] = serializeItem(item)
	}
	return "(" + strings.Join(parts, " ") + ")" + serializeParams(list.params)
}

func findParam(params []sfParam, key string) (sfBareItem, bool) {
	for _, param := range params {
		if param.key == key {
			return param.value, true
		}
	}
	return sfBareItem{}, false
}
