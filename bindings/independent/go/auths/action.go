package auths

import (
	"bytes"
	"sort"
	"unicode"
	"unicode/utf8"
)

// The canonical-action input is decoded under the trusted context's
// deployment limits, before the proof is read. The input length is bounded
// before any byte is read; fields are read in key order, each bound checked
// as its field is read; and the unique canonical encoding is required only
// after the whole input has been read, so a shortest-form violation never
// hides a structural or bound failure that follows it.

func actionMalformed() error    { return denied("malformed-proof") }
func actionNonCanonical() error { return denied("non-canonical-proof") }
func actionOverLimit() error    { return denied("resource-limit-exceeded") }

type actionReader struct {
	data []byte
	at   int
}

// head reads one item head. The argument need not use the shortest
// encoding: the final canonical comparison rejects that.
func (r *actionReader) head() (byte, uint64, error) {
	if r.at >= len(r.data) {
		return 0, 0, actionMalformed()
	}
	initial := r.data[r.at]
	r.at++
	major, additional := initial>>5, initial&31
	if additional < 24 {
		return major, uint64(additional), nil
	}
	width := 0
	switch additional {
	case 24:
		width = 1
	case 25:
		width = 2
	case 26:
		width = 4
	case 27:
		width = 8
	default:
		// Indefinite lengths and reserved values are unreadable here.
		return 0, 0, actionMalformed()
	}
	if len(r.data)-r.at < width {
		return 0, 0, actionMalformed()
	}
	var value uint64
	for _, octet := range r.data[r.at : r.at+width] {
		value = value<<8 | uint64(octet)
	}
	r.at += width
	return major, value, nil
}

func (r *actionReader) mapOf(entries uint64) error {
	major, value, err := r.head()
	if err != nil {
		return err
	}
	if major != 5 || value != entries {
		return actionMalformed()
	}
	return nil
}

// key reads a map key. A key that is not a small unsigned integer is
// unreadable; a readable key other than the next expected one is a
// non-canonical key order.
func (r *actionReader) key(expected uint64) error {
	major, value, err := r.head()
	if err != nil {
		return err
	}
	if major != 0 || value > 0xff {
		return actionMalformed()
	}
	if value != expected {
		return actionNonCanonical()
	}
	return nil
}

func (r *actionReader) unsigned(maximum uint64) (uint64, error) {
	major, value, err := r.head()
	if err != nil {
		return 0, err
	}
	if major != 0 || value > maximum {
		return 0, actionMalformed()
	}
	return value, nil
}

func (r *actionReader) byteString() ([]byte, error) {
	major, length, err := r.head()
	if err != nil {
		return nil, err
	}
	if major != 2 || length > uint64(len(r.data)-r.at) {
		return nil, actionMalformed()
	}
	value := r.data[r.at : r.at+int(length)]
	r.at += int(length)
	return append([]byte(nil), value...), nil
}

// identifier reads a bounded protocol identifier: non-empty, at most
// maximum bytes, without whitespace or control characters.
func (r *actionReader) identifier(maximum int) (string, error) {
	major, length, err := r.head()
	if err != nil {
		return "", err
	}
	if major != 3 || length > uint64(len(r.data)-r.at) {
		return "", actionMalformed()
	}
	value := r.data[r.at : r.at+int(length)]
	r.at += int(length)
	if !utf8.Valid(value) || len(value) == 0 || len(value) > maximum {
		return "", actionMalformed()
	}
	text := string(value)
	for _, character := range text {
		if unicode.IsControl(character) || unicode.IsSpace(character) {
			return "", actionMalformed()
		}
	}
	return text, nil
}

func (r *actionReader) actionProfile() (profile, error) {
	if err := r.mapOf(2); err != nil {
		return profile{}, err
	}
	if err := r.key(0); err != nil {
		return profile{}, err
	}
	id, err := r.identifier(128)
	if err != nil {
		return profile{}, err
	}
	if err := r.key(1); err != nil {
		return profile{}, err
	}
	version, err := r.unsigned(0xffff)
	if err != nil {
		return profile{}, err
	}
	if version == 0 {
		return profile{}, actionMalformed()
	}
	return profile{id: id, version: version}, nil
}

func (r *actionReader) actionPermission() (permission, error) {
	if err := r.mapOf(2); err != nil {
		return permission{}, err
	}
	if err := r.key(0); err != nil {
		return permission{}, err
	}
	capability, err := r.identifier(128)
	if err != nil {
		return permission{}, err
	}
	if err := r.key(1); err != nil {
		return permission{}, err
	}
	resource, err := r.identifier(1024)
	if err != nil {
		return permission{}, err
	}
	return permission{capability: capability, resource: resource}, nil
}

func (r *actionReader) requestedBudget() (*budget, error) {
	if r.at < len(r.data) && r.data[r.at] == 0xf6 {
		r.at++
		return nil, nil
	}
	if err := r.mapOf(2); err != nil {
		return nil, err
	}
	if err := r.key(0); err != nil {
		return nil, err
	}
	algebra, err := r.identifier(128)
	if err != nil {
		return nil, err
	}
	if err := r.key(1); err != nil {
		return nil, err
	}
	value, err := r.unsigned(^uint64(0))
	if err != nil {
		return nil, err
	}
	return &budget{algebra: algebra, value: value}, nil
}

func (r *actionReader) detachedAttachments(limits [27]uint64) ([]detachedAttachment, error) {
	major, count, err := r.head()
	if err != nil {
		return nil, err
	}
	if major != 4 {
		return nil, actionMalformed()
	}
	if count > limits[13] {
		return nil, actionOverLimit()
	}
	attachments := make([]detachedAttachment, 0, int(count))
	var total uint64
	for range count {
		if err := r.mapOf(2); err != nil {
			return nil, err
		}
		if err := r.key(0); err != nil {
			return nil, err
		}
		digest, err := r.byteString()
		if err != nil {
			return nil, err
		}
		if len(digest) != 32 {
			return nil, actionMalformed()
		}
		if err := r.key(1); err != nil {
			return nil, err
		}
		content, err := r.byteString()
		if err != nil {
			return nil, err
		}
		size := uint64(len(content))
		if size == 0 || size > limits[14] {
			return nil, actionOverLimit()
		}
		total += size
		if total > limits[14] {
			return nil, actionOverLimit()
		}
		attachments = append(attachments, detachedAttachment{digest: digest, bytes: content})
	}
	return attachments, nil
}

// decodeBoundedCanonicalAction decodes the canonical-action input under the
// context's limits: input bytes (limit 1), body bytes (limit 23), detached
// attachment count (limit 13), and each and all detached attachment bytes
// (limit 14). It returns the native stable code for every failure.
func decodeBoundedCanonicalAction(data []byte, limits [27]uint64) (*canonicalAction, error) {
	if uint64(len(data)) > limits[1] {
		return nil, actionOverLimit()
	}
	reader := actionReader{data: data}
	if err := reader.mapOf(6); err != nil {
		return nil, err
	}
	if err := reader.key(0); err != nil {
		return nil, err
	}
	actionProfile, err := reader.actionProfile()
	if err != nil {
		return nil, err
	}
	if err := reader.key(1); err != nil {
		return nil, err
	}
	mediaType, err := reader.identifier(128)
	if err != nil {
		return nil, err
	}
	if err := reader.key(2); err != nil {
		return nil, err
	}
	body, err := reader.byteString()
	if err != nil {
		return nil, err
	}
	if len(body) == 0 || uint64(len(body)) > limits[23] {
		return nil, actionOverLimit()
	}
	if err := reader.key(3); err != nil {
		return nil, err
	}
	actionPermission, err := reader.actionPermission()
	if err != nil {
		return nil, err
	}
	if err := reader.key(4); err != nil {
		return nil, err
	}
	requested, err := reader.requestedBudget()
	if err != nil {
		return nil, err
	}
	if err := reader.key(5); err != nil {
		return nil, err
	}
	detached, err := reader.detachedAttachments(limits)
	if err != nil {
		return nil, err
	}
	sorted := append([]detachedAttachment(nil), detached...)
	sort.Slice(sorted, func(left, right int) bool {
		return bytes.Compare(sorted[left].digest, sorted[right].digest) < 0
	})
	for index := 1; index < len(sorted); index++ {
		if bytes.Equal(sorted[index-1].digest, sorted[index].digest) {
			return nil, actionMalformed()
		}
	}
	if reader.at != len(data) {
		return nil, actionMalformed()
	}
	action := &canonicalAction{
		body: body, profile: actionProfile, mediaType: mediaType,
		permission: actionPermission, budget: requested, detached: sorted,
	}
	if !bytes.Equal(encodeCanonicalAction(action), data) {
		return nil, actionNonCanonical()
	}
	return action, nil
}

// encodeCanonicalAction is the unique canonical encoding of a decoded
// canonical action, with detached attachments in digest order.
func encodeCanonicalAction(action *canonicalAction) []byte {
	output := encodeCBORHead(5, 6)
	output = append(output, 0x00)
	output = append(output, encodeCBORHead(5, 2)...)
	output = append(output, 0x00)
	output = append(output, encodeCBORText(action.profile.id)...)
	output = append(output, 0x01)
	output = append(output, encodeCBORHead(0, action.profile.version)...)
	output = append(output, 0x01)
	output = append(output, encodeCBORText(action.mediaType)...)
	output = append(output, 0x02)
	output = append(output, encodeCBORBytes(action.body)...)
	output = append(output, 0x03)
	output = append(output, encodeCBORHead(5, 2)...)
	output = append(output, 0x00)
	output = append(output, encodeCBORText(action.permission.capability)...)
	output = append(output, 0x01)
	output = append(output, encodeCBORText(action.permission.resource)...)
	output = append(output, 0x04)
	if action.budget == nil {
		output = append(output, 0xf6)
	} else {
		output = append(output, encodeCBORHead(5, 2)...)
		output = append(output, 0x00)
		output = append(output, encodeCBORText(action.budget.algebra)...)
		output = append(output, 0x01)
		output = append(output, encodeCBORHead(0, action.budget.value)...)
	}
	output = append(output, 0x05)
	output = append(output, encodeCBORHead(4, uint64(len(action.detached)))...)
	for _, attachment := range action.detached {
		output = append(output, encodeCBORHead(5, 2)...)
		output = append(output, 0x00)
		output = append(output, encodeCBORBytes(attachment.digest)...)
		output = append(output, 0x01)
		output = append(output, encodeCBORBytes(attachment.bytes)...)
	}
	return output
}
