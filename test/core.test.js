import { test } from 'node:test';
import assert from 'node:assert/strict';
import { encodeName, decodeName, MAX_NAME_LENGTH, MAX_LABEL_LENGTH } from '../src/core.js';

/** Helper: encode then decode, returning the decoded name. */
function roundTrip(name) {
  const wire = encodeName(name);
  return decodeName(wire, 0).name;
}

test('root name round-trips', () => {
  assert.equal(roundTrip(''), '');
  assert.equal(roundTrip('.'), '');
  assert.deepEqual(Array.from(encodeName('')), [0]);
});

test('single label round-trips', () => {
  assert.equal(roundTrip('example'), 'example');
});

test('multi-label name round-trips', () => {
  assert.equal(roundTrip('ns1.example'), 'ns1.example');
  assert.equal(roundTrip('a.b.c.d'), 'a.b.c.d');
});

test('encoding is lowercase regardless of input case', () => {
  assert.equal(roundTrip('ExAmPlE.COM'), 'example.com');
  const wire = encodeName('UPPER');
  assert.deepEqual(Array.from(wire), [5, 0x75, 0x70, 0x70, 0x65, 0x72, 0]);
});

test('trailing dot is accepted on encode', () => {
  assert.deepEqual(encodeName('a.b.'), encodeName('a.b'));
});

test('decode reports bytes consumed without a pointer', () => {
  const wire = encodeName('two.labels');
  const { name, bytesRead } = decodeName(wire, 0);
  assert.equal(name, 'two.labels');
  // "two"(4) + "labels"(7) + root(1) = 12
  assert.equal(bytesRead, 12);
  assert.equal(bytesRead, wire.length);
});

test('decode follows a compression pointer', () => {
  // Build a message where the name at offset 12 is a pointer back to
  // offset 0, which holds "example".
  const base = encodeName('example');           // 8 bytes, ends with root zero
  const msg = new Uint8Array(base.length + 5);
  msg.set(base, 0);                             // offset 0: "example"
  // Offset 8: some unrelated filler byte so the pointer isn't at EOF
  msg[base.length] = 0x00;
  // Offset 9..10: a two-byte pointer to offset 0
  msg[base.length + 1] = 0xc0;
  msg[base.length + 2] = 0x00;
  // Offset 11: trailing byte we don't read
  msg[base.length + 3] = 0xff;
  msg[base.length + 4] = 0xff;

  const { name, bytesRead } = decodeName(msg, base.length + 1);
  assert.equal(name, 'example');
  // Only the two pointer bytes are consumed from the start offset.
  assert.equal(bytesRead, 2);
});

test('decode follows a pointer to a multi-label prefix', () => {
  // Message layout:
  //   0:  "a.b"     (5 bytes: 1,a,1,b,0)
  //   5:  "c"       (3 bytes: 1,c,0)
  //   8:  ptr->5    (2 bytes)
  const a = encodeName('a.b');      // [1,97,1,98,0]
  const c = encodeName('c');        // [1,99,0]
  const msg = new Uint8Array(a.length + c.length + 2);
  msg.set(a, 0);
  msg.set(c, a.length);
  const ptrAt = a.length + c.length;
  msg[ptrAt] = 0xc0;
  msg[ptrAt + 1] = a.length;       // point at "c"

  const { name, bytesRead } = decodeName(msg, ptrAt);
  assert.equal(name, 'c');
  assert.equal(bytesRead, 2);
});

test('decode rejects a self-pointer (loop)', () => {
  const msg = new Uint8Array([0xc0, 0x00]);
  assert.throws(() => decodeName(msg, 0), RangeError);
});

test('decode rejects a forward pointer', () => {
  const msg = new Uint8Array([0x00, 0xc0, 0x03]);
  // Pointer at offset 1 targets offset 3, which is later.
  assert.throws(() => decodeName(msg, 1), RangeError);
});

test('decode rejects a pointer to itself via a chain (loop)', () => {
  // Two pointers that target each other: both are "not earlier" so
  // the first one is rejected before we even chase the chain.
  const msg = new Uint8Array([0x00, 0xc0, 0x03, 0xc0, 0x01]);
  assert.throws(() => decodeName(msg, 1), RangeError);
});

test('decode rejects reserved label type 0x40', () => {
  const msg = new Uint8Array([0x40, 0x00]);
  assert.throws(() => decodeName(msg, 0), RangeError);
});

test('decode rejects reserved label type 0x80', () => {
  const msg = new Uint8Array([0x80, 0x00]);
  assert.throws(() => decodeName(msg, 0), RangeError);
});

test('decode rejects truncated label (runs past EOF)', () => {
  const msg = new Uint8Array([3, 0x61, 0x62]); // claims 3 bytes, only 2 follow
  assert.throws(() => decodeName(msg, 0), RangeError);
});

test('decode rejects truncated pointer (missing second byte)', () => {
  const msg = new Uint8Array([0xc0]);
  assert.throws(() => decodeName(msg, 0), RangeError);
});

test('encode rejects empty labels (consecutive dots)', () => {
  assert.throws(() => encodeName('a..b'), RangeError);
  assert.throws(() => encodeName('.a'), RangeError);
});

test('encode rejects a label longer than 63 bytes', () => {
  const long = 'a'.repeat(MAX_LABEL_LENGTH + 1);
  assert.throws(() => encodeName(long), RangeError);
});

test('encode rejects a name longer than 255 wire bytes', () => {
  // 5-byte labels (1 length + 4 chars) x 52 = 260 wire bytes + root.
  const labels = [];
  for (let i = 0; i < 52; i++) labels.push('aaaa');
  assert.throws(() => encodeName(labels.join('.')), RangeError);
});

test('encode accepts a name at exactly the 255-byte limit', () => {
  // 63 + 63 + 63 + 62 = 251 label chars, plus 4 length octets + root = 256?
  // Carefully: wire = sum(1+len) + 1 (root).  We want total <= 255.
  // 4 labels of 63 bytes: 4*(1+63) + 1 = 257 -> too big.
  // 3 labels of 63 + 1 label of 61: 3*64 + 62 + 1 = 255.  Good.
  const name = [
    'a'.repeat(63),
    'b'.repeat(63),
    'c'.repeat(63),
    'd'.repeat(61),
  ].join('.');
  const wire = encodeName(name);
  assert.equal(wire.length, MAX_NAME_LENGTH);
  assert.equal(decodeName(wire, 0).name, name.toLowerCase());
});

test('decode rejects a name that exceeds 255 bytes via pointer expansion', () => {
  // Construct a flat (no-pointer) name of 256 wire bytes directly and
  // hand it to decodeName.  encodeName refuses to build such bytes, so
  // we craft them by hand: 52 labels of 4 chars each = 52*(1+4) = 260,
  // plus the root zero = 261 wire bytes.
  const parts = [];
  for (let i = 0; i < 52; i++) {
    parts.push(4, 0x61, 0x61, 0x61, 0x61);
  }
  parts.push(0);
  const wire = new Uint8Array(parts);
  assert.throws(() => decodeName(wire, 0), RangeError);
});

test('decode offset defaults to 0', () => {
  const wire = encodeName('hello');
  const { name } = decodeName(wire);
  assert.equal(name, 'hello');
});

test('decode rejects non-integer offset', () => {
  const wire = encodeName('x');
  assert.throws(() => decodeName(wire, 1.5), TypeError);
  assert.throws(() => decodeName(wire, -1), TypeError);
});

test('encode rejects non-string input', () => {
  assert.throws(() => encodeName(42), TypeError);
  assert.throws(() => encodeName(null), TypeError);
});

test('a pointer may target a name that itself ends with a pointer', () => {
  // Message:
  //   0:  "a"            [1,97,0]            (3 bytes)
  //   3:  "b" + ptr->0   [1,98, C0 00]       (4 bytes, no root zero)
  //   7:  ptr->3         [C0 03]             (2 bytes)
  // Decoding from offset 7 should yield "b.a".
  const msg = new Uint8Array([
    1, 0x61, 0x00,            // "a"
    1, 0x62, 0xc0, 0x00,      // "b" then pointer to offset 0
    0xc0, 0x03,               // pointer to offset 3
  ]);
  const { name, bytesRead } = decodeName(msg, 7);
  assert.equal(name, 'b.a');
  assert.equal(bytesRead, 2);
});
