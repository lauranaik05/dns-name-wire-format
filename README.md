# dns-name-wire

Compresses and decompresses DNS domain names to and from the wire format defined in RFC 1035 §4.1.4, including two-byte pointer back-references.

```js
import { encodeName, decodeName } from './src/index.js';

const wire = encodeName('ns1.example');
// Uint8Array [ 3, 110, 115, 49, 7, 101, 120, 97, 109, 112, 108, 101, 0 ]

const { name, bytesRead } = decodeName(wire, 0);
// name === 'ns1.example', bytesRead === 13
```

## Why this exists

DNS messages cram domain names into as few bytes as possible by replacing repeated suffixes with pointers — a two-octet token whose top two bits are set and whose low fourteen bits are an offset into the message. Parsing a response means following those pointers without falling into a loop; building a message means deciding where pointers are legal.

This library makes one deliberate trade-off: **encoding never emits pointers.** A pointer is only meaningful relative to the surrounding message, so a standalone name encoder has nothing valid to point at. Decoding, by contrast, fully honours pointers. If you need compression when assembling a full DNS message, that logic belongs in your message builder, which knows the offsets.

## Exports

- `encodeName(name: string): Uint8Array` — dotted name → wire bytes (lowercased, root-terminated, no pointers).
- `decodeName(buffer: Uint8Array, offset?: number): { name: string, bytesRead: number }` — wire bytes → dotted name, following pointers. `name` is lowercase with no trailing dot; the root is `""`. `bytesRead` is how many bytes were consumed from `offset` (pointer bytes included, the bytes they point at are not).
- `MAX_NAME_LENGTH` — `255`.
- `MAX_LABEL_LENGTH` — `63`.

## Awkward edges

- **Case.** Encoding normalises to lowercase; decoding returns whatever the bytes say, which in practice is already lowercase. Don't expect `encodeName('A')` and `decodeName(encodeName('A'))` to round-trip uppercase.
- **Trailing dot.** `encodeName('a.b.')` is accepted and identical to `encodeName('a.b')`. The root is `""` or `"."`, both producing a single zero byte.
- **Pointer direction.** Every pointer must target an earlier offset than where the pointer begins. Forward pointers and self-pointers are rejected as loops, even if a creative reading of the RFC might allow them — rejecting is safer than spinning.
- **Reserved label types** (length octets with the top two bits `01` or `10`) are rejected. Only plain labels (`00`) and pointers (`11`) are supported.

## Interpretation note

Where RFC 1035 is permissive, this library picks the strict reading and states it above. It does not attempt to support extended label types, case-preserving round-trips, or message-level compression during encoding.

## Performance

The window keeps a bounded buffer, so `push` is constant time and memory does not
grow with the length of the stream. `peak` and `trough` are linear in the window
size, which is the trade that keeps `push` cheap.

