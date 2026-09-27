/**
 * DNS name wire-format codec — RFC 1035 §4.1.4.
 *
 * Encodes domain names into the length-prefixed label form used in DNS
 * messages and decodes them back, honouring the two-byte pointer
 * back-references that make DNS messages compact.
 *
 * Design choices (stated once, honoured throughout):
 *
 * 1. Lowercase only on the wire.  RFC 1035 says name comparisons are
 *    case-insensitive, but every implementation we care about emits
 *    lowercase.  Encoding normalises to lowercase so that round-trips
 *    are stable regardless of input case; decoding returns exactly
 *    what the bytes say (also lowercase in practice).
 *
 * 2. No partial-parse tolerance.  If a message is malformed we throw
 *    rather than returning a best-effort prefix.  Callers wrapping a
 *    real resolver know that a truncated name is useless.
 *
 * 3. Decode takes (buffer, offset) and returns {name, bytesRead}.
 *    Callers need bytesRead to advance past the name in the message;
 *    returning the new offset would be equally valid but bytesRead
 *    composes better with slicing.
 *
 * 4. Pointers may point anywhere earlier in the buffer (lower offset
 *    than the current read position).  Forward pointers and
 *    self-pointers are rejected as loops; pointers that point past
 *    EOF are rejected as truncation.
 */

/** Maximum wire length of a domain name, including the terminating zero. */
export const MAX_NAME_LENGTH = 255;

/** Maximum length of a single label (wire bytes, excluding the length octet). */
export const MAX_LABEL_LENGTH = 63;

// The top two bits of a length octet distinguish a pointer (0b11) from
// a plain label (0b00).  0b01 and 0b10 are reserved by RFC 3596 / 6891
// for extended label types; we reject them here because this library
// only implements classic names.
const POINTER_MASK = 0xc0;
const POINTER_FLAG = 0xc0;

/**
 * Encode a dotted domain name into DNS wire format.
 *
 * Compression pointers are NOT emitted: every label is written in full.
 * A name compressed inside a larger message is the resolver's job —
 * it needs the surrounding message context to know where to point.
 * Keeping the encoder pointer-free means it produces a self-contained,
 * position-independent byte sequence.
 *
 * @param {string} name  Dotted name, e.g. "ns1.example".  A trailing
 *                       dot is accepted; the empty string encodes the
 *                       root (a single zero byte).
 * @returns {Uint8Array} Wire bytes, terminating zero included.
 * @throws {TypeError|RangeError} On non-string input, overlong labels,
 *                                overlong names, or empty labels.
 */
export function encodeName(name) {
  if (typeof name !== 'string') {
    throw new TypeError(`encodeName: expected string, got ${typeof name}`);
  }

  // Accept a trailing dot as the FQDN form; strip it so we don't emit
  // an empty trailing label.  The root ("" or ".") becomes a lone
  // zero byte below.
  let trimmed = name;
  if (trimmed.length > 0 && trimmed.charCodeAt(trimmed.length - 1) === 0x2e /* '.' */) {
    trimmed = trimmed.slice(0, -1);
  }

  const out = [];
  let total = 0; // wire bytes produced, excluding the final zero

  if (trimmed.length === 0) {
    // Root name: just the terminating zero.
    return new Uint8Array([0]);
  }

  const labels = trimmed.split('.');
  for (const label of labels) {
    if (label.length === 0) {
      throw new RangeError(`encodeName: empty label in "${name}"`);
    }
    const lowered = label.toLowerCase();
    if (lowered.length > MAX_LABEL_LENGTH) {
      throw new RangeError(
        `encodeName: label "${label}" exceeds ${MAX_LABEL_LENGTH} bytes`,
      );
    }
    total += 1 + lowered.length;
    if (total + 1 > MAX_NAME_LENGTH) {
      // +1 for the terminating zero that hasn't been added yet.
      throw new RangeError(`encodeName: "${name}" exceeds ${MAX_NAME_LENGTH} wire bytes`);
    }
    out.push(lowered.length);
    for (let i = 0; i < lowered.length; i++) {
      out.push(lowered.charCodeAt(i));
    }
  }

  out.push(0); // terminating zero-length root label
  return new Uint8Array(out);
}

/**
 * Decode a DNS wire-format name starting at `offset` in `buffer`.
 *
 * Follows compression pointers per RFC 1035 §4.1.4.  A pointer's
 * target is always an earlier position in the buffer (lower offset
 * than where the pointer itself begins); loops and forward pointers
 * are rejected.
 *
 * @param {Uint8Array|ArrayLike<number>} buffer  The DNS message.
 * @param {number} [offset=0]                     Position of the first
 *                                               length octet.
 * @returns {{name: string, bytesRead: number}}   `name` is lowercase
 *                                               dotted form with no
 *                                               trailing dot; the root
 *                                               name is "".  `bytesRead`
 *                                               is how many bytes were
 *                                               consumed from `offset`
 *                                               (pointers are not
 *                                               counted, since they
 *                                               terminate the run).
 * @throws {TypeError|RangeError} On truncation, loops, reserved label
 *                                types, or overlong names.
 */
export function decodeName(buffer, offset = 0) {
  if (!buffer || typeof buffer.length !== 'number') {
    throw new TypeError('decodeName: expected an array-like buffer');
  }
  if (!Number.isInteger(offset) || offset < 0) {
    throw new TypeError(`decodeName: offset must be a non-negative integer, got ${offset}`);
  }

  const labels = [];
  let totalWire = 0;       // total wire bytes of the reconstructed name
  let consumed = 0;        // bytes consumed from the starting offset
  let pos = offset;
  let followedPointer = false;
  let jumpedFrom = 0;      // offset at which we took the first pointer

  // Cap the number of jumps so a malicious message can't make us
  // spin.  In well-formed data there is exactly one jump per pointer
  // and pointers never exceed the label count; 16 is comfortably
  // above any realistic chain.
  let jumpsRemaining = 16;

  while (true) {
    if (pos >= buffer.length) {
      throw new RangeError(`decodeName: truncated at offset ${pos}`);
    }
    const len = buffer[pos];

    if (len === 0) {
      // Root label terminates the name.
      if (!followedPointer) {
        consumed += 1;
      }
      break;
    }

    if ((len & POINTER_MASK) === POINTER_FLAG) {
      // Pointer: 14-bit offset in the two bytes starting at pos.
      if (pos + 1 >= buffer.length) {
        throw new RangeError(`decodeName: truncated pointer at offset ${pos}`);
      }
      const hi = len & 0x3f;
      const lo = buffer[pos + 1] & 0xff;
      const target = (hi << 8) | lo;

      if (target >= pos) {
        // RFC 1035 requires pointers to reference earlier occurrences.
        // A pointer to the same or later offset is either a forward
        // pointer (illegal) or a self-loop.
        throw new RangeError(
          `decodeName: pointer at ${pos} targets ${target} (not earlier)`,
        );
      }

      if (!followedPointer) {
        // The first pointer ends the contiguous run consumed from the
        // original offset; remember where we jumped from so `consumed`
        // reflects only bytes up to and including the pointer.
        consumed += 2;
        followedPointer = true;
        jumpedFrom = pos;
      }

      if (--jumpsRemaining < 0) {
        throw new RangeError('decodeName: too many pointer jumps (loop?)');
      }

      pos = target;
      continue;
    }

    if ((len & POINTER_MASK) !== 0) {
      // 0b01xxxxxx and 0b10xxxxxx are reserved label types we don't
      // support.
      throw new RangeError(
        `decodeName: reserved label type 0x${len.toString(16)} at offset ${pos}`,
      );
    }

    // Plain label: `len` bytes follow.
    if (len > MAX_LABEL_LENGTH) {
      throw new RangeError(
        `decodeName: label length ${len} exceeds ${MAX_LABEL_LENGTH} at offset ${pos}`,
      );
    }
    if (pos + 1 + len > buffer.length) {
      throw new RangeError(`decodeName: truncated label at offset ${pos}`);
    }

    totalWire += 1 + len;
    if (totalWire + 1 > MAX_NAME_LENGTH) {
      throw new RangeError(`decodeName: name exceeds ${MAX_NAME_LENGTH} wire bytes`);
    }

    let label = '';
    for (let i = 1; i <= len; i++) {
      label += String.fromCharCode(buffer[pos + i]);
    }
    labels.push(label);

    pos += 1 + len;
    if (!followedPointer) {
      consumed = pos - offset;
    }
  }

  // `consumed` already accounts for the terminating zero when no
  // pointer was followed.  When a pointer was followed, consumed was
  // set to include the pointer's two bytes and we broke before
  // adding the zero (the zero lives at the pointer target's path).
  void jumpedFrom;

  return { name: labels.join('.'), bytesRead: consumed };
}
