
// A ZIP read by byte ranges: the central directory from the end of the file, then only the entries asked for.
// Large packages (MLOs, vehicle packs, server packs) keep their text files small; only those ranges are read.
// Pure functions over a ReadRange, so the same code reads from any byte source or from a buffer in tests.
//
// Archives are untrusted (third-party uploads): every size, count and offset in them is checked against hard limits
// before it decides how much is fetched, allocated or decompressed.
import { Inflate, strFromU8 } from "fflate";

// header: name + extra length from the central directory, the usual size of the local header's variable part.
// raw: the name's bytes as stored (the local header must repeat them exactly). aliased: extractors may write it under
// another name than `name` (ambiguousName, or an Info-ZIP Unicode Path field): never read, callers count it unread.
export type ZipEntry = { name: string; raw: Uint8Array; method: number; flags: number; crc: number; compressedSize: number; size: number; offset: number; header: number; aliased: boolean };
/** Bytes [start, end) of the archive. */
export type ReadRange = (start: number, end: number) => Promise<Uint8Array>;

const EOCD = 0x06054b50;
const EOCD64 = 0x06064b50;
const EOCD64_LOCATOR = 0x07064b50;
const CENTRAL = 0x02014b50;
const LOCAL = 0x04034b50;
const MAX_COMMENT = 0xffff;
// A central directory over this is not a FiveM package (tens of thousands of files): refuse instead of downloading it.
export const MAX_CENTRAL_DIRECTORY = 64 * 1024 * 1024;
const MAX_ENTRIES = 200_000;
/** Largest entry readZipEntries returns by default (text files up to 1 MB; callers may pass their own). */
export const MAX_ENTRY_SIZE = 1024 * 1024;
// Ranges are merged when the gap between two wanted entries is small, so a resource folder costs one request, not one per file.
const MAX_GAP = 64 * 1024;
const MAX_GROUP = 8 * 1024 * 1024;
// Local extra fields may be a little longer than the central ones (ZIP64 sizes, timestamps); a longer one is re-read.
const HEADER_SLACK = 512;
// Small input chunks: deflate expands up to ~1032:1, so one chunk can produce at most ~4 MB before the cap is checked.
const INFLATE_CHUNK = 4 * 1024;

const u16 = (b: Uint8Array, at: number) => b[at] | (b[at + 1] << 8);
const u32 = (b: Uint8Array, at: number) => (b[at] | (b[at + 1] << 8) | (b[at + 2] << 16) | (b[at + 3] << 24)) >>> 0;
// ZIP64 sizes and offsets; files over 2^53 bytes don't exist here.
const u64 = (b: Uint8Array, at: number) => u32(b, at) + u32(b, at + 4) * 2 ** 32;

export class ZipIndexError extends Error {}

// A segment Windows or an extractor rewrites (trailing dot or space, "." / "..", empty, NUL, ":" as in x.lua::$DATA):
// the file lands under another path than the name says.
const ODD_SEGMENT = /^\.{1,2}$|[. ]$|[\0:]/;
export const ambiguousName = (name: string) => name.replace(/\/$/, "").split(/[\\/]/).some((s) => s === "" || ODD_SEGMENT.test(s));

/**
 * Every entry in the central directory, in its order (the order unzipSync sees them in). The structure must be
 * unambiguous: exactly one end record ending at the end of the file, the central directory right before it and filled
 * by exactly `count` records. `contiguous` (archives in memory): the listed entries must also cover the file from byte 0
 * to the central directory without a gap, so no unlisted entry hides between them for a streaming extractor.
 */
export async function readZipIndex(size: number, read: ReadRange, { contiguous = false } = {}): Promise<ZipEntry[]> {
  const tailStart = Math.max(0, size - (22 + MAX_COMMENT));
  const tail = await read(tailStart, size);
  // Every signature whose comment ends exactly at the end of the file is a possible end record; two (one planted in the
  // other's comment) let extractors disagree about the whole archive.
  const ends: number[] = [];
  for (let i = tail.length - 22; i >= 0; i--) if (u32(tail, i) === EOCD && i + 22 + u16(tail, i + 20) === tail.length) ends.push(i);
  if (ends.length !== 1) throw new ZipIndexError(ends.length ? "more than one end of central directory" : "no end of central directory");
  const at = ends[0];
  let cdEnd = tailStart + at;
  let count = u16(tail, at + 10);
  let cdSize = u32(tail, at + 12);
  let cdOffset = u32(tail, at + 16);
  // A ZIP64 trailer (record + locator) sits between the central directory and the end record; Info-ZIP writes one
  // even for small archives when it streams. Its values count only where the classic ones are maxed out: a classic
  // archive may have exactly 65,535 entries.
  const maxed = count === 0xffff || cdSize === 0xffffffff || cdOffset === 0xffffffff;
  const locAt = at - 20;
  let record: Uint8Array | null = null;
  if (locAt >= 0 && u32(tail, locAt) === EOCD64_LOCATOR) {
    const recordAt = u64(tail, locAt + 8);
    const found = recordAt + 56 <= size ? await read(recordAt, recordAt + 56) : null;
    if (found && u32(found, 0) === EOCD64 && recordAt + 12 + u64(found, 4) === tailStart + locAt) {
      record = found;
      cdEnd = recordAt;
    } else if (maxed) throw new ZipIndexError("ZIP64 end record missing");
  }
  if (record && maxed) {
    count = u64(record, 32);
    cdSize = u64(record, 40);
    cdOffset = u64(record, 48);
  } else if (cdSize === 0xffffffff || cdOffset === 0xffffffff) {
    throw new ZipIndexError("ZIP64 locator missing");
  }
  if (count > MAX_ENTRIES) throw new ZipIndexError("too many entries");
  if (cdSize > MAX_CENTRAL_DIRECTORY) throw new ZipIndexError("central directory too large");
  if (cdOffset + cdSize !== cdEnd) throw new ZipIndexError("central directory not right before its end record");
  const cd = await read(cdOffset, cdOffset + cdSize);
  const entries: ZipEntry[] = [];
  let p = 0;
  for (let i = 0; i < count; i++) {
    if (p + 46 > cd.length || u32(cd, p) !== CENTRAL) throw new ZipIndexError("broken central directory");
    const flags = u16(cd, p + 8);
    const nameLen = u16(cd, p + 28);
    const extraLen = u16(cd, p + 30);
    const commentLen = u16(cd, p + 32);
    if (p + 46 + nameLen + extraLen + commentLen > cd.length) throw new ZipIndexError("broken central directory");
    let compressedSize = u32(cd, p + 20);
    let entrySize = u32(cd, p + 24);
    let offset = u32(cd, p + 42);
    // Same name decoding as fflate's unzipSync: UTF-8 when flag 11 is set, otherwise Latin-1.
    const raw = cd.slice(p + 46, p + 46 + nameLen);
    const name = strFromU8(raw, !(flags & 0x800));
    // ZIP64 extra field (0x0001): the 0xFFFFFFFF fields follow in this order, each 8 bytes, within the field's length.
    const extraEnd = p + 46 + nameLen + extraLen;
    // Info-ZIP Unicode Path (0x7075): Info-ZIP and 7-Zip extract under the name in it, not under `name`.
    let aliased = ambiguousName(name);
    for (let e = p + 46 + nameLen; e + 4 <= extraEnd; ) {
      const id = u16(cd, e);
      const len = u16(cd, e + 2);
      if (e + 4 + len > extraEnd) break;
      if (id === 0x7075) aliased = true;
      if (id === 0x0001) {
        let q = e + 4;
        const fieldEnd = q + len;
        if (entrySize === 0xffffffff && q + 8 <= fieldEnd) {
          entrySize = u64(cd, q);
          q += 8;
        }
        if (compressedSize === 0xffffffff && q + 8 <= fieldEnd) {
          compressedSize = u64(cd, q);
          q += 8;
        }
        if (offset === 0xffffffff && q + 8 <= fieldEnd) offset = u64(cd, q);
      }
      e += 4 + len;
    }
    entries.push({ name, raw, method: u16(cd, p + 10), flags, crc: u32(cd, p + 16), compressedSize, size: entrySize, offset, header: nameLen + extraLen, aliased });
    p += 46 + nameLen + extraLen + commentLen;
  }
  // More records than `count` says: extractors that walk the whole directory see entries this index would not.
  if (p !== cd.length) throw new ZipIndexError("central directory has unlisted records");
  if (contiguous) await assertContiguous(entries, cdOffset, read);
  return entries;
}

// Local entries back to back from byte 0 to the central directory: header, data, data descriptor (flag 3; optional
// signature, 8-byte sizes with a ZIP64 local field). Archives in memory only: every local header is read.
async function assertContiguous(entries: ZipEntry[], cdOffset: number, read: ReadRange) {
  let cursor = 0;
  for (const e of [...entries].sort((a, b) => a.offset - b.offset)) {
    if (e.offset !== cursor) throw new ZipIndexError("data between the listed entries");
    const head = await read(e.offset, e.offset + 30);
    if (head.length < 30 || u32(head, 0) !== LOCAL) throw new ZipIndexError("broken local header");
    const nameLen = u16(head, 26);
    const extraLen = u16(head, 28);
    cursor = e.offset + 30 + nameLen + extraLen + e.compressedSize;
    if (e.flags & 8) {
      const extra = await read(e.offset + 30 + nameLen, e.offset + 30 + nameLen + extraLen);
      let zip64 = e.size >= 0xffffffff || e.compressedSize >= 0xffffffff;
      for (let x = 0; x + 4 <= extra.length; x += 4 + u16(extra, x + 2)) if (u16(extra, x) === 0x0001) zip64 = true;
      const sig = await read(cursor, cursor + 4);
      if (sig.length === 4 && u32(sig, 0) === 0x08074b50) cursor += 4;
      cursor += zip64 ? 20 : 12;
    }
  }
  if (cursor !== cdOffset) throw new ZipIndexError("data between the last entry and the central directory");
}

/**
 * Whether an entry can be read within the limits. Stored data is exactly its size; deflate grows incompressible data by
 * at most a few bytes per 16 KB block, so a larger compressed size than that is a lie meant to make us fetch gigabytes.
 */
const plausible = (e: ZipEntry, size: number, maxEntry: number) =>
  !(e.flags & 1) &&
  e.size <= maxEntry &&
  e.offset < size &&
  (e.method === 0 ? e.compressedSize === e.size : e.method === 8 && e.compressedSize <= e.size + (e.size >> 3) + 1024);

// Deflate with a hard cap on the output: decoding stops as soon as the entry would exceed its declared size.
function inflateBounded(data: Uint8Array, size: number): Uint8Array | null {
  const out = new Uint8Array(size);
  let n = 0;
  let over = false;
  const inflate = new Inflate((chunk) => {
    if (over || n + chunk.length > size) {
      over = true;
      return;
    }
    out.set(chunk, n);
    n += chunk.length;
  });
  try {
    for (let i = 0; i < data.length && !over; i += INFLATE_CHUNK) inflate.push(data.subarray(i, i + INFLATE_CHUNK), i + INFLATE_CHUNK >= data.length);
  } catch {
    return null; // corrupt stream
  }
  return over || n !== size ? null : out;
}

// Where an entry lands on Windows/macOS: case-insensitive, backslash as separator, trailing dots and spaces dropped,
// "." and empty segments skipped.
const pathKey = (name: string) =>
  name
    .replaceAll("\\", "/")
    .toLowerCase()
    .split("/")
    .map((s) => s.replace(/[. ]+$/, ""))
    .filter((s) => s && s !== ".")
    .join("/");

/** Names that more than one entry of the archive extracts to. Which copy wins depends on the extractor. One pass. */
export function duplicateNames(entries: { name: string }[]): Set<string> {
  const first = new Map<string, string>();
  const out = new Set<string>();
  for (const { name } of entries) {
    const key = pathKey(name);
    const seen = first.get(key);
    if (seen === undefined) first.set(key, name);
    else out.add(seen).add(name);
  }
  return out;
}

// CRC-32 (IEEE), as stored in every ZIP header.
const CRC_TABLE = Uint32Array.from({ length: 256 }, (_, n) => {
  let c = n;
  for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
  return c >>> 0;
});
export function crc32(bytes: Uint8Array): number {
  let c = 0xffffffff;
  for (let i = 0; i < bytes.length; i++) c = CRC_TABLE[(c ^ bytes[i]) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}

const sameBytes = (a: Uint8Array, b: Uint8Array) => a.length === b.length && a.every((x, i) => x === b[i]);

/**
 * The uncompressed bytes of these entries (stored or deflated, at most `maxEntry` each). An entry is returned only when
 * every extractor would produce exactly these bytes: its local header repeats the central directory's name, method and
 * sizes (unless a data descriptor carries them), the output has the declared size and CRC, and no other entry of the
 * archive extracts to the same path. Everything else (encrypted, implausible, corrupt, inconsistent, duplicated,
 * other-method) is left out: callers report a missing entry as unreadable, never as clean. Neighbouring entries share
 * one range request.
 */
export async function readZipEntries(wanted: ZipEntry[], size: number, read: ReadRange, { maxEntry = MAX_ENTRY_SIZE, all = wanted }: { maxEntry?: number; all?: ZipEntry[] } = {}): Promise<Record<string, Uint8Array>> {
  const dupes = duplicateNames(all);
  const sorted = wanted.filter((e) => plausible(e, size, maxEntry) && !e.aliased && !dupes.has(e.name)).sort((a, b) => a.offset - b.offset);
  const endOf = (e: ZipEntry) => Math.min(size, e.offset + 30 + e.header + HEADER_SLACK + e.compressedSize);
  const groups: ZipEntry[][] = [];
  for (const e of sorted) {
    const g = groups.at(-1);
    if (g && e.offset - endOf(g.at(-1)!) < MAX_GAP && endOf(e) - g[0].offset < MAX_GROUP) g.push(e);
    else groups.push([e]);
  }
  const out: Record<string, Uint8Array> = Object.create(null);
  // false: cut off by our estimate of the header length (retry with the exact one); true: done (read or unreadable).
  const decode = (e: ZipEntry, buf: Uint8Array, at: number): boolean => {
    if (at + 30 > buf.length || u32(buf, at) !== LOCAL) return true;
    const nameLen = u16(buf, at + 26);
    if (at + 30 + nameLen > buf.length) return false;
    if (!localMatches(e, buf, at)) return true;
    const dataAt = at + 30 + nameLen + u16(buf, at + 28);
    const data = buf.subarray(dataAt, dataAt + e.compressedSize);
    if (data.length !== e.compressedSize) {
      const dataEndInFile = e.offset - at + dataAt + e.compressedSize;
      return dataEndInFile > size; // past the end of the file: truncated archive, give up
    }
    const bytes = e.method === 0 ? data.slice() : inflateBounded(data, e.size);
    if (bytes && crc32(bytes) === e.crc) out[e.name] = bytes;
    return true;
  };
  for (const g of groups) {
    const start = g[0].offset;
    const end = g.reduce((m, e) => Math.max(m, endOf(e)), 0);
    const buf = await read(start, end);
    for (const e of g) {
      if (decode(e, buf, e.offset - start)) continue;
      // The local header was longer than the central one suggested: read this entry exactly (header ≤ 128 KB).
      const head = await read(e.offset, Math.min(size, e.offset + 30));
      if (head.length < 30 || u32(head, 0) !== LOCAL) continue;
      decode(e, await read(e.offset, Math.min(size, e.offset + 30 + u16(head, 26) + u16(head, 28) + e.compressedSize)), 0);
    }
  }
  return out;
}

// The local header must describe the same entry as the central directory: a streaming extractor reads only the local
// one. With a data descriptor (flag 3) the local CRC and sizes are zero and the central ones count.
function localMatches(e: ZipEntry, buf: Uint8Array, at: number): boolean {
  const flags = u16(buf, at + 6);
  if ((flags & 1) !== (e.flags & 1) || u16(buf, at + 8) !== e.method) return false;
  if (!sameBytes(buf.subarray(at + 30, at + 30 + u16(buf, at + 26)), e.raw)) return false;
  if (flags & 8) return true;
  const crc = u32(buf, at + 14);
  const compressed = u32(buf, at + 18);
  const plain = u32(buf, at + 22);
  // ZIP64 local headers put 0xFFFFFFFF here and the real sizes in their extra field; the CRC check still binds the data.
  const sizeOk = (local: number, central: number) => local === central || local === 0xffffffff;
  return crc === e.crc && sizeOk(compressed, e.compressedSize) && sizeOk(plain, e.size);
}

/** A ReadRange over an in-memory archive (tests, and archives that were downloaded anyway). */
export const bufferRange =
  (bytes: Uint8Array): ReadRange =>
  async (start, end) =>
    bytes.subarray(start, end);

/**
 * A ReadRange with a budget: at most `requests` reads, and no read starts after `ms` (one already running may take its own
 * timeout longer). After that every read throws ZipIndexError: the file is reported unreadable instead of holding
 * the read open for many minutes.
 */
export function budgetedRange(read: ReadRange, { requests, ms }: { requests: number; ms: number }): ReadRange {
  let used = 0;
  const deadline = Date.now() + ms;
  return async (start, end) => {
    if (++used > requests || Date.now() > deadline) throw new ZipIndexError("range budget exhausted");
    return read(start, end);
  };
}


