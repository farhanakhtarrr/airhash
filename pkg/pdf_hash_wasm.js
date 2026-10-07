// pkg/pdf_hash_wasm.js
// Matches https://github.com/openwall/john/bleeding-jumbo/blob/bleeding-jumbo/run/pdf2john.py
// Output format: $pdf$V*R*Length*P*EncryptMetadata*IDLen*IDhex*ULen*Uhex*OLen*Ohex
// Note: U comes BEFORE O (this is what the Python script outputs).

export function init() {
  return Promise.resolve();
}

export function extract_hash(pdfBytes) {
  const debug = [];
  try {
    const bytes = pdfBytes instanceof Uint8Array
      ? pdfBytes
      : new Uint8Array(pdfBytes);

    debug.push('PDF size: ' + bytes.length + ' bytes');

    const parser = new PDFParser(bytes, debug);

    // 1. Trailer
    const trailer = parser.findTrailer();
    if (!trailer) return fail('No trailer found.', debug);

    // 2. /Encrypt
    const encRef = trailer.get('/Encrypt');
    if (!encRef) return fail('PDF is not encrypted (no /Encrypt).', debug);
    const encObjNum = encRef.ref;
    debug.push('/Encrypt object: ' + encObjNum);

    // 3. /ID (first element)
    const idArr = trailer.get('/ID');
    let id = null;
    if (idArr && idArr.array && idArr.array.length > 0) {
      id = toHex(idArr.array[0]);
      debug.push('/ID: ' + id);
    }
    if (!id) return fail('Missing /ID in trailer.', debug);

    // 4. /Encrypt dict
    const encDict = parser.getObject(encObjNum);
    if (!encDict || encDict.type !== 'dict') {
      return fail('Could not resolve /Encrypt object #' + encObjNum + '.', debug);
    }
    debug.push('/Encrypt dict keys: ' + Object.keys(encDict.map || {}).join(','));

    // 5. Fields
    const V = numOr(encDict.get('/V'), NaN);
    const R = numOr(encDict.get('/R'), NaN);
    const P = numOr(encDict.get('/P'), NaN);
    const emTok = encDict.get('/EncryptMetadata');
    const em = emTok && emTok.type === 'bool' && emTok.value === false ? 0 : 1;

    debug.push('/V: ' + V);
    debug.push('/R: ' + R);
    debug.push('/P: ' + P);
    debug.push('/EncryptMetadata: ' + em);

    if (!V || !R) return fail('Missing /V or /R.', debug);
    if (R === 5 || R === 6) {
      return fail('AES-256 (R5/R6) — use Python pdf2john.', debug);
    }

    // 6. /O and /U
    const oTok = encDict.get('/O');
    const uTok = encDict.get('/U');
    if (!oTok || !uTok) return fail('Missing /O or /U.', debug);

    const O = toHex(oTok);
    const U = toHex(uTok);
    debug.push('/O bytes: ' + (O ? O.length / 2 : 0) + '  value: ' + O);
    debug.push('/U bytes: ' + (U ? U.length / 2 : 0) + '  value: ' + U);

    if (!O || O.length !== 64) return fail('/O must be 32 bytes.', debug);
    if (!U || U.length !== 64) return fail('/U must be 32 bytes.', debug);
    if (id.length !== 32) return fail('/ID must be 16 bytes.', debug);

    // 7. Length forced by revision (matches Python's SecurityRevision table)
    let length;
    if (R === 2) length = 40;
    else if (R === 3) length = 128;
    else if (R === 4) length = 128;
    else length = 128;

    debug.push('Length: ' + length);

    // 8. Assemble — MATCHES THE PYTHON SCRIPT ORDER:
    //    $pdf$V*R*Length*P*EncryptMetadata*IDLen*IDhex*ULen*Uhex*OLen*Ohex
    const hash =
      '$pdf$' + V + '*' +
      R + '*' +
      length + '*' +
      P + '*' +
      em + '*' +
      (id.length / 2) + '*' + id + '*' +
      (U.length / 2) + '*' + U + '*' +
      (O.length / 2) + '*' + O;

    return { hash, error: null, debug: debug.join('\n') };
  } catch (e) {
    return fail('Exception: ' + (e && e.message ? e.message : e), debug);
  }
}

function fail(msg, debug) {
  return { hash: null, error: 'Error: ' + msg, debug: (debug || []).join('\n') };
}
function numOr(tok, def) {
  if (!tok) return def;
  if (tok.type === 'number') return tok.value;
  return def;
}
function toHex(tok) {
  if (!tok) return null;
  if (tok.type === 'hexstring') return tok.value;
  if (tok.type === 'litstring') {
    let out = '';
    for (let i = 0; i < tok.value.length; i++) {
      out += tok.value.charCodeAt(i).toString(16).padStart(2, '0');
    }
    return out;
  }
  return null;
}

// =====================================================================
// PDF Parser (identical to previous version — full tokenizer + object
// stream support + inflate decoder)
// =====================================================================

class PDFParser {
  constructor(bytes, debug) {
    this.bytes = bytes;
    this.debug = debug || [];
    this.text = bytesToLatin1(bytes);
    this.objects = {};
    this.objStreams = null;
  }

  findTrailer() {
    let idx = this.text.lastIndexOf('trailer');
    while (idx >= 0) {
      const dict = this.readObjectFrom(idx + 7);
      if (dict && dict.type === 'dict') return dict;
      idx = this.text.lastIndexOf('trailer', idx - 1);
    }
    // Fallback: XRef streams
    const xrefObjs = this.findAllObjectsWithType('XRef');
    if (xrefObjs.length > 0) {
      const dict = this.getObject(xrefObjs[xrefObjs.length - 1]);
      if (dict && dict.type === 'dict') return dict;
    }
    return null;
  }

  findAllObjectsWithType(typeName) {
    const out = [];
    const re = /(\d+)\s+0\s+obj\b/g;
    let m;
    while ((m = re.exec(this.text)) !== null) {
      const objNum = parseInt(m[1], 10);
      const start = m.index + m[0].length;
      const dict = this.readObjectFrom(start);
      if (dict && dict.type === 'dict') {
        const t = dict.get('/Type');
        if (t && t.type === 'name' && t.value === typeName) out.push(objNum);
      }
    }
    return out;
  }

  getObject(num) {
    if (this.objects[num] !== undefined) return this.objects[num];
    const re = new RegExp('(?:^|[\\r\\n\\s])' + num + '\\s+0\\s+obj\\b');
    const m = this.text.match(re);
    if (m) {
      const start = m.index + m[0].length;
      const obj = this.readObjectFrom(start);
      if (obj) { this.objects[num] = obj; return obj; }
    }
    this.buildObjectStreams();
    if (this.objStreams && this.objStreams[num] !== undefined) {
      this.objects[num] = this.objStreams[num];
      return this.objects[num];
    }
    return null;
  }

  buildObjectStreams() {
    if (this.objStreams !== null) return;
    this.objStreams = {};
    const re = /(\d+)\s+0\s+obj\b/g;
    let m;
    while ((m = re.exec(this.text)) !== null) {
      const start = m.index + m[0].length;
      const dict = this.readObjectFrom(start);
      if (!dict || dict.type !== 'dict') continue;
      const typeTok = dict.get('/Type');
      if (!typeTok || typeTok.type !== 'name' || typeTok.value !== 'ObjStm') continue;

      const N = numOr(dict.get('/N'), 0);
      const First = numOr(dict.get('/First'), 0);
      const filter = dict.get('/Filter');

      const streamStart = this.findStreamStart(m.index + m[0].length);
      if (streamStart < 0) continue;
      const streamData = this.readStream(streamStart);
      if (!streamData) continue;

      let decoded = streamData;
      if (filter) {
        for (const f of filterToList(filter)) {
          if (f === 'FlateDecode' || f === 'Fl') {
            decoded = inflate(decoded);
            if (!decoded) break;
          }
        }
      }
      if (!decoded) continue;

      const decodedText = bytesToLatin1(decoded);
      const header = decodedText.slice(0, First);
      const nums = header.trim().split(/\s+/).map(s => parseInt(s, 10));
      const pairs = [];
      for (let i = 0; i + 1 < nums.length; i += 2) {
        if (!isNaN(nums[i]) && !isNaN(nums[i + 1])) pairs.push([nums[i], nums[i + 1]]);
      }
      for (let k = 0; k < pairs.length; k++) {
        const [objNum, offset] = pairs[k];
        const objStart = First + offset;
        const nextOffset = k + 1 < pairs.length ? First + pairs[k + 1][1] : decodedText.length;
        const objText = decodedText.slice(objStart, nextOffset);
        const obj = this.readObjectFrom(objText);
        if (obj) this.objStreams[objNum] = obj;
      }
    }
  }

  readObjectFrom(start) {
    const parser = new TokReader(this.text.slice(start));
    return parser.parseObject();
  }

  findStreamStart(fromIdx) {
    const idx = this.text.indexOf('stream', fromIdx);
    if (idx < 0) return -1;
    let start = idx + 6;
    if (this.text[start] === '\r' && this.text[start + 1] === '\n') start += 2;
    else if (this.text[start] === '\n' || this.text[start] === '\r') start += 1;
    return start;
  }

  readStream(startIdx) {
    const endIdx = this.text.indexOf('endstream', startIdx);
    if (endIdx < 0) return null;
    return this.bytes.subarray(startIdx, endIdx);
  }
}

class TokReader {
  constructor(str) { this.s = str; this.i = 0; }

  skipWS() {
    while (this.i < this.s.length) {
      const c = this.s[this.i];
      if (c === '%') { while (this.i < this.s.length && this.s[this.i] !== '\n' && this.s[this.i] !== '\r') this.i++; }
      else if (/\s/.test(c)) this.i++;
      else break;
    }
  }

  parseObject() {
    this.skipWS();
    if (this.i >= this.s.length) return null;
    const c = this.s[this.i];
    if (c === '<' && this.s[this.i + 1] === '<') return this.parseDict();
    if (c === '<') return this.parseHexString();
    if (c === '(') return this.parseLiteralString();
    if (c === '[') return this.parseArray();
    if (c === '/') return this.parseName();
    if (c === 't' || c === 'f') return this.parseBool();
    if (c === 'n' && this.s.slice(this.i, this.i + 4) === 'null') { this.i += 4; return { type: 'null' }; }
    if (c === '+' || c === '-' || c === '.' || (c >= '0' && c <= '9')) return this.parseNumberOrRef();
    const start = this.i;
    while (this.i < this.s.length && !/[\s<>\[\]()/]/.test(this.s[this.i])) this.i++;
    return { type: 'raw', value: this.s.slice(start, this.i) };
  }

  parseDict() {
    const map = {}; const order = [];
    this.i += 2;
    while (true) {
      this.skipWS();
      if (this.i >= this.s.length) break;
      if (this.s[this.i] === '>' && this.s[this.i + 1] === '>') { this.i += 2; break; }
      const key = this.parseObject();
      if (!key || key.type !== 'name') break;
      const val = this.parseObject();
      map[key.value] = val;
      order.push(key.value);
    }
    return { type: 'dict', map, order, get(k) { return this.map[k.slice(1)]; } };
  }

  parseHexString() {
    this.i++;
    const start = this.i;
    while (this.i < this.s.length && this.s[this.i] !== '>') this.i++;
    const inner = this.s.slice(start, this.i).replace(/[^0-9a-fA-F]/g, '').toLowerCase();
    this.i++;
    return { type: 'hexstring', value: inner };
  }

  parseLiteralString() {
    this.i++;
    let depth = 0; let out = '';
    while (this.i < this.s.length) {
      const c = this.s[this.i];
      if (c === '\\') {
        const n = this.s[this.i + 1];
        const m = { n: '\n', r: '\r', t: '\t', b: '\b', f: '\f', '(': '(', ')': ')', '\\': '\\' }[n];
        if (m) { out += m; this.i += 2; continue; }
        if (/[0-7]/.test(n)) {
          let oct = ''; let k = this.i + 1;
          while (k < this.s.length && /[0-7]/.test(this.s[k]) && oct.length < 3) { oct += this.s[k]; k++; }
          out += String.fromCharCode(parseInt(oct, 8));
          this.i = k; continue;
        }
        out += n; this.i += 2; continue;
      }
      if (c === '(') depth++;
      else if (c === ')') { if (depth === 0) { this.i++; break; } depth--; }
      out += c; this.i++;
    }
    return { type: 'litstring', value: out };
  }

  parseArray() {
    this.i++;
    const arr = [];
    while (true) {
      this.skipWS();
      if (this.i >= this.s.length) break;
      if (this.s[this.i] === ']') { this.i++; break; }
      const v = this.parseObject();
      if (!v) break;
      arr.push(v);
    }
    return { type: 'array', array: arr };
  }

  parseName() {
    this.i++;
    const start = this.i;
    while (this.i < this.s.length && !/[\s<>\[\]()/]/.test(this.s[this.i])) this.i++;
    let name = this.s.slice(start, this.i);
    name = name.replace(/#([0-9a-fA-F]{2})/g, (_, h) => String.fromCharCode(parseInt(h, 16)));
    return { type: 'name', value: name };
  }

  parseBool() {
    if (this.s.startsWith('true', this.i)) { this.i += 4; return { type: 'bool', value: true }; }
    if (this.s.startsWith('false', this.i)) { this.i += 5; return { type: 'bool', value: false }; }
    this.i++; return { type: 'raw', value: '?' };
  }

  parseNumberOrRef() {
    const start = this.i;
    while (this.i < this.s.length && /[+\-0-9.]/.test(this.s[this.i])) this.i++;
    const nStr = this.s.slice(start, this.i);
    const n = parseFloat(nStr);
    const save = this.i;
    this.skipWS();
    const genStart = this.i;
    while (this.i < this.s.length && /[0-9]/.test(this.s[this.i])) this.i++;
    if (this.i > genStart) {
      const genStr = this.s.slice(genStart, this.i);
      this.skipWS();
      if (this.s[this.i] === 'R') { this.i++; return { type: 'ref', ref: parseInt(nStr, 10), gen: parseInt(genStr, 10) }; }
    }
    this.i = save;
    return { type: 'number', value: n };
  }
}

function bytesToLatin1(bytes) {
  const CHUNK = 0x8000;
  let out = '';
  for (let i = 0; i < bytes.length; i += CHUNK) {
    out += String.fromCharCode.apply(null, bytes.subarray(i, Math.min(i + CHUNK, bytes.length)));
  }
  return out;
}

function filterToList(filter) {
  if (!filter) return [];
  if (filter.type === 'name') return [filter.value];
  if (filter.type === 'array') return filter.array.map(t => t.value);
  return [];
}

// ---------------------------------------------------------------------
// DEFLATE decoder (raw inflate) — needed for object streams in modern PDFs
// ---------------------------------------------------------------------
function inflate(bytes) {
  try { return rawInflate(bytes); } catch (e) { return null; }
}

function rawInflate(input) {
  let bitPos = 0, bytePos = 0;
  const output = [];

  function readBits(n) {
    let v = 0;
    for (let i = 0; i < n; i++) {
      const bit = (input[bytePos] >> (bitPos & 7)) & 1;
      v |= bit << i;
      bitPos++;
      if ((bitPos & 7) === 0) bytePos++;
    }
    return v;
  }

  function pushByte(b) { output.push(b); }

  const LBASE = [3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258];
  const LEXTRA = [0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0];
  const DBASE = [1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577];
  const DEXTRA = [0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13];

  function buildHuffman(lengths) {
    const maxLen = Math.max(...lengths);
    const blCount = new Array(maxLen + 1).fill(0);
    for (const l of lengths) if (l) blCount[l]++;
    const nextCode = new Array(maxLen + 1).fill(0);
    let code = 0;
    for (let bits = 1; bits <= maxLen; bits++) {
      code = (code + blCount[bits - 1]) << 1;
      nextCode[bits] = code;
    }
    const codes = {};
    for (let i = 0; i < lengths.length; i++) {
      const l = lengths[i];
      if (!l) continue;
      codes[nextCode[l] + '_' + l] = i;
      nextCode[l]++;
    }
    return { codes, maxLen };
  }

  function decodeSym(huff) {
    let code = 0;
    for (let len = 1; len <= huff.maxLen; len++) {
      code = (code << 1) | readBits(1);
      const k = code + '_' + len;
      if (huff.codes[k] !== undefined) return huff.codes[k];
    }
    throw new Error('Bad Huffman code');
  }

  const litLenLengths = new Array(288).fill(0);
  for (let i = 0; i < 144; i++) litLenLengths[i] = 8;
  for (let i = 144; i < 256; i++) litLenLengths[i] = 9;
  for (let i = 256; i < 280; i++) litLenLengths[i] = 7;
  for (let i = 280; i < 288; i++) litLenLengths[i] = 8;
  const fixedLitLen = buildHuffman(litLenLengths);
  const fixedDist = buildHuffman(new Array(30).fill(5));

  let last = 0;
  do {
    last = readBits(1);
    const type = readBits(2);
    if (type === 0) {
      if ((bitPos & 7) !== 0) { bitPos = (bitPos + 7) & ~7; bytePos++; }
      const len = input[bytePos] | (input[bytePos + 1] << 8);
      bytePos += 4;
      for (let i = 0; i < len; i++) pushByte(input[bytePos++]);
    } else if (type === 1) {
      while (true) {
        const s = decodeSym(fixedLitLen);
        if (s === 256) break;
        if (s < 256) pushByte(s);
        else {
          const li = s - 257;
          const len = LBASE[li] + (LEXTRA[li] ? readBits(LEXTRA[li]) : 0);
          const d = decodeSym(fixedDist);
          const dist = DBASE[d] + (DEXTRA[d] ? readBits(DEXTRA[d]) : 0);
          for (let i = 0; i < len; i++) pushByte(output[output.length - dist]);
        }
      }
    } else if (type === 2) {
      const hlit = readBits(5) + 257;
      const hdist = readBits(5) + 1;
      const hclen = readBits(4) + 4;
      const order = [16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15];
      const clLens = new Array(19).fill(0);
      for (let i = 0; i < hclen; i++) clLens[order[i]] = readBits(3);
      const clHuff = buildHuffman(clLens);

      const lens = [];
      while (lens.length < hlit + hdist) {
        const s = decodeSym(clHuff);
        if (s < 16) lens.push(s);
        else if (s === 16) { const r = readBits(2) + 3; const p = lens[lens.length - 1]; for (let i = 0; i < r; i++) lens.push(p); }
        else if (s === 17) { const r = readBits(3) + 3; for (let i = 0; i < r; i++) lens.push(0); }
        else if (s === 18) { const r = readBits(7) + 11; for (let i = 0; i < r; i++) lens.push(0); }
      }
      const litLen = buildHuffman(lens.slice(0, hlit));
      const distHuff = buildHuffman(lens.slice(hlit));

      while (true) {
        const s = decodeSym(litLen);
        if (s === 256) break;
        if (s < 256) pushByte(s);
        else {
          const li = s - 257;
          const len = LBASE[li] + (LEXTRA[li] ? readBits(LEXTRA[li]) : 0);
          const d = decodeSym(distHuff);
          const dist = DBASE[d] + (DEXTRA[d] ? readBits(DEXTRA[d]) : 0);
          for (let i = 0; i < len; i++) pushByte(output[output.length - dist]);
        }
      }
    } else {
      throw new Error('Bad block type');
    }
  } while (!last);

  return new Uint8Array(output);
}