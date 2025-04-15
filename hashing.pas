unit hashing;

// fibodevy 2025
// https://github.com/fibodevy

{$mode ObjFPC}{$H+}
{$modeswitch anonymousfunctions}
{$modeswitch functionreferences}

interface

uses SysUtils;

// helper functions
function tohex(p: pointer; l: dword): string;
function tohex(s: string): string;
function tobin(p: pointer; l: dword): string;
function tobin(b: tbytes): string;

// SHA hashes
function sha1(const s: rawbytestring): rawbytestring;
function sha256(const s: rawbytestring): rawbytestring;

// HMAC
type
  thashfunc = reference to function(data: string): string;

function hash_hmac(hash: thashfunc; blocksize: dword; data: pbyte; datalen: dword; key: pbyte; keylen: dword; raw: boolean=false): string;
function hmac_sha1(data: pbyte; datalen: dword; key: pbyte; keylen: dword; raw: boolean=false): string;
function hmac_sha256(data: pbyte; datalen: dword; key: pbyte; keylen: dword; raw: boolean=false): string;

implementation

// helper functions

function tohex(p: pointer; l: dword): string;
var
  i: integer;
begin
  result := '';
  for i := 0 to l-1 do result += inttohex(pbyte(p+i)^, 2);
  result := lowercase(result);
end;

function tohex(s: string): string;
begin
  result := tohex(@s[1], length(s));
end;

function tobin(p: pointer; l: dword): string;
begin
  setlength(result, l);
  move(p^, result[1], l);
end;

function tobin(b: tbytes): string;
begin
  result := tobin(@b[0], length(b));
end;

// SHA1

type
  TSHA1Contet = record
    state: array[0..4] of dword;
    count: int64;
    buffer: array[0..63] of byte;
  end;

procedure sha1init(var ctx: TSHA1Contet);
begin
  ctx.state[0] := $67452301;
  ctx.state[1] := $EFCDAB89;
  ctx.state[2] := $98BADCFE;
  ctx.state[3] := $10325476;
  ctx.state[4] := $C3D2E1F0;
  ctx.count := 0;
end;

function rol(v: longword; n: byte): longword;
begin
  Result := (v shl n) or (v shr (32 - n));
end;

procedure sha1transform(var state: array of dword; const block: array of byte);
var
  w: array[0..79] of dword;
  a, b, c, d, e, f, k, temp: dword;
  i: integer;
begin
  for i := 0 to 15 do w[i] := (block[i * 4] shl 24) or (block[i * 4 + 1] shl 16) or (block[i * 4 + 2] shl 8) or block[i * 4 + 3];
  for i := 16 to 79 do w[i] := rol(w[i - 3] xor w[i - 8] xor w[i - 14] xor w[i - 16], 1);

  a := state[0]; b := state[1]; c := state[2]; d := state[3]; e := state[4];

  for i := 0 to 79 do begin
    if i < 20 then begin
      f := (b and c) or ((not b) and d);
      k := $5A827999;
    end else if i < 40 then begin
      f := b xor c xor d;
      k := $6ED9EBA1;
    end else if i < 60 then begin
      f := (b and c) or (b and d) or (c and d);
      k := $8F1BBCDC;
    end else begin
      f := b xor c xor d; k := $CA62C1D6;
    end;
    temp := rol(a, 5) + f + e + k + w[i];
    e := d;
    d := c;
    c := rol(b, 30);
    b := a;
    a := temp;
  end;

  state[0] += a;
  state[1] += b;
  state[2] += c;
  state[3] += d;
  state[4] += e;
end;

procedure sha1update(var ctx: TSHA1Contet; const data: pbyte; len: integer);
var
  i, j: integer;
begin
  j := ctx.count shr 3 mod 64;
  ctx.count += len * 8;
  i := 0;
  while len > 0 do begin
    ctx.buffer[j] := data[i];
    inc(j);
    inc(i);
    dec(len);
    if j = 64 then begin
      sha1transform(ctx.state, ctx.buffer);
      j := 0;
    end;
  end;
end;

procedure sha1final(var ctx: TSHA1Contet; out digest: array of byte);
var
  i: integer;
  finalcount: array[0..7] of byte;
  pad: array[0..63] of byte = (128, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
begin
  for i := 0 to 7 do finalcount[i] := (ctx.count shr ((7 - i) * 8)) and $FF;

  sha1update(ctx, @pad[0], 1 + ((119 - (ctx.count shr 3) mod 64) mod 64));
  sha1update(ctx, @finalcount[0], 8);

  for i := 0 to 4 do begin
    digest[i*4+0] := (ctx.state[i] shr 24) and $FF;
    digest[i*4+1] := (ctx.state[i] shr 16) and $FF;
    digest[i*4+2] := (ctx.state[i] shr 8) and $FF;
    digest[i*4+3] := ctx.state[i] and $FF;
  end;
end;

function sha1(const s: rawbytestring): rawbytestring;
var
  ctx: TSHA1Contet;
  hash: array[0..19] of byte;
begin
  sha1init(ctx);
  sha1update(ctx, @s[1], Length(s));
  sha1final(ctx, hash);
  setlength(result, 20);
  move(hash[0], result[1], 20);
end;

// SHA256

type
  TSHA256State = array[0..7] of dword;

const
  K: array of dword = (
    $428a2f98, $71374491, $b5c0fbcf, $e9b5dba5, $3956c25b, $59f111f1, $923f82a4, $ab1c5ed5,
    $d807aa98, $12835b01, $243185be, $550c7dc3, $72be5d74, $80deb1fe, $9bdc06a7, $c19bf174,
    $e49b69c1, $efbe4786, $0fc19dc6, $240ca1cc, $2de92c6f, $4a7484aa, $5cb0a9dc, $76f988da,
    $983e5152, $a831c66d, $b00327c8, $bf597fc7, $c6e00bf3, $d5a79147, $06ca6351, $14292967,
    $27b70a85, $2e1b2138, $4d2c6dfc, $53380d13, $650a7354, $766a0abb, $81c2c92e, $92722c85,
    $a2bfe8a1, $a81a664b, $c24b8b70, $c76c51a3, $d192e819, $d6990624, $f40e3585, $106aa070,
    $19a4c116, $1e376c08, $2748774c, $34b0bcb5, $391c0cb3, $4ed8aa4a, $5b9cca4f, $682e6ff3,
    $748f82ee, $78a5636f, $84c87814, $8cc70208, $90befffa, $a4506ceb, $bef9a3f7, $c67178f2
  );

function ror(x: dword; n: byte): dword;
begin
  result := (x shr n) or (x shl (32 - n));
end;

procedure sha256transform(var state: TSHA256State; const block: array of byte);
var
  w: array[0..63] of dword;
  a, b, c, d, e, f, g, h, t1, t2: dword;
  i: integer;
begin
  for i := 0 to 15 do w[i] := (block[i*4] shl 24) or (block[i*4+1] shl 16) or (block[i*4+2] shl 8) or block[i*4+3];
  for i := 16 to 63 do w[i] := (ror(w[i-15],7) xor ror(w[i-15],18) xor (w[i-15] shr 3))+w[i-16]+(ror(w[i-2],17) xor ror(w[i-2],19) xor (w[i-2] shr 10))+w[i-7];

  a := state[0]; b := state[1]; c := state[2]; d := state[3];
  e := state[4]; f := state[5]; g := state[6]; h := state[7];

  for i := 0 to 63 do begin
    t1 := h + (ror(e,6) xor ror(e,11) xor ror(e,25)) + ((e and f) xor ((not e) and g)) + K[i] + w[i];
    t2 := (ror(a,2) xor ror(a,13) xor ror(a,22)) + ((a and b) xor (a and c) xor (b and c));
    h := g; g := f; f := e; e := d + t1;
    d := c; c := b; b := a; a := t1 + t2;
  end;

  state[0] += a; state[1] += b; state[2] += c; state[3] += d;
  state[4] += e; state[5] += f; state[6] += g; state[7] += h;
end;

function sha256(const s: rawbytestring): rawbytestring;
var
  state: TSHA256State = (
    $6a09e667, $bb67ae85, $3c6ef372, $a54ff53a,
    $510e527f, $9b05688c, $1f83d9ab, $5be0cd19
  );
  bitlen: qword;
  buf: array[0..63] of byte;
  i: integer;
begin
  result := '';
  bitlen := length(s) * 8;
  FillChar(buf, sizeof(buf), 0);
  i := 0;

  // full blocks
  while i + 63 < length(s) do begin
    move(s[i+1], buf[0], 64);
    sha256transform(state, buf);
    inc(i, 64);
  end;

  // final block
  FillChar(buf, SizeOf(buf), 0);
  move(s[i+1], buf[0], length(s) - i);
  buf[length(s)-i] := $80;
  if (Length(s)-i) >= 56 then begin
    sha256transform(state, buf);
    FillChar(buf, sizeof(buf), 0);
  end;

  buf[63] := bitlen and $FF;
  buf[62] := (bitlen shr 8) and $FF;
  buf[61] := (bitlen shr 16) and $FF;
  buf[60] := (bitlen shr 24) and $FF;
  buf[59] := (bitlen shr 32) and $FF;
  buf[58] := (bitlen shr 40) and $FF;
  buf[57] := (bitlen shr 48) and $FF;
  buf[56] := (bitlen shr 56) and $FF;

  sha256transform(state, buf);

  setlength(result, 32);
  for i := 0 to 7 do begin
    pbyte(@result[1+i*4+0])^ := (state[i] shr 24) and $FF;
    pbyte(@result[1+i*4+1])^ := (state[i] shr 16) and $FF;
    pbyte(@result[1+i*4+2])^ := (state[i] shr 8) and $FF;
    pbyte(@result[1+i*4+3])^ := (state[i] and $ff);
  end;
end;

// HMAC
function hash_hmac(hash: thashfunc; blocksize: dword; data: pbyte; datalen: dword; key: pbyte; keylen: dword; raw: boolean=false): string;
var
  opad, ipad: tbytes;
  i: integer;
  s: string;
begin
  // fix key
  if keylen > blocksize then begin
    setlength(s, keylen);
    move(key^, s[1], keylen);
    s := hash(s);
    key := @s[1];
    keylen := length(s);
  end;
  // make opad ipad
  setlength(opad, blocksize);
  fillchar(opad[0], blocksize, $5c);
  setlength(ipad, blocksize);
  fillchar(ipad[0], blocksize, $36);
  for i := 0 to keylen-1 do begin
    opad[i] := opad[i] xor ord(key[i]);
    ipad[i] := ipad[i] xor ord(key[i]);
  end;
  // hash it
  result := hash(tobin(opad)+hash(tobin(ipad)+tobin(data, datalen)));
  if not raw then result := tohex(@result[1], length(result));
end;

function hmac_sha1(data: pbyte; datalen: dword; key: pbyte; keylen: dword; raw: boolean=false): string;
begin
  result := hash_hmac(function(data: string): string
  begin
    result := sha1(data);
  end, 64, data, datalen, key, keylen, raw);
end;

function hmac_sha256(data: pbyte; datalen: dword; key: pbyte; keylen: dword; raw: boolean=false): string;
begin
  result := hash_hmac(function(data: string): string
  begin
    result := sha256(data);
  end, 64, data, datalen, key, keylen, raw);
end;

end.
