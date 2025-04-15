unit otp;

// fibodevy 2025
// https://github.com/fibodevy

{$mode ObjFPC}{$H+}

interface

uses SysUtils, Math, DateUtils, hashing;

function otp_gen_key(len: integer=32): string;
function otp_calc(key: string; digits: integer=6; secs: integer=30; counter: integer=-1; hash: string='sha1'): string;
function totp_calc(key: string; digits: integer=6; secs: integer=30; hash: string='sha1'): string;
function hotp_calc(key: string; digits: integer=6; counter: integer=0; hash: string='sha1'): string;

implementation

const
  RFC4648_ALPHABET = 'abcdefghijklmnopqrstuvwxyz234567';

function otp_gen_key(len: integer=32): string;
var
  i: integer;
begin
  setlength(result, len);
  for i := 1 to len do result[i] := RFC4648_ALPHABET[1+random(length(RFC4648_ALPHABET))];
end;

function otp_calc(key: string; digits: integer=6; secs: integer=30; counter: integer=-1; hash: string='sha1'): string;
var
  i, n, j, c, offset, otp: integer;
  binarykey, t, hashedkey: string;
begin
  result := '';

  // decode base32
  n := 0;
  j := 0;
  binarykey := '';
  for i := 1 to length(key) do begin
    n := (n shl 5)+pos(key[i], RFC4648_ALPHABET)-1;
    j += 5;
    if j >= 8 then begin
      j -= 8;
      binarykey += chr((n and ($ff shl j)) shr j);
    end;
  end;

  if counter = -1 then begin
    // time mode
    c := floor(DateTimeToUnix(Now, false) div secs);
  end else begin
    // or counter mode
    c := counter;
  end;

  // pack into 64 bit
  setlength(t, 8);
  fillchar(t[1], 8, 0);
  pdword(@t[5])^ := SwapEndian(c);

  // hashed key
  if hash = 'sha1' then
    hashedkey := hmac_sha1(@t[1], length(t), @binarykey[1], length(binarykey), true)
  else if hash = 'sha256' then
    hashedkey := hmac_sha256(@t[1], length(t), @binarykey[1], length(binarykey), true)
  else
    exit;

  // otp from hash
  offset := ord(hashedkey[length(hashedkey)]) and $0f;

  // otp
  otp := floor((
    ((ord(hashedkey[1+offset+0]) and $7f) shl 24) or
    ((ord(hashedkey[1+offset+1]) and $ff) shl 16) or
    ((ord(hashedkey[1+offset+2]) and $ff) shl 8) or
    ((ord(hashedkey[1+offset+3]) and $ff))
  ) mod power(10, digits));

  result := IntToStr(otp);
  while length(result) < digits do result := '0'+result;
end;

function totp_calc(key: string; digits: integer=6; secs: integer=30; hash: string='sha1'): string;
begin
  result := otp_calc(key, digits, secs, -1, hash);
end;

function hotp_calc(key: string; digits: integer=6; counter: integer=0; hash: string='sha1'): string;
begin
  result := otp_calc(key, digits, 0, counter, hash);
end;

end.

