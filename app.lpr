program app;

// fibodevy 2025
// https://github.com/fibodevy

uses otp, hashing;

var
  otpkey: string;
  i: integer;

begin
  writeln('  sha1(test) = ', tohex(sha1('test')));
  writeln('       valid = ', 'a94a8fe5ccb19ba61c4c0873d391e987982fbbd3');
  writeln('sha256(test) = ', tohex(sha256('test')));
  writeln('       valid = ', '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08');
  writeln;

  //otpkey := otp_gen_key(32);
  otpkey := 'uidzl7xawzmgob5ht4dh3kfew27mhqbb';

  writeln('OTP key = ', otpkey);

  // TOTP mode
  writeln('TOTP sha1   = ', totp_calc(otpkey, 6, 30));
  writeln('TOTP sha256 = ', totp_calc(otpkey, 6, 30, 'sha256'));

  // counter mode
  for i := 0 to 4 do
    writeln('HOTP ',  i, ' = ', hotp_calc(otpkey, 6, i));

  readln;
end.

