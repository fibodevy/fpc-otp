program app;

// fibodevy 2025
// https://github.com/fibodevy

uses otp;

var
  otpkey: string;
  i: integer;

begin
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

