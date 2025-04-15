# fpc-otp

TOTP & HOTP. SHA1 & SHA256. Time based or counter based.

No bloat, minimal code. Only `SysUtils` unit is used, which can be removed with minimal effort, reducing binary output to the smallest binary FPC can produce.

#### APIs

```pas
function otp_gen_key(len: integer=32): string;
function otp_calc(key: string; digits: integer=6; secs: integer=30; counter: integer=-1; hash: string='sha1'): string;
function totp_calc(key: string; digits: integer=6; secs: integer=30; hash: string='sha1'): string;
function hotp_calc(key: string; digits: integer=6; counter: integer=0; hash: string='sha1'): string; 
```

#### Example of use: TOTP

```pas
totp_calc(otpkey, 6, 30));
totp_calc(otpkey, 6, 30, 'sha256'));
```

#### Example of use: HOTP

```pas
hotp_calc(otpkey, 6, 0));
hotp_calc(otpkey, 6, 1));
hotp_calc(otpkey, 6, 2));
```
#### Demo output

```
OTP key = uidzl7xawzmgob5ht4dh3kfew27mhqbb
TOTP sha1   = 390945
TOTP sha256 = 109177
HOTP 0 = 256807
HOTP 1 = 990662
HOTP 2 = 431439
HOTP 3 = 961137
HOTP 4 = 786000
```
