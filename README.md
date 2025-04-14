# fpc-otp

TOTP & HOTP. SHA1 & SHA256. Time based or counter based.

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