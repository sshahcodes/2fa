2fa is a TOTP server pivoted from rsc/2fa(cli based 2fa client)

frustrated with other either "incompatible" or "over-engineered" 2fa-totp packages,
porting TOTP generation code from rsc/2fa to implement server side works like charm

### Features:
- works fine on generating totp key-uri and QR code.
- validates TOTP code


### To-Do
- test, test and test.
- retry throttling 
- [done] skew to validate one step previous or next code
- can be more beautifull.
- IT's a WIP!