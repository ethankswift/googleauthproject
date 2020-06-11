This is a program that can generate a QR barcode representation of a URI for
use with Google Authenticator, and also can generate the time based codes for
use with the Authenticator.

This was originally written and compiled on Ubuntu 18.04.4 LTS, and generates
an executable that should work on most UNIX systems.

In order to use the program, you will need to run

$ make

then either

$ ./totp --generate-qr       //this will create qr.svg in the program directory

or

$ ./totp --get-otp           //this will generate passwords every 30 seconds

Notes:
The make command may take a while, the crypto library I used is fairly large.
If compilation fails on your system, support may be found at:
https://www.cryptopp.com/wiki/GNUmakefile


Implementation:

I utilized the cryptography library CryptoPP to run HMAC-SHA1, and the QR code
generator library by Nayuki to create a qr code.

The time since 1970 is sourced from the C++ library chrono, and then
manipulated into hex before being sent as the message to the HMAC-SHA1.

When the --get-otp flag is set, another thread is spawned which prints out
passwords every 30 seconds, while the main thread waits for user entry to
terminate.

For both the qr code and otp, the secret is hardcoded "12345678901234567890".
This was chosen because it is in the test cases for the spec documents.
Accuracy testing was done using Google Authenticator for iOS, but it should
work on other systems.
