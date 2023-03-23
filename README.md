# hs-qr-cable

**DISCLAIMER**: Don't take it seriously, super low quality code that not even necessarily correct. To show some hints for the one who's curious, I left it here.

## What's this?

This tool decodes the QR code generated by browsers when login with Passkeys.
But it won't decode the QR code itself, you need another one, such as [this](https://zxing.org/w/decode.jspx).

This new specification will likely to be called "CTAP 2.2", and will be published as a draft [soon](https://groups.google.com/a/fidoalliance.org/g/fido-dev/c/oTiO9SBl08o/m/TUSv4neVAAAJ).

While I've added the basic ability to connect to the tunnel servers, it never really worked with Apple's. I don't know why: sending fake Safari requests, forge the headers, the last resort would be MitM (let's hope they don't really do SSL pinning), but I don't feel like debugging this...btw, `/cable/connect/...` worked a bit.

## Where...I don't...

For convenience I built 2 binaries.

## Screenshot

```
$ hs-qr-cable-exe 
Usage: hs-qr-cable-exe FIDO:/00112233445566778899...

$ hs-qr-cable-exe FIDO:/aaaa
# caBLEv2 Initiator FIDO:/ URL Decoder
## Input
"FIDO:/aaaa"
## CBOR data
### CBOR bytes (hex)
Error decoding URL: contains non-digit characters
```
