## About

securetoken arose out of wanting a simple, encrypted, and authenticated token. [Fernet](https://github.com/fernet/spec/blob/master/Spec.md) seemed like a great option at first glance, but the Go library didn't seem very idiomatic, and the spec itself seems to have [some issues](https://github.com/fernet/spec/issues). This spec should be very easy to implement assuming you already have an AES-GCM library. A Go and Python implementation are provided.

AES-GCM with a 256-bit key is used as the encryption and authentication method.

All base-64 encoding is done with the "URL and Filename Safe" variant, defined in [RFC 4648](http://tools.ietf.org/html/rfc4648#section-5) as "base64url".

## Key Format

A *key* is the base64url encoding of a 256-bit random key.

## Token Format

A *token* is the base64url encoding of the concatenation of the following fields:

`Timestamp || Nonce || Ciphertext`

## Token Fields

**Timestamp - 64 bits**

Timestamp is the 64-bit, unsigned, big-endian encoding of the number of nanoseconds since January 1, 1970 UTC, i.e. the Unix epoch.

**Nonce - 96 bits**

Nonce is a randomly generated 96-bit nonce. While AES-GCM only requires unique nonces, this spec requires random nonces so that nonce management is not required.

**Ciphertext - 128 bits minimum**

Ciphertext is the encrypted and authenticated message. It includes the 128-bit AES-GCM authentication tag at the end.

## Generating a Token

1. Record the current time for the timestamp field.
2. Generate a new, unique nonce.
3. Encrypt the plaintext with AES-GCM using a 256-bit key to get the ciphertext.
    * The 64-bit timestamp is used as AES-GCM's "additional data".
4. Concatenate the timestamp, nonce, and ciphertext using the Token Format.
5. base64url encode the result from step 4 to get the token.

## Verifying and Decrypting a Token

1. base64url decode the token.
2. Check the token is at least the minimum length: 36 bytes
3. Separate the timestamp, nonce, and ciphertext
4. Verify and authenticate the ciphertext, nonce, and timestamp (as "additional data") using AES-GCM with the original 256-bit key.
5. If desired, verify the timestamp not expired.

## Note About Security

I'm not a security expert, by any definition of the term. I've chosen what I believe is a very simple and secure method for generating and verifying/decrypting tokens. I'd find it hard to believe there's any security issues with this spec (unless the underlying crypto is broken.) However, don't take my word for it. I'm comfortable using this for my needs, and you'll need to evaluate that for yourself.
