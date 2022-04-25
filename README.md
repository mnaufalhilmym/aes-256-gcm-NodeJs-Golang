# Equivalent Coding of aes-256-gcm Algorithm on Golang and Node.js

## Node.js

```javascript
const encrypted = crypto.Encrypt("enryption test");

console.log(encrypted); // Print: encKey, encCipherText, encAuthTag, encIv

const decrypted = crypto.Decrypt(encrypted);

console.log(decrypted); // Will print "encryption test"
```

## Golang

```go
encrypted, err := Encrypt("encryption test")
if err != nil {
  log.Fatalln(err)
}

fmt.Println(encrypted) // Print: encKey, encCipherText, encAuthTag, encNonce

decrypted, err := Decrypt(encrypted)
if err != nil {
  log.Fatalln(err)
}

fmt.Println(decrypted) // Will print "encryption test"
```

## Note

The encrypted code from Node.js can be decrypted using Golang and vice versa.
