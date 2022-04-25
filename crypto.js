const crypto = require("crypto");

function generateRandomKey() {
  const randomKey = crypto.randomBytes(32);
  return randomKey;
}

function generateRandomIV() {
  const iv = crypto.randomBytes(12);
  return iv;
}

// plain: string
exports.Encrypt = function Encrypt(plain) {
  const key = generateRandomKey();
  const iv = generateRandomIV();
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);

  let encrypted = cipher.update(plain, "utf8", "base64url");
  encrypted += cipher.final("base64url");

  return {
    encKey: key.toString("base64url"),
    encCipherText: encrypted,
    encAuthTag: cipher.getAuthTag().toString("base64url"),
    encIv: iv.toString("base64url"),
  };
};

// encKey: string
// encCipherText: string
// encAuthTag: string
// encIv: string
exports.Decrypt = function Decrypt({ encKey, encCipherText, encAuthTag, encIv }) {
  const key = Buffer.from(encKey, "base64url")
  const authTag = Buffer.from(encAuthTag, "base64url")
  const iv = Buffer.from(encIv, "base64url")

  const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
  decipher.setAuthTag(authTag);
  const decrypted = decipher.update(encCipherText, "base64url", "utf8");

  return decrypted + decipher.final("utf8");
};
