// ECDH-AES-256-GCM - diffie Hellman
import {
  randomBytes,
  createCipheriv,
  createDecipheriv,
  createECDH,
} from "node:crypto";

const alice = createECDH("secp256k1");
alice.generateKeys();

const bob = createECDH("secp256k1");
bob.generateKeys();

const alicePublicKeyBase64 = alice.getPublicKey().toString("base64");
const bobPublicKeyBase64 = bob.getPublicKey().toString("base64");

const aliceSharedKey = alice.computeSecret(bobPublicKeyBase64, "base64", "hex");
const bobSharedKey = bob.computeSecret(alicePublicKeyBase64, "base64", "hex");

console.log(aliceSharedKey === bobSharedKey);
console.log("Alice: ", aliceSharedKey);
console.log("Bob: ", bobSharedKey);

const MESSAGE = "Óla Luposki!";

// Encrypt
const IV = randomBytes(16);
const cipher = createCipheriv(
  "aes-256-gcm",
  Buffer.from(aliceSharedKey, "hex"),
  IV
);

let encrypted = cipher.update(MESSAGE, "utf8", "hex");
encrypted += cipher.final("hex");

let auth_tag = cipher.getAuthTag().toString("hex");

console.table({
  IV: IV.toString("hex"),
  encrypted,
  auth_tag,
});

const payload = IV.toString("hex") + encrypted + auth_tag;

const payloadBase64 = Buffer.from(payload, "hex").toString("base64");

console.log("Payload-Base64: ", payloadBase64);

// Decrypt
// bob will do from here => bob fará daqui

const bob_payload = Buffer.from(payloadBase64, "base64").toString("hex");

const bob_iv = bob_payload.substring(0, 32);
const bob_encrypted = bob_payload.substring(32, bob_payload.length - 32);
const bob_auth_tag = bob_payload.substring(bob_payload.length - 32, bob_payload.length);


console.table({
  bob_iv,
  bob_encrypted,
  bob_auth_tag,
});

try {
    const decipher = createDecipheriv(
    "aes-256-gcm",
    Buffer.from(bobSharedKey, "hex"),
    Buffer.from(bob_iv, "hex")
  );
  
  decipher.setAuthTag(Buffer.from(bob_auth_tag, "hex"));
  
  let decrypted = decipher.update(bob_encrypted, "hex", "utf8");
  decrypted += decipher.final("utf8");
  
  console.log("\n\n=====> Decrypted message: ", decrypted);
} catch (error) {
    console.log(error.message);
}
