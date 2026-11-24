const crypto = require("crypto");

const ALGORITHM = "aes-256-gcm";
const IV_LENGTH = 12;
const AUTH_TAG_LENGTH = 16;

function getEncryptionKey() {
const keyHex = process.env.ENCRYPTION_KEY;


if (!keyHex || !/^[0-9a-fA-F]{64}$/.test(keyHex)) {
    throw new Error(
        "ENCRYPTION_KEY must contain exactly 64 hexadecimal characters."
    );
}

return Buffer.from(keyHex, "hex");


}

// Encrypt file contents
function encryptBuffer(buffer) {
const key = getEncryptionKey();


// Generate a unique initialization vector for each encryption
const iv = crypto.randomBytes(IV_LENGTH);

const cipher = crypto.createCipheriv(
    ALGORITHM,
    key,
    iv
);

const encrypted = Buffer.concat([
    cipher.update(buffer),
    cipher.final()
]);

const authTag = cipher.getAuthTag();

return Buffer.concat([
    Buffer.from("SSF1"),
    iv,
    authTag,
    encrypted
]);


}

// Decrypt and authenticate file contents
function decryptBuffer(encryptedBuffer) {
const key = getEncryptionKey();


const headerLength = 4 + IV_LENGTH + AUTH_TAG_LENGTH;

if (
    encryptedBuffer.length < headerLength ||
    encryptedBuffer.subarray(0, 4).toString() !== "SSF1"
) {
    throw new Error("Invalid or corrupted encrypted file.");
}

const iv = encryptedBuffer.subarray(4, 16);
const authTag = encryptedBuffer.subarray(16, 32);
const ciphertext = encryptedBuffer.subarray(32);

const decipher = crypto.createDecipheriv(
    ALGORITHM,
    key,
    iv
);

decipher.setAuthTag(authTag);

// Authentication failure throws an error during final()
return Buffer.concat([
    decipher.update(ciphertext),
    decipher.final()
]);


}

module.exports = {
encryptBuffer,
decryptBuffer
};
