require("dotenv").config();

const {
encryptBuffer,
decryptBuffer
} = require("./services/encryptionService");

const originalText = "SecureShare confidential test file.";

try {
const originalBuffer = Buffer.from(originalText, "utf8");


const encryptedBuffer = encryptBuffer(originalBuffer);

const decryptedBuffer = decryptBuffer(encryptedBuffer);

console.log("Original text:", originalText);

console.log(
    "Encrypted file begins with:",
    encryptedBuffer.subarray(0, 4).toString()
);

console.log(
    "Encrypted content differs from original:",
    !encryptedBuffer.equals(originalBuffer)
);

console.log(
    "Decryption successful:",
    decryptedBuffer.toString("utf8") === originalText
);

// Verify that tampering is detected
const tamperedBuffer = Buffer.from(encryptedBuffer);
tamperedBuffer[tamperedBuffer.length - 1] ^= 1;

try {
    decryptBuffer(tamperedBuffer);
    console.error("ERROR: Tampering was not detected.");
    process.exitCode = 1;
} catch {
    console.log("Tampering detected successfully.");
}


} catch (error) {
console.error("Encryption test failed:", error.message);
process.exitCode = 1;
}
