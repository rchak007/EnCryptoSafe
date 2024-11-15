// how to run - dont use "" when you supply the words

// (base) $ tsc aes.ts
// (base) $ node aes.js
// Choose an option:
// 1. Decrypt an encrypted Base64 string
//    Example: "gPinvU4XdB/S0Yv8AMWk4P7C3KaSQ5aIdgUNTY6FfSQ="
// 2. Encrypt a plaintext string to Base64
//    Example: "plug example hello current"
// Enter 1 or 2: 1
// Enter the Base64 encrypted string to decrypt: gPinvU4XdB/S0Yv8AMWk4P7C3KaSQ5aIdgUNTY6FfSQ=
// Decrypted (utf8): plug example hello current
// (base) $ node aes.js
// Choose an option:
// 1. Decrypt an encrypted Base64 string
//    Example: "gPinvU4XdB/S0Yv8AMWk4P7C3KaSQ5aIdgUNTY6FfSQ="
// 2. Encrypt a plaintext string to Base64
//    Example: "plug example hello current"
// Enter 1 or 2: 2
// Enter the plaintext string to encrypt: "plug example hello current"
// Encrypted (Base64): sHtvsDUyVdyvxUdHMaXd1zVwar1JOq/kPQmZRP80Hes=
// (base) $ node aes.js
// Choose an option:
// 1. Decrypt an encrypted Base64 string
//    Example: "gPinvU4XdB/S0Yv8AMWk4P7C3KaSQ5aIdgUNTY6FfSQ="
// 2. Encrypt a plaintext string to Base64
//    Example: "plug example hello current"
// Enter 1 or 2: 2
// Enter the plaintext string to encrypt: plug example hello current
// Encrypted (Base64): gPinvU4XdB/S0Yv8AMWk4P7C3KaSQ5aIdgUNTY6FfSQ=
// (base) $

// https://github.com/bcgit/pc-dart/blob/master/tutorials/aes-cbc.md
// https://www.javainuse.com/aesgenerator

import * as crypto from "crypto";
import * as readline from "readline";

// AES CBC encryption
function aesCbcEncrypt(key: Buffer, iv: Buffer, plaintext: Buffer): Buffer {
  if (![16, 24, 32].includes(key.length)) {
    throw new Error("Key must be 128, 192, or 256 bits.");
  }
  if (iv.length !== 16) {
    throw new Error("IV must be 128 bits.");
  }

  const cipher = crypto.createCipheriv("aes-128-cbc", key, iv);
  const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return encrypted;
}

// AES CBC decryption
function aesCbcDecrypt(key: Buffer, iv: Buffer, ciphertext: Buffer): Buffer {
  if (![16, 24, 32].includes(key.length)) {
    throw new Error("Key must be 128, 192, or 256 bits.");
  }
  if (iv.length !== 16) {
    throw new Error("IV must be 128 bits.");
  }

  const decipher = crypto.createDecipheriv("aes-128-cbc", key, iv);
  const decrypted = Buffer.concat([
    decipher.update(ciphertext),
    decipher.final(),
  ]);
  return decrypted;
}

function decryptFromEncryptedKey(key: Buffer, iv: Buffer, encrypted1: string) {
  const encryptedBuffer1 = Buffer.from(encrypted1, "base64");
  const decrypted = aesCbcDecrypt(key, iv, encryptedBuffer1);
  console.log("Decrypted (utf8):", decrypted.toString("utf8"));
}

function encryptToBase64(key: Buffer, iv: Buffer, plaintext: string) {
  const plaintextBuffer = Buffer.from(plaintext, "utf8");
  const encryptedBuffer = aesCbcEncrypt(key, iv, plaintextBuffer);
  const encryptedBase64 = encryptedBuffer.toString("base64");
  console.log("Encrypted (Base64):", encryptedBase64);
}

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
});

function promptForKeyAndIV(callback: (key: Buffer, iv: Buffer) => void) {
  rl.question("Enter your 16-byte AES key: ", (keyInput) => {
    rl.question("Enter your 16-byte AES IV: ", (ivInput) => {
      const key = Buffer.from(keyInput, "utf8");
      const iv = Buffer.from(ivInput, "utf8");

      if (key.length !== 16 || iv.length !== 16) {
        console.log("Error: Key and IV must each be exactly 16 bytes.");
        rl.close();
      } else {
        callback(key, iv);
      }
    });
  });
}

function showMenu() {
  console.log("Choose an option:");
  console.log("1. Decrypt an encrypted Base64 string");
  console.log('   Example: "gPinvU4XdB/S0Yv8AMWk4P7C3KaSQ5aIdgUNTY6FfSQ="');
  console.log("2. Encrypt a plaintext string to Base64");
  console.log('   Example: "plug example hello current"');

  rl.question("Enter 1 or 2: ", (option) => {
    promptForKeyAndIV((key, iv) => {
      if (option === "1") {
        rl.question(
          "Enter the Base64 encrypted string to decrypt: ",
          (encryptedInput) => {
            decryptFromEncryptedKey(key, iv, encryptedInput);
            rl.close();
          }
        );
      } else if (option === "2") {
        rl.question(
          "Enter the plaintext string to encrypt: ",
          (plaintextInput) => {
            encryptToBase64(key, iv, plaintextInput);
            rl.close();
          }
        );
      } else {
        console.log("Invalid option. Please choose 1 or 2.");
        rl.close();
      }
    });
  });
}

// Start the menu
showMenu();
