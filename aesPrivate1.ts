// how to run - dont use "" when you supply the words

// aesPrivate1 - we are trying to now encrypt a private key. Before we did seed phrase which was text and it worked.
// but not working if its private key -

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
import * as crypto from "crypto";
import * as readline from "readline";

// Load environment variables from .env file (if needed)
import * as dotenv from "dotenv";
dotenv.config();

// Access key and IV from environment variables
const myKEY = Buffer.from(process.env.AES_KEY as string, "utf8"); // AES Key from .env
const myIV = Buffer.from(process.env.AES_IV as string, "utf8"); // AES IV from .env

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

// Function to encrypt a plaintext string to Base64
function encryptToBase64(plaintext: string) {
  const plaintextBuffer = Buffer.from(plaintext, "utf8");
  const encryptedBuffer = aesCbcEncrypt(myKEY, myIV, plaintextBuffer);
  const encryptedBase64 = encryptedBuffer.toString("base64");
  console.log("Encrypted (Base64):", encryptedBase64);
}
// Function to encrypt a private key
function encryptPrivateKey(privateKey: string) {
  // Assuming the private key is provided in hex format
  try {
    const privateKeyBuffer = Buffer.from(privateKey, "hex");

    // Encrypt using AES-CBC
    const encryptedBuffer = aesCbcEncrypt(myKEY, myIV, privateKeyBuffer);
    const encryptedBase64 = encryptedBuffer.toString("base64");

    console.log("Encrypted Private Key (Base64):", encryptedBase64);
  } catch (error) {
    // console.error("Error during encryption:", error.message);
    console.error("Error during encryption:", (error as Error).message);
  }
}
function decryptToPrivateKey(encryptedPrivateKey: string) {
  try {
    // Convert Base64 string to Buffer for decryption
    const encryptedBuffer = Buffer.from(encryptedPrivateKey, "base64");
    const decryptedBuffer = aesCbcDecrypt(myKEY, myIV, encryptedBuffer);

    // Convert decrypted buffer to hex string
    const decryptedHex = decryptedBuffer.toString("hex");

    console.log("Decrypted Private Key (hex):", decryptedHex);
  } catch (error) {
    // console.error("Error during decryption:", error.message);
    console.error("Error during decryption:", (error as Error).message);
  }
}

// Existing decrypt function for other cases
function decryptFromEncryptedKey(encrypted1: string) {
  const encryptedBuffer1 = Buffer.from(encrypted1, "base64");
  const decrypted = aesCbcDecrypt(myKEY, myIV, encryptedBuffer1);
  console.log("Decrypted (utf8):", decrypted.toString("utf8"));
}

// Create readline interface for user input
const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
});

// Show menu and prompt for input
function showMenu() {
  console.log("Choose an option:");
  console.log("1. Decrypt an encrypted Base64 string");
  console.log('   Example: "gPinvU4XdB/S0Yv8AMWk4P7C3KaSQ5aIdgUNTY6FfSQ="');
  console.log("2. Encrypt a plaintext string to Base64");
  console.log('   Example: "plug example hello current"');
  console.log("3. Encrypt a private key");
  console.log("4. Decrypt a private key");

  rl.question("Enter 1, 2, 3, or 4: ", (option) => {
    if (option === "1") {
      rl.question(
        "Enter the Base64 encrypted string to decrypt: ",
        (encryptedInput) => {
          decryptFromEncryptedKey(encryptedInput);
          rl.close();
        }
      );
    } else if (option === "2") {
      rl.question(
        "Enter the plaintext string to encrypt: ",
        (plaintextInput) => {
          encryptToBase64(plaintextInput);
          rl.close();
        }
      );
    } else if (option === "3") {
      rl.question(
        "Enter the private key (in Base64 or hex format): ",
        (privateKeyInput) => {
          encryptPrivateKey(privateKeyInput);
          rl.close();
        }
      );
    } else if (option === "4") {
      rl.question(
        "Enter the encrypted Base64 private key to decrypt: ",
        (encryptedPrivateKey) => {
          decryptToPrivateKey(encryptedPrivateKey);
          rl.close();
        }
      );
    } else {
      console.log("Invalid option. Please choose 1, 2, 3, or 4.");
      rl.close();
    }
  });
}

// Start the menu
showMenu();
