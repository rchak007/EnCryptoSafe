// const express = require("express");
// const bodyParser = require("body-parser");

// import express, { Request, Response } from "express";
// import bodyParser from "body-parser";
import * as crypto from "crypto";
import path from "path";

const express = require("express");
const bodyParser = require("body-parser");
import { Request, Response } from "express"; // You can still import types like this

// Create an Express app
const app = express();
const port = process.env.PORT || 3000;

// Middleware to parse JSON and form data
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// TypeScript type for request body
// interface EncryptDecryptRequestBody {
//   key: string;
//   iv: string;
//   plaintext?: string;
//   encrypted?: string;
// }

// AES encryption function
function aesCbcEncrypt(key: Buffer, iv: Buffer, plaintext: Buffer): Buffer {
  if (![16, 24, 32].includes(key.length)) {
    throw new Error("Key must be 128, 192, or 256 bits.");
  }
  if (iv.length !== 16) {
    throw new Error("IV must be 128 bits.");
  }

  const cipher = crypto.createCipheriv("aes-128-cbc", key, iv);
  return Buffer.concat([cipher.update(plaintext), cipher.final()]);
}

// AES decryption function
function aesCbcDecrypt(key: Buffer, iv: Buffer, ciphertext: Buffer): Buffer {
  if (![16, 24, 32].includes(key.length)) {
    throw new Error("Key must be 128, 192, or 256 bits.");
  }
  if (iv.length !== 16) {
    throw new Error("IV must be 128 bits.");
  }

  const decipher = crypto.createDecipheriv("aes-128-cbc", key, iv);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}

app.use(express.static(path.join(__dirname, "public")));

// Default route to serve index.html
app.get("/", (req: Request, res: Response) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

// Route for encryption
// app.post(
//   "/encrypt",
//     (req: Request<{}, {}, EncryptDecryptRequestBody>, res: Response) => {
app.post("/encrypt", (req: Request, res: Response) => {
  try {
    // const { key, iv, plaintext } = req.body;
    const { key, iv, plaintext } = req.body as {
      key: string;
      iv: string;
      plaintext: string;
    };
    if (!key || !iv || !plaintext) {
      return res.status(400).json({ error: "Missing required parameters." });
    }

    const keyBuffer = Buffer.from(key, "utf8");
    const ivBuffer = Buffer.from(iv, "utf8");
    const plaintextBuffer = Buffer.from(plaintext, "utf8");

    const encryptedBuffer = aesCbcEncrypt(keyBuffer, ivBuffer, plaintextBuffer);
    const encryptedBase64 = encryptedBuffer.toString("base64");

    res.json({ encrypted: encryptedBase64 });
  } catch (error: any) {
    res.status(500).json({ error: (error as any).message });
  }
});

// Route for decryption
// app.post(
//   "/decrypt",
//   (req: Request<{}, {}, EncryptDecryptRequestBody>, res: Response) => {
app.post("/decrypt", (req: Request, res: Response) => {
  try {
    // const { key, iv, encrypted } = req.body;
    const { key, iv, encrypted } = req.body as {
      key: string;
      iv: string;
      encrypted: string;
    };
    if (!key || !iv || !encrypted) {
      return res.status(400).json({ error: "Missing required parameters." });
    }
    const keyBuffer = Buffer.from(key, "utf8");
    const ivBuffer = Buffer.from(iv, "utf8");
    const encryptedBuffer = Buffer.from(encrypted, "base64");

    const decryptedBuffer = aesCbcDecrypt(keyBuffer, ivBuffer, encryptedBuffer);
    const decryptedText = decryptedBuffer.toString("utf8");

    res.json({ decrypted: decryptedText });
  } catch (error) {
    res.status(500).json({ error: (error as any).message });
  }
});

// Start the server
app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
});
