import { VercelRequest, VercelResponse } from "@vercel/node";
import * as crypto from "crypto";

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

// Vercel API handler
export default function handler(req: VercelRequest, res: VercelResponse) {
  try {
    const { key, iv, plaintext, encrypted } = req.body;

    if (req.method === "POST" && plaintext) {
      // Encrypt plaintext
      const keyBuffer = Buffer.from(key, "utf8");
      const ivBuffer = Buffer.from(iv, "utf8");
      const plaintextBuffer = Buffer.from(plaintext, "utf8");

      const encryptedBuffer = aesCbcEncrypt(
        keyBuffer,
        ivBuffer,
        plaintextBuffer
      );
      const encryptedBase64 = encryptedBuffer.toString("base64");

      return res.status(200).json({ encrypted: encryptedBase64 });
    }

    if (req.method === "POST" && encrypted) {
      // Decrypt ciphertext
      const keyBuffer = Buffer.from(key, "utf8");
      const ivBuffer = Buffer.from(iv, "utf8");
      const encryptedBuffer = Buffer.from(encrypted, "base64");

      const decryptedBuffer = aesCbcDecrypt(
        keyBuffer,
        ivBuffer,
        encryptedBuffer
      );
      const decryptedText = decryptedBuffer.toString("utf8");

      return res.status(200).json({ decrypted: decryptedText });
    }

    // Handle invalid requests
    return res
      .status(400)
      .json({ error: "Invalid request. Please provide correct parameters." });
  } catch (error: any) {
    return res.status(500).json({ error: error.message });
  }
}
