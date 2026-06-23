#!/usr/bin/env node
import { createDecipheriv, pbkdf2Sync } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { stdin as input, stdout as output } from "node:process";

const MAGIC = "CFWDAVBACKUP1\n";

const [inputPath, outputPathArg] = process.argv.slice(2);
if (!inputPath) {
  console.error("Usage: node scripts/decrypt-backup.mjs <backup.tar.gz.enc> [output.tar.gz]");
  process.exit(1);
}

const encrypted = readFileSync(inputPath);
const magicBytes = Buffer.from(MAGIC, "utf8");
if (!encrypted.subarray(0, magicBytes.length).equals(magicBytes)) {
  throw new Error("Invalid backup file magic");
}

const headerLengthOffset = magicBytes.length;
const headerLength = encrypted.readUInt32BE(headerLengthOffset);
const headerStart = headerLengthOffset + 4;
const headerEnd = headerStart + headerLength;
const header = JSON.parse(encrypted.subarray(headerStart, headerEnd).toString("utf8"));
if (header.version !== 1 || header.cipher !== "AES-256-GCM" || header.kdf !== "PBKDF2-SHA256") {
  throw new Error("Unsupported backup format");
}

const password = await readPassword("Backup password: ");

const ciphertextWithTag = encrypted.subarray(headerEnd);
const authTag = ciphertextWithTag.subarray(ciphertextWithTag.length - 16);
const ciphertext = ciphertextWithTag.subarray(0, ciphertextWithTag.length - 16);
const key = pbkdf2Sync(
  password,
  Buffer.from(header.salt, "base64"),
  header.iterations,
  32,
  "sha256",
);
const decipher = createDecipheriv("aes-256-gcm", key, Buffer.from(header.iv, "base64"));
decipher.setAuthTag(authTag);

const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
const outputPath = outputPathArg || header.filename || inputPath.replace(/\.enc$/i, "");
writeFileSync(outputPath, plaintext);
console.log(`Wrote ${outputPath}`);

async function readPassword(prompt) {
  if (process.env.BACKUP_PASSWORD) {
    return process.env.BACKUP_PASSWORD;
  }
  if (!input.isTTY) {
    const chunks = [];
    for await (const chunk of input) {
      chunks.push(Buffer.from(chunk));
    }
    return Buffer.concat(chunks).toString("utf8").split(/\r?\n/, 1)[0];
  }

  return new Promise((resolve, reject) => {
    let password = "";
    output.write(prompt);
    input.setRawMode(true);
    input.resume();

    function finish() {
      input.setRawMode(false);
      input.pause();
      input.off("data", onData);
      output.write("\n");
      resolve(password);
    }

    function onData(chunk) {
      const char = chunk.toString("utf8");
      if (char === "\u0003") {
        input.setRawMode(false);
        input.pause();
        input.off("data", onData);
        reject(new Error("Cancelled"));
        return;
      }
      if (char === "\r" || char === "\n") {
        finish();
        return;
      }
      if (char === "\u007f") {
        password = password.slice(0, -1);
        return;
      }
      password += char;
    }

    input.on("data", onData);
  });
}
