import { expect, test } from "bun:test";
import { executeKeyGeneration } from "./init.ts";

const server = "http://127.0.0.1:8080";
const chainCode =
  "80871c0f885f953e5206e461630a9222148797e66276a83224c7b9b0f75b3ec0";
const publicKey =
  "020c0de41f4b57e64bfab9387a095d72b1f2c835c8083ae61e45a3d2de2dccda77";
const message = "aGVsbG8gd29ybGQK";
const derivationPath = "m/84'/0'/0'/0/0";
// const session random rounded number between 1 and 1m
const session = 1;

test("executeKeyGeneration", async () => {
  const parties = ["first", "second", "third"];

  const publicKey = await executeKeyGeneration(
    server,
    session,
    "first",
    "../keys/first",
    parties,
    chainCode,
  );
  expect(publicKey).toBeTruthy();
});

// test("executeKeySigning", async () => {
//   const parties = ["first", "third"];
//   const keygenInput: KeygenInput = {
//     publicKey,
//     server,
//     session,
//     parties,
//     chainCode,
//     derivePath,
//     message,
//     key: "first",
//     keyFolder: "../keys/first",
//   };

//   await performECDSAKeySigning(keygenInput);
//   // Add assertions if needed
// });
