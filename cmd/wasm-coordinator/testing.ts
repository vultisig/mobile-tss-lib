import { executeKeyGeneration, hello } from "./init.ts";

const server = "http://127.0.0.1:8080";
const chainCode =
  "80871c0f885f953e5206e461630a9222148797e66276a83224c7b9b0f75b3ec0";
const publicKey =
  "020c0de41f4b57e64bfab9387a095d72b1f2c835c8083ae61e45a3d2de2dccda77";
const message = "aGVsbG8gd29ybGQK";
const derivationPath = "m/84'/0'/0'/0/0";
// const session random rounded number between 1 and 1m
const session = Math.floor(Math.random() * 1e6).toString();

console.log(`Session: ${session}`);

const keyFolderBase = "../../keys/";

const parties = ["first", "second", "third"];

// const response = await executeKeyGeneration(
//   server,
//   session,
//   "first",
//   "../keys/first",
//   parties.toString(),
//   chainCode,
// );

// const response = await hello();
// console.log(response);

const promises = parties.map((party) => {
  return executeKeyGeneration(
    server,
    session,
    party,
    keyFolderBase + party,
    parties.toString(),
    chainCode,
  )
    .then((publicKey) => {
      console.log(`Public key for ${party}: ${publicKey}`);
      return publicKey;
    })
    .catch((error) => {
      console.error(`Execution for ${party} failed:`, error);
      return null; // Handle error, e.g., return null or a specific error marker
    });
});

const results = await Promise.all(promises);

// Check all public keys
results.forEach((publicKey, index) => {
  console.log(publicKey);
});
