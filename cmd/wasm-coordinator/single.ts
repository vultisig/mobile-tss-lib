import { readFile } from "fs/promises";
import { dirname, resolve } from "path";
import { fileURLToPath } from "url";
import "./wasm_exec.js"; // This adds Go to the global scope

const server = "http://127.0.0.1:8080";
const chainCode =
  "80871c0f885f953e5206e461630a9222148797e66276a83224c7b9b0f75b3ec0";
const publicKey =
  "020c0de41f4b57e64bfab9387a095d72b1f2c835c8083ae61e45a3d2de2dccda77";
const message = "aGVsbG8gd29ybGQK";
const derivationPath = "m/84'/0'/0'/0/0";
const session = Math.floor(Math.random() * 1e6).toString();

async function main() {
  const CURRENT_DIR = dirname(fileURLToPath(import.meta.url));
  const wasmBuffer = await readFile(resolve(CURRENT_DIR, "./main.wasm"));

  const keyFolderBase = "../../keys/";
  const parties = ["first"];

  const go = new global.Go();
  const { instance } = await WebAssembly.instantiate(
    wasmBuffer,
    go.importObject,
  );
  go.run(instance);

  const party = "first";

  const publicKey = await global.executeKeyGeneration(
    server,
    session,
    party,
    keyFolderBase + party,
    parties.toString(),
    chainCode,
  );
  console.log(`Public key for ${party}: ${publicKey}`);
  return publicKey;
}

main();
