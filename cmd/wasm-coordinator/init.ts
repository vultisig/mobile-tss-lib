import { readFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import "./wasm_exec.js"; // This adds global.Go

// Load the WebAssembly wasm file
const CURRENT_DIR = dirname(fileURLToPath(import.meta.url));
const wasmBuffer = await readFile(resolve(CURRENT_DIR, "./main.wasm"));

// Set up the WebAssembly module instance
const go = new global.Go();
const { instance } = await WebAssembly.instantiate(wasmBuffer, go.importObject);
go.run(instance);

// Export extractURL from the global object
export const executeKeyGeneration = global.executeKeyGeneration;
export const hello = global.hello;

// Cleanup references
delete global.Go;
delete global.executeKeyGeneration;
delete global.hello;
