require("./wasm_exec.js");

const go = new Go();

const buf = await Bun.file("./main.wasm").arrayBuffer();
const inst = await WebAssembly.instantiate(buf, go.importObject);

go.run(inst.instance);
