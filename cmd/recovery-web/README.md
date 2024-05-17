# Recovery Web

This is a golang wasm web app that allows you to upload shares of TSS and export the private key in case of an emergency.

## How to run

## How to run it (manually)

```
make
```

Navigate to: [http://localhost:3000/index.html](http://localhost:3000/index.html)

Compile the `.wasm` file

```shell
GOOS=js GOARCH=wasm go build -o static/main.wasm cmd/wasm/main.go
```

Copy the supporting JavaScript file

```shell
cp "$(go env GOROOT)/misc/wasm/wasm_exec.js" ./static
```

Start the webserver

```shell
go run ./cmd/webserver/main.go
```

Navigate to: [http://localhost:3000/index.html](http://localhost:3000/index.html)
