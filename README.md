# mobile-tss-lib

```bash
# after I run `go mod tidy` , I will have to download mobile bind library again , otherwise gomobile command won't run
go get golang.org/x/mobile/bind
gomobile bind -v -target=ios,macos,iossimulator -tags=ios,macos,iossimulator ./tss
```