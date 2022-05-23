# ebpf-proxy-rs


Inspired by [go-ebpf-proxy-example](https://github.com/astoycos/go-ebpf-proxy-example).

## Prerequisites

1. Install a rust stable toolchain: `rustup install stable`
1. Install a rust nightly toolchain: `rustup install nightly`
1. Install bpf-linker: `cargo install bpf-linker`

## Run

This will setup a backend server, compile and run the program

```bash
docker run --name server -d -p 8080:80 nginx
cargo xtask run -- --service-vip 169.254.1.1 --service-backend $(docker inspect -f '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' server)
```

To test the service:
```bash
curl http://169.254.1.1:80
```

## License

This project is distributed under the terms of either the [MIT license] or the [Apache License] (version
2.0), at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in this crate by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.

[MIT license]: ./LICENSE-MIT
[Apache license]: ./LICENSE-APACHE