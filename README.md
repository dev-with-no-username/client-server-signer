# client-server-signer

## How it works

This project allows you to use various programming languages ​​to test the aws sig_v4 library running on a Go server. These programming languages ​​are:

- Python
- Java
- Javascript
- Rust

## Running examples

To run the examples, you must first start the Go server with the following command:

```bash
    task run-go-server
```

and then, depending on the language you want to use, simply launch one of the following commands:

- Python

```bash
    task build-python-venv # to make sure you have all the necessary libraries in the virtual environment
    task run-python-client
```

- Java

```bash
    task run-java-client
```

- Javascript

```bash
    task run-js-client
```

- Rust

```bash
    task run-rust-client
```

## Peculiarities

| Language | Client side | Server side | Content-length before signature | X-amz-date before signature |
| -------- | ----------- | ----------- | ------------------------------- | --------------------------- |
| Python | content-length added after signature | it considers everything that is in the SignedHeaders by sanitizing those headers to avoid adding some unaccepted ones before signing | accepted | accepted |
| Java | content-length added after signature | it considers everything that is in the SignedHeaders by sanitizing those headers to avoid adding some unaccepted ones before signing | not accepted dal client che poi effettuerà la chiamata | not accepted |
| Javascript | content-length added after signature | it considers everything that is in the SignedHeaders by sanitizing those headers to avoid adding some unaccepted ones before signing | accepted | not accepted |
| Rust | content-length added after signature | it considers everything that is in the SignedHeaders by sanitizing those headers to avoid adding some unaccepted ones before signing | accepted | accepted |

## Interoperability

Considering that with the Go server all languages used client side work correctly, I tried to make every language used on
the client side work with every other language used on the server side, and the following table shows the interoperability
between these various languages ​​in all tested client-server configurations:

| Client side | Server side | Interoperable |
| ----------- | ----------- | ------------- |
| Python | Java | yes |
| Python | Javascript | yes |
| Python | Rust | yes |
| Javascript | Python | yes |
| Javascript | Java | yes |
| Javascript | Rust | yes |
| Java | Python | yes |
| Java | Javascript | yes |
| Java | Rust | yes |
| Rust | Python | yes |
| Rust | Java | yes |
| Rust | Javascript | yes |
