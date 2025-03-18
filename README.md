<p align=center><img src="https://github.com/user-attachments/assets/c3cc15f9-b4fd-4aa5-b08b-d5e4948dee01" width=100></p>

<h1 align=center>CollapseScanner</h1>

<h2 align=center>Jar scanning tool for links and ips</h2>

## Arguments

> Since version 0.1.2, the following arguments have been added:

- `--help`: Really?
- `--log <FILE>`:  Log the results to a file.

In addition, users can now simply add a file as an argument to scan it:
```
CollapseScanner.exe program.jar
```

Or with cargo
```sh
cargo run -- <path-to-file> (or arguments)
```

## Showcase
<img src="https://github.com/user-attachments/assets/b9a219e4-50d5-4661-ab82-c4976b2913ed" width=500>

### Build Instructions:

1. Clone the repository:

```sh
git clone https://github.com/CollapseLoader/CollapseScanner.git
cd CollapseScanner
```

2. Build the project:

```sh
cargo build --release
```
