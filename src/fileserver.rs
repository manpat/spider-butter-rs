use std::net::{TcpStream, TcpListener};
use std::sync::mpsc::Receiver;
use std::io::{Write, Read};
use std::time;
use std::str;

use std::path::Path;

use mappings::*;
use http;

pub fn start(listener: TcpListener, mapping_channel: Receiver<Mappings>) {
	let mut buf = [0u8; 8<<10];

	let mut mappings = Mappings::new();

	for stream in listener.incoming() {
		if let Ok(new_mappings) = mapping_channel.try_recv() {
			mappings = new_mappings;
		}

		if !stream.is_ok() {
			continue
		}

		let mut stream = stream.unwrap();

		// TODO: poll or async instead of block until timeout
		match stream.set_read_timeout(Some(time::Duration::from_millis(500))) {
			Ok(()) => {}, Err(e) => {
				println!("[fsrv] set_read_timeout failed: {}", e);
				continue
			}
		}

		let size = stream.read(&mut buf).unwrap_or(0);
		if size == 0 { continue }

		let reqstr = match str::from_utf8(&buf[0..size]) {
			Ok(string) => string,
			Err(_) => continue,
		};

		let request = match http::Request::parse(&reqstr) {
			Ok(r) => r,
			Err(e) => {
				println!("Parsing request: {}", e);
				let _ = http::Response::new("HTTP/1.1 400 Bad Request").write_to_stream(&mut stream);
				continue;
			}
		};

		let encodings = request.get("Accept-Encoding")
			.map(|s| s.split_terminator(',').map(str::trim).collect())
			.unwrap_or(Vec::new());

		let encoding = encodings.iter()
			.find(|&&enc| enc == "deflate" || enc == "gzip")
			.cloned();

		if let Some(path) = mappings.get_route(request.uri()) {
			send_file(&mut stream, path, encoding);
		} else {
			let _ = http::Response::new("HTTP/1.1 404 File not found")
				.write_to_stream(&mut stream);
		}
	}
}

fn send_file(mut stream: &mut TcpStream, filepath: &Path, encoding: Option<&str>) {
	use std::fs::File;
	use flate2::Compression;
	use flate2::write::{GzEncoder, DeflateEncoder};

	// TODO: cache
	let mut f = match File::open(filepath) {
		Ok(f) => f,
		Err(e) => {
			println!("Couldn't open requested file '{:?}': {}", filepath, e);
			let _ = http::Response::new("HTTP/1.1 500 Internal Server Error")
				.write_to_stream(&mut stream);

			return
		}
	};

	let mut body_buffer = Vec::new();
	if let Err(e) = f.read_to_end(&mut body_buffer) {
		println!("Couldn't read requested file '{:?}': {}", filepath, e);
		let _ = http::Response::new("HTTP/1.1 500 Internal Server Error")
			.write_to_stream(&mut stream);

		return
	}

	let mut res = http::Response::new("HTTP/1.1 200 OK");

	if let Some(encoding) = encoding {
		let mut encoded_buffer = Vec::new();

		let write_result = match encoding {
			"gzip" =>
				GzEncoder::new(&mut encoded_buffer, Compression::Default)
					.write_all(&body_buffer),

			"deflate" =>
				DeflateEncoder::new(&mut encoded_buffer, Compression::Default)
					.write_all(&body_buffer),

			_ => {
				println!("Couldn't encode requested file '{:?}': Unknown encoding '{}'", filepath, encoding);
				let _ = http::Response::new("HTTP/1.1 500 Internal Server Error")
					.write_to_stream(&mut stream);
					
				return
			}
		};

		if write_result.is_ok() {
			body_buffer = encoded_buffer;
			res.set("Content-Encoding", encoding);
		} else {
			println!("Couldn't encode requested file '{:?}': {}", filepath, write_result.err().unwrap());
		}
	}

	res.set_body(&body_buffer);
	res.write_to_stream(&mut stream).unwrap();
}