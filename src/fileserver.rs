use std::net::{TcpStream, TcpListener};
use std::sync::mpsc::{self, Receiver};
use std::io::{Write, Read};
use std::thread;
use std::time;
use std::str;
use std::io;

use std::path::Path;
use std::rc::Rc;

use coro_util::*;
use tcp_util::*;
use mappings::*;
use http;

#[derive(Clone, Copy)]
enum Encoding {
	Gzip,
	Deflate,
}

pub fn start(listener: TcpListener, mapping_channel: Receiver<Mappings>) {
	let mut mappings = Rc::new(Mappings::new());

	let (tx, rx) = mpsc::channel::<Coro<()>>();

	let coro_thread = thread::spawn(move || {
		let mut coros = Vec::new();

		loop {
			// Block until we receive a new connection
			match rx.recv() {
				Ok(c) => coros.push(c),
				Err(e) => {
					println!("[fsrv] Rx error: {:?}", e);
					break;
				}
			}

			// Process all connections until completion
			loop {
				for c in rx.try_iter() {
					coros.push(c);
				}

				for c in coros.iter_mut() {
					c.next();
				}

				coros.retain(Coro::is_valid);
				if coros.is_empty() { break }

				thread::sleep(time::Duration::from_millis(3));
			}
		}
	});

	for stream in listener.incoming() {
		if let Ok(new_mappings) = mapping_channel.try_recv() {
			mappings = Rc::new(new_mappings);
		}

		if !stream.is_ok() {
			continue
		}

		let coro = start_stream_process(stream.unwrap(), mappings.clone());
		tx.send(coro).unwrap();
	}

	coro_thread.join().unwrap();
}

fn start_stream_process(mut stream: TcpStream, mappings: Rc<Mappings>) -> Coro<()> {
	Coro::from(move || {
		if let Err(e) = stream.set_nonblocking(true) {
			println!("[fsrv] set_nonblocking failed: {}", e);
			return;
		}

		let coro = {
			let mut buf = [0u8; 8<<10];
			let mut read_wait_timeout = 0;

			let size = loop {
				use std::io::ErrorKind as EK;

				match stream.read(&mut buf) {
					Ok(0) => return,
					Ok(s) => break s,
					Err(e) => match e.kind() {
						EK::WouldBlock => {},
						_ => return,
					}
				}

				read_wait_timeout += 1;
				if read_wait_timeout > 1000 {
					println!("Timeout!");
					return
				} else {
					yield
				}
			};

			let request = match str::from_utf8(&buf[0..size]) {
				Ok(string) => http::Request::parse(string),
				Err(_) => return,
			};

			let request = match request {
				Ok(r) => r,
				Err(_) => {
					let _ = http::Response::new("HTTP/1.1 400 Bad Request").write_to_stream(&mut stream);
					return;
				}
			};

			let mut encodings = request.get("Accept-Encoding")
				.map(|s| s.split_terminator(',')
					.map(str::trim)
					.filter_map(|enc| match enc {
						"deflate" => Some(Encoding::Deflate),
						"gzip" => Some(Encoding::Gzip),
						_ => None
					})
					.collect())
				.unwrap_or(Vec::new());

			encodings.sort_unstable_by_key(|k| match *k {
				Encoding::Gzip => 1,
				Encoding::Deflate => 2,
			});

			if let Some(path) = mappings.get_route(request.uri()) {
				send_file_async(stream, path, encodings.first().cloned())
			} else {
				http::Response::new("HTTP/1.1 404 File not found")
					.write_header_async(stream)
			}
		};

		for res in coro {
			if let Err(e) = res {
				println!("Error sending data: {:?}", e.kind());
				return
			}

			yield
		}
	})
}

fn send_file_async(mut stream: TcpStream, filepath: &Path, encoding: Option<Encoding>) -> Coro<io::Result<()>> {
	use std::fs::File;
	use flate2::Compression;
	use std::io::ErrorKind::{WouldBlock, Interrupted};
	use flate2::write::{GzEncoder, DeflateEncoder};

	// TODO: cache
	let mut f = match File::open(filepath) {
		Ok(f) => f,
		Err(e) => {
			println!("Couldn't open requested file '{:?}': {}", filepath, e);
			return http::Response::new("HTTP/1.1 500 Internal Server Error")
				.write_header_async(stream)
		}
	};

	let mut body_buffer = Vec::new();
	if let Err(e) = f.read_to_end(&mut body_buffer) {
		println!("Couldn't read requested file '{:?}': {}", filepath, e);
		return http::Response::new("HTTP/1.1 500 Internal Server Error")
			.write_header_async(stream)
	}

	Coro::from(move || {
		let mut res = http::Response::new("HTTP/1.1 200 OK");

		if let Some(encoding) = encoding {
			let mut encoded_buffer = Vec::new();

			let write_result = match encoding {
				Encoding::Gzip =>
					GzEncoder::new(&mut encoded_buffer, Compression::Default)
						.write_all(&body_buffer),

				Encoding::Deflate =>
					DeflateEncoder::new(&mut encoded_buffer, Compression::Default)
						.write_all(&body_buffer),
			};

			if write_result.is_ok() {
				body_buffer = encoded_buffer;
				match encoding {
					Encoding::Gzip => res.set("Content-Encoding", "gzip"),
					Encoding::Deflate => res.set("Content-Encoding", "deflate"),
				}
			} else {
				println!("Failed to encode file: {}", write_result.err().unwrap());
			}
		}

		let response_head = res.header_string().into_bytes();
		let mut read_amt = 0;

		loop {
			let result = stream.write(&response_head[read_amt..]);
			yield match result {
				Err(ref e) if e.kind() == WouldBlock => Ok(()),
				Err(ref e) if e.kind() == Interrupted => Ok(()),
				Err(e) => Err(e),
				Ok(sz) => {
					read_amt += sz;
					if read_amt >= response_head.len() { break }
					Ok(())
				},
			};

			while stream.has_pending_writes() { yield Ok(()) }
		}

		let mut read_amt = 0;
		loop {
			let result = stream.write(&body_buffer[read_amt..]);
			yield match result {
				Err(ref e) if e.kind() == WouldBlock => Ok(()),
				Err(ref e) if e.kind() == Interrupted => Ok(()),
				Err(e) => Err(e),
				Ok(sz) => {
					read_amt += sz;
					if read_amt >= body_buffer.len() { break }
					Ok(())
				},
			};

			while stream.has_pending_writes() { yield Ok(()) }
		}
	})
}