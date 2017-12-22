use std::net::{TcpStream, TcpListener};
use std::sync::mpsc::{self, Receiver};
use std::io::{Write, Read};
use std::thread;
use std::time;
use std::str;
use std::io;

use std::sync::Arc;

use coro_util::*;
use tcp_util::*;
use mappings::*;
use http;

const MAX_CONCURRENT_CONNECTIONS_PER_THREAD: usize = 128;
const MAX_PENDING_CONNECTIONS_PER_THREAD: usize = 128;
const NUM_WORKER_THREADS: usize = 4;

pub fn start(listener: TcpListener, mapping_channel: Receiver<Mappings>) {
	let mut mappings = Arc::new(Mappings::new());

	let mut tx_list = Vec::new();

	let coro_threads = {
		let mut ths = Vec::new();
		for _ in 0..NUM_WORKER_THREADS {
			let (tx, rx) = mpsc::sync_channel(MAX_PENDING_CONNECTIONS_PER_THREAD);
			ths.push(thread::spawn(move || continuation_thread(rx)));
			tx_list.push(tx);
		}
		ths
	};

	let mut tx_iter = tx_list.iter().cycle();

	for stream in listener.incoming() {
		if let Ok(new_mappings) = mapping_channel.try_recv() {
			mappings = Arc::new(new_mappings);
		}

		if !stream.is_ok() {
			continue
		}

		let coro = start_stream_process(stream.unwrap(), mappings.clone());
		tx_iter.next().unwrap()
			.send(coro).unwrap();
	}

	for th in coro_threads {
		th.join().unwrap();
	}
}

fn continuation_thread(rx: Receiver<Coro<()>>) {
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
			if coros.len() < MAX_CONCURRENT_CONNECTIONS_PER_THREAD {
				for c in rx.try_iter() {
					coros.push(c);
				}
			}

			for c in coros.iter_mut() {
				c.next();
			}

			coros.retain(Coro::is_valid);
			if coros.is_empty() { break }

			thread::sleep(time::Duration::from_millis(3));
		}
	}
}

fn start_stream_process(mut stream: TcpStream, mappings: Arc<Mappings>) -> Coro<()> {
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
				_ => 10,
			});

			if let Some(asset) = mappings.get_asset(request.uri()) {
				let encoding = encodings.first().cloned()
					.unwrap_or(Encoding::Uncompressed);

				send_data_async(stream, asset, encoding)
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

fn send_data_async(mut stream: TcpStream, data: Arc<CachedFile>, encoding: Encoding) -> Coro<io::Result<()>> {
	use std::io::ErrorKind::{WouldBlock, Interrupted};

	let body = data.get_encoding(encoding).iter().cloned().collect::<Vec<_>>();

	Coro::from(move || {
		let mut res = http::Response::new("HTTP/1.1 200 OK");

		match encoding {
			Encoding::Uncompressed => {},
			Encoding::Gzip => res.set("Content-Encoding", "gzip"),
			Encoding::Deflate => res.set("Content-Encoding", "deflate"),
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
			let result = stream.write(&body[read_amt..]);
			yield match result {
				Err(ref e) if e.kind() == WouldBlock => Ok(()),
				Err(ref e) if e.kind() == Interrupted => Ok(()),
				Err(e) => Err(e),
				Ok(sz) => {
					read_amt += sz;
					if read_amt >= body.len() { break }
					Ok(())
				},
			};

			while stream.has_pending_writes() { yield Ok(()) }
		}
	})
}