use std::net::TcpListener;
use std::sync::mpsc::{self, Receiver};
use std::io::{Write, Read};
use std::ops::Generator;
use std::rc::Rc;
use std::thread;
use std::time;
use std::str;

use std::sync::Arc;
use acme_client::openssl::ssl::{SslAcceptor, SslMethod, HandshakeError};

use failure::bail;

use crate::SBResult;

use crate::cert::Certificate;
use crate::coro_util::*;
use crate::tcp_util::*;
use crate::mappings::*;
use crate::http;

const MAX_CONCURRENT_CONNECTIONS_PER_THREAD: usize = 128;
const MAX_PENDING_CONNECTIONS_PER_THREAD: usize = 128;
const NUM_WORKER_THREADS: usize = 4;

const SSL_UPGRADE_TIMEOUT_SECS: u64 = 5;
const REQUEST_READ_TIMEOUT_SECS: u64 = 5;

pub enum FileserverCommand {
	NewMappings(Mappings),
	SetCert(Certificate),
	Zombify,
	// Close,
}

pub fn start(listener: TcpListener, command_rx: Receiver<FileserverCommand>) {
	let mut mappings = Arc::new(Mappings::new(false));

	let (coro_threads, worker_tx_list) = {
		let mut txs = Vec::new();
		let mut ths = Vec::new();
		for _ in 0..NUM_WORKER_THREADS {
			let (tx, rx) = mpsc::sync_channel(MAX_PENDING_CONNECTIONS_PER_THREAD);
			ths.push(thread::spawn(move || continuation_thread(rx)));
			txs.push(tx);
		}
		(ths, txs)
	};

	let mut worker_tx_iter = worker_tx_list.into_iter().cycle();
	let mut submit_task = move |task| {
		worker_tx_iter.next().unwrap().send(task).unwrap()
	};

	let mut ssl_acceptor = None;
	let mut zombie_mode = false;

	for stream in listener.incoming() {
		for command in command_rx.try_iter() {
			match command {
				FileserverCommand::NewMappings(new_mappings) => {
					mappings = Arc::new(new_mappings);
				}

				FileserverCommand::SetCert(cert) => {
					let mut builder = SslAcceptor::mozilla_intermediate(SslMethod::tls()).unwrap();
					builder.set_certificate(cert.certificate()).unwrap();
					builder.add_extra_chain_cert(cert.intermediate().clone()).unwrap();
					builder.set_private_key(cert.private_key()).unwrap();
					builder.check_private_key().unwrap();
					ssl_acceptor = Some(Rc::new(builder.build()));
				}

				FileserverCommand::Zombify => {
					zombie_mode = true;
				}
			}
		}

		if stream.is_err() {
			continue
		}

		let stream = stream.unwrap();

		if stream.set_nonblocking(true).is_err() {
			continue
		}

		let mappings_clone = mappings.clone();

		if let Some(acceptor) = ssl_acceptor.as_ref().map(Rc::clone) {
			let stream_task = static move || {
				// Start TLS upgrade
				let mut accept_result = acceptor.accept(stream);
				let handshake_timer = std::time::Instant::now();

				// Keep resuming handshake until either an error, timeout or success
				while let Err(HandshakeError::WouldBlock(inprogress_stream)) = accept_result {
					if handshake_timer.elapsed().as_secs() >= SSL_UPGRADE_TIMEOUT_SECS {
						bail!("Timeout while trying to upgrade connection")
					}

					yield;
					accept_result = inprogress_stream.handshake();
				}

				// Start regular stream process
				let tls_stream = accept_result?;
				task_await!(start_stream_process(tls_stream, mappings_clone, zombie_mode))
			};

			submit_task(stream_task.into());

		} else {
			let stream_task = start_stream_process(stream, mappings_clone, zombie_mode);
			submit_task(stream_task.into());
		}
	}

	for th in coro_threads {
		th.join().unwrap();
	}
}

fn continuation_thread(rx: Receiver<Task<SBResult<()>>>) {
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

		// println!("[cont {:?}] connection made, transitioning to processing loop", thread::current().id());

		// Process all connections until completion
		loop {
			if coros.len() < MAX_CONCURRENT_CONNECTIONS_PER_THREAD {
				for c in rx.try_iter() {
					coros.push(c);
				}
			}

			for c in coros.iter_mut() {
				if let Some(Err(e)) = c.resume() {
					println!("[fsrv] Connection aborted with error: {}", e);
				}
			}

			coros.retain(Task::is_valid);
			if coros.is_empty() { break }

			thread::sleep(time::Duration::from_millis(1));
		}

		// println!("[cont {:?}] connections processed, waiting...", thread::current().id());
	}
}


fn start_stream_process<S>(mut stream: S, mappings: Arc<Mappings>, zombie_mode: bool)
	-> impl Generator<Yield=(), Return=SBResult<()>>
	where S: Read + Write + TcpStreamExt + 'static {

	static move || {
		// println!("[stream {:?}] new stream", thread::current().id());

		let mut buf = [0u8; 8<<10];
		let read_start = std::time::Instant::now();

		// Try to read request
		let size = loop {
			use std::io::ErrorKind as EK;

			match stream.read(&mut buf) {
				Err(e) => match e.kind() {
					EK::WouldBlock => {},
					_ => bail!("Error while reading request: {:?}", e)
				}

				Ok(0) => bail!("Zero size request"),
				Ok(s) => break s,
			}

			if read_start.elapsed().as_secs() > REQUEST_READ_TIMEOUT_SECS {
				bail!("Timeout during request read");
			}

			yield
		};

		let request = str::from_utf8(&buf[0..size])
			.map_err(Into::into)
			.and_then(http::Request::parse);

		let request = match request {
			Ok(r) => r,
			Err(e) => {
				let _ = stream.write_all(&http::Response::new("HTTP/1.1 400 Bad Request").into_bytes());
				return Err(e);
			}
		};

		// If we're on a zombie thread, and the request isn't part of an acme challenge,
		// tell the client to upgrade to https
		if zombie_mode && !request.uri().contains("/.well-known/acme-challenge") {
			// TODO: this needs to be made way more robust - way too much trust here
			let mut res = http::Response::new("HTTP/1.1 301 Moved Permanently");
			let new_location = format!("https://{}{}", request.get("Host").unwrap_or(""), request.uri());
			res.set("Location", &new_location);
			let _ = stream.write_all(&res.into_bytes());
			return Ok(());
		}

		// Figure out what compression method to use
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

		// Try to send the asset with the correct encoding and content type
		// or bail with a 404 if it's not found in the mappings
		let asset_and_content_type = mappings
			.get_route(request.uri())
			.and_then(|r| Some((mappings.get_asset(&r.path)?, &r.content_type)));

		if let Some((asset, content_type)) = asset_and_content_type {
			let encoding = encodings.first().cloned()
				.unwrap_or(Encoding::Uncompressed);

			let content_type = content_type.as_ref().map(String::clone);

			task_await!(send_data_async(stream, asset, encoding, content_type))
		} else {
			let response = http::Response::new("HTTP/1.1 404 File not found").into_bytes();
			task_await!(write_async(&mut stream, &response))
		}

		// println!("[stream {:?}] stream close", thread::current().id());
	}
}

fn send_data_async<S>(mut stream: S, data: Arc<dyn MappedAsset>, encoding: Encoding, content_type: Option<String>)
	-> impl Generator<Yield=(), Return=SBResult<()>>
	where S: Read + Write + TcpStreamExt + 'static {

	static move || {
		let body = data.get_encoding(encoding)?;
		let mut res = http::Response::new("HTTP/1.1 200 OK");

		match encoding {
			Encoding::Uncompressed => {},
			Encoding::Gzip => res.set("Content-Encoding", "gzip"),
			Encoding::Deflate => res.set("Content-Encoding", "deflate"),
		}

		if let Some(content_type) = content_type.as_ref() {
			res.set("Content-Type", content_type);
		}

		let response_head = res.into_bytes();

		task_await!(write_async(&mut stream, &response_head))?;
		task_await!(write_async(&mut stream, &body))?;

		Ok(())
	}
}