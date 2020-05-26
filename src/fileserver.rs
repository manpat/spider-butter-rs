use std::time::Duration;
use std::str;
use std::sync::Arc;

use async_std::prelude::*;
use async_std::io::{Write, Read};
use async_std::net::TcpListener;
use async_std::sync::Receiver;
use async_std::future::timeout;
use async_std::task;

use rustls::{NoClientAuth, ServerConfig};
use async_tls::TlsAcceptor;

use crate::SBResult;

use crate::cert::Certificate;
use crate::mappings::*;
use crate::http;

const TLS_UPGRADE_TIMEOUT: Duration = Duration::from_secs(5);
const REQUEST_READ_TIMEOUT: Duration = Duration::from_secs(5);

pub enum FileserverCommand {
	NewMappings(Mappings),
	SetCert(Certificate),
	Zombify,
	// Close,
}

pub async fn start(listener: TcpListener, command_rx: Receiver<FileserverCommand>) {
	let mut mappings = Arc::new(Mappings::new(false));

	let mut ssl_acceptor = None;
	let mut zombie_mode = false;

	println!("[fsrv] start");

	while let Some(stream) = listener.incoming().next().await {
		println!("[fsrv] Stream accept");

		while let Ok(command) = command_rx.try_recv() {
			match command {
				FileserverCommand::NewMappings(new_mappings) => {
					mappings = Arc::new(new_mappings);
				}

				FileserverCommand::SetCert(cert) => {
					use rustls::internal::pemfile::{certs, pkcs8_private_keys};

					let private_key = pkcs8_private_keys(&mut cert.private_key())
						.expect("Failed to read private_key")
						.remove(0);

					let mut cert_chain = certs(&mut cert.certificate())
						.expect("Failed to read cert");

					let intermediate = certs(&mut cert.intermediate())
						.expect("Failed to read intermediate cert");

					cert_chain.extend_from_slice(&intermediate);

					let mut config = ServerConfig::new(NoClientAuth::new());
					config.set_single_cert(cert_chain, private_key)
						.expect("Failed to set cert");
				    ssl_acceptor = Some(TlsAcceptor::from(Arc::new(config)));
				}

				FileserverCommand::Zombify => {
					zombie_mode = true;
				}
			}
		}

		if stream.is_err() {
			println!("[fsrv] stream err");
			continue
		}

		let stream = stream.unwrap();
		let mappings_clone = mappings.clone();

		if let Some(acceptor) = ssl_acceptor.as_ref() {
			// Start TLS upgrade
			let accept_result = timeout(TLS_UPGRADE_TIMEOUT, acceptor.accept(stream)).await;

			if let Ok(Ok(stream)) = accept_result {
				let stream_task = start_stream_process(stream, mappings_clone, zombie_mode);
				task::spawn(stream_task);
			} else {
				println!("[fsrv] Accept failed");
			}

		} else {
			let stream_task = start_stream_process(stream, mappings_clone, zombie_mode);
			task::spawn(stream_task);
		}
	}
}


async fn start_stream_process<S>(mut stream: S, mappings: Arc<Mappings>, zombie_mode: bool) -> SBResult<()>
	where S: Read + Write + Send + Unpin + 'static
{
	println!("[stream {:?}] new stream", task::current().id());

	// Try to read request
	let mut buf = [0u8; 8<<10];

	let size = timeout(REQUEST_READ_TIMEOUT, stream.read(&mut buf)).await??;
	let request = str::from_utf8(&buf[0..size])
		.map_err(Into::into)
		.and_then(http::Request::parse);

	let request = match request {
		Ok(r) => r,
		Err(e) => {
			let _ = stream.write_all(&http::Response::new("HTTP/1.1 400 Bad Request").into_bytes()).await;
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
		let _ = stream.write_all(&res.into_bytes()).await;
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

		send_data_async(stream, asset, encoding, content_type).await?;
	} else {
		let response = http::Response::new("HTTP/1.1 404 File not found").into_bytes();
		stream.write_all(&response).await?;
	}

	println!("[stream {:?}] stream close", task::current().id());

	Ok(())
}


async fn send_data_async<S>(mut stream: S, data: Arc<dyn MappedAsset>, encoding: Encoding, content_type: Option<String>)
	-> SBResult<()>
	where S: Write + Unpin + 'static
{
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

	stream.write_all(&response_head).await?;
	stream.write_all(&body).await?;

	Ok(())
}