#![feature(generators, generator_trait)]
#![feature(specialization)]
#![deny(rust_2018_idioms, future_incompatible)]

use structopt::StructOpt;
use inotify::{event_mask, watch_mask, Inotify};

use async_std::net::TcpListener;
use async_std::sync::{channel, Sender};
use async_std::task;

mod fileserver;
mod http;
mod cert;

mod mappings;
use crate::mappings::*;
use crate::fileserver::FileserverCommand;

pub type SBResult<T> = Result<T, failure::Error>;


#[derive(Debug, StructOpt)]
#[structopt( raw(setting="structopt::clap::AppSettings::ColoredHelp") )]
struct Opts {
	/// Load and compress resources as they're requested instead of ahead of time
	#[structopt(short, long)]
	nocache: bool,

	/// Serve everything in the current working directory
	#[structopt(short, long)]
	local: bool,

	/// Port to use for unencrypted connections
	#[structopt(short, long, default_value="8000")]
	port: u16,

	/// Encrypt connections and attempt to request a certificate
	#[structopt(short, long)]
	secure: bool,

	/// Port to use for encrypted connections
	#[structopt(short, long, default_value="8001")]
	tls_port: u16,

	/// Use letsencrypt staging API so you don't get rate limited
	#[structopt(long)]
	staging: bool,

	/// Domains to try and request certificates for
	#[structopt(short, long)]
	domains: Vec<String>,
}


fn main() -> SBResult<()> {
	async_std::task::block_on(start())
}


async fn start() -> SBResult<()> {
	let opts = Opts::from_args();

	let current_dir = std::env::current_dir().expect("Failed to determine current directory");

	let fs_listener = TcpListener::bind(("0.0.0.0", opts.port)).await?;
	let (mut fs_command_tx, fs_command_rx) = channel(3);

	println!("Running...");
	if opts.nocache {
		println!("Caching disabled!");
	}

	task::spawn(fileserver::start(fs_listener, fs_command_rx));

	if opts.secure {
		let sfs_listener = TcpListener::bind(("0.0.0.0", opts.tls_port)).await?;
		let (sfs_command_tx, sfs_command_rx) = channel(3);

		task::spawn(fileserver::start(sfs_listener, sfs_command_rx));
		task::spawn(
			start_autorenew_thread(opts.domains, fs_command_tx.clone(), sfs_command_tx.clone(), opts.staging)
		);

		fs_command_tx.send(FileserverCommand::Zombify).await;
		fs_command_tx = sfs_command_tx;
	}

	if opts.local {
		let mappings = Mappings::from_dir(".".into(), !opts.nocache)?;
		fs_command_tx.send(FileserverCommand::NewMappings(mappings)).await;
		println!("Done.");

		// TODO: Something better
		loop {
			task::yield_now().await;
		}
	}

	match Mappings::from_file(MAPPINGS_FILENAME, !opts.nocache) {
		Ok(mappings) => {
			fs_command_tx.send(FileserverCommand::NewMappings(mappings)).await;
			println!("Done.");
		}

		Err(err) => {
			println!("Error: {:?}", err);
		}
	}

	let mut inotify = Inotify::init().expect("Inotify init failed");
	inotify.add_watch(current_dir, watch_mask::MODIFY)
		.expect("Failed to add inotify watch");

	// let mut buffer = [0u8; 4096];
	// loop {
	// 	println!("Waiting for events...");
	// 	let mapping_file_changed = inotify
	// 		.read_events_blocking(&mut buffer)
	// 		.expect("Failed to read inotify events")
	// 		.filter(|e| !e.mask.contains(event_mask::ISDIR))
	// 		.map(|e| e.name.to_str().unwrap_or(""))
	// 		.any(|name| name.ends_with(MAPPINGS_FILENAME));

	// 	if mapping_file_changed {
	// 		println!("Updating mappings...");

	// 		match Mappings::from_file(MAPPINGS_FILENAME, !opts.nocache) {
	// 			Ok(mappings) => {
	// 				fs_command_tx.send(FileserverCommand::NewMappings(mappings)).await;
	// 				println!("Done.");
	// 			}

	// 			Err(err) => {
	// 				println!("Error: {:?}", err);
	// 			}
	// 		}
	// 	}
	// }

	// TODO: something better
	loop {
		task::yield_now().await;
	}
}



async fn start_autorenew_thread(domains: Vec<String>, insecure_server: Sender<FileserverCommand>, secure_server: Sender<FileserverCommand>, staging: bool) {
	use std::time::Duration;

	println!("Starting certificate autorenewal task...");

	loop {
		let cert = cert::acquire_certificate(&domains, &insecure_server, staging)
			.await
			.expect("Failed to acquire certificate");

		let days_till_expiry = cert.days_till_expiry().unwrap();

		assert!(days_till_expiry > 0);
		println!("Valid certificate acquired");

		secure_server.send(FileserverCommand::SetCert(cert)).await;

		// I don't know if sleeping for long periods of time is okay, but idk how else to do this
		let hours_to_wait = days_till_expiry.saturating_sub(cert::RENEWAL_PERIOD_DAYS) as u64 * 24;
		for _ in 0..hours_to_wait {
			task::sleep(Duration::from_secs(60 * 60)).await;
		}

		println!("Renewing certificate...");
	}
}