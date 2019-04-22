#![feature(generators, generator_trait)]
#![feature(specialization)]

use structopt::StructOpt;
use inotify::{event_mask, watch_mask, Inotify};

use std::net::TcpListener;
use std::sync::mpsc;
use std::thread;

mod fileserver;
mod coro_util;
mod tcp_util;
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

	// /// Serve everything in the current working directory
	// #[structopt(short, long)]
	// local: bool,

	/// Port to use for unencrypted connections
	#[structopt(short, long, default_value="8000")]
	port: u16,

	/// Encrypt connections and attempt to request a certificate
	#[structopt(short, long)]
	secure: bool,

	/// Port to use for encrypted connections
	#[structopt(short, long, default_value="8001")]
	tls_port: u16,

	/// Use letsencrypt staging API so you don't get ratelimited
	#[structopt(long)]
	staging: bool,

	/// Domains to try and request certificates for
	#[structopt(short, long)]
	domains: Vec<String>,
}

fn main() -> SBResult<()> {
	let opts = Opts::from_args();

	let mut inotify = Inotify::init().expect("Inotify init failed");
	let current_dir = std::env::current_dir().expect("Failed to determine current directory");

	inotify.add_watch(current_dir, watch_mask::MODIFY)
		.expect("Failed to add inotify watch");

	let fs_listener = TcpListener::bind(("0.0.0.0", opts.port)).unwrap();
	let (mut fs_command_tx, fs_command_rx) = mpsc::channel();

	println!("Running...");
	if opts.nocache {
		println!("Caching disabled!");
	}

	thread::spawn(move || fileserver::start(fs_listener, fs_command_rx));

	if opts.secure {
		let sfs_listener = TcpListener::bind(("0.0.0.0", opts.tls_port)).unwrap();
		let (sfs_command_tx, sfs_command_rx) = mpsc::channel();

		thread::spawn(move || fileserver::start(sfs_listener, sfs_command_rx));
		start_autorenew_thread(opts.domains, fs_command_tx.clone(), sfs_command_tx.clone(), opts.staging);

		fs_command_tx.send(FileserverCommand::Zombify).unwrap();
		fs_command_tx = sfs_command_tx;
	}

	match Mappings::from_file(MAPPINGS_FILENAME, !opts.nocache) {
		Ok(mappings) => {
			fs_command_tx.send(FileserverCommand::NewMappings(mappings)).unwrap();
			println!("Done.");
		}

		Err(err) => {
			println!("Error: {:?}", err);
		}
	}

	let mut buffer = [0u8; 4096];
	loop {
		let mapping_file_changed = inotify
			.read_events_blocking(&mut buffer)
			.expect("Failed to read inotify events")
			.filter(|e| !e.mask.contains(event_mask::ISDIR))
			.map(|e| e.name.to_str().unwrap_or(""))
			.any(|name| name.ends_with(MAPPINGS_FILENAME));

		if mapping_file_changed {
			println!("Updating mappings...");

			match Mappings::from_file(MAPPINGS_FILENAME, !opts.nocache) {
				Ok(mappings) => {
					fs_command_tx.send(FileserverCommand::NewMappings(mappings)).unwrap();
					println!("Done.");
				}

				Err(err) => {
					println!("Error: {:?}", err);
				}
			}
		}
	}
}


fn start_autorenew_thread(domains: Vec<String>, insecure_server: mpsc::Sender<FileserverCommand>, secure_server: mpsc::Sender<FileserverCommand>, staging: bool) {
	use std::time::Duration;

	println!("Starting certificate autorenewal thread...");

	thread::spawn(move || -> SBResult<()> {
		loop {
			let cert = cert::acquire_certificate(&domains, &insecure_server, staging)?;
			let days_to_sleep = cert.days_till_expiry()?;

			assert!(days_to_sleep > 0);

			secure_server.send(FileserverCommand::SetCert(cert))?;

			// I don't know if sleeping for long periods of time is okay, but idk how else to do this
			thread::sleep(Duration::from_secs(days_to_sleep as u64 * 24 * 60 * 60));

			println!("Renewing certificate...");
		}
	});
}