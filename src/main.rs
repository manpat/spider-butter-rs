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

mod mappings;
use crate::mappings::*;

#[derive(Debug, StructOpt)]
#[structopt( raw(setting="structopt::clap::AppSettings::ColoredHelp") )]
struct Opts {
	/// Load and compress resources as they're requested instead of ahead of time
	#[structopt(short, long)]
	nocache: bool,

	// /// Serve everything in the current working directory
	// #[structopt(short, long)]
	// local: bool,

	#[structopt(short, long, default_value="8000")]
	port: u16,
}

fn main() {
	let opts = Opts::from_args();

	let mut inotify = Inotify::init().expect("Inotify init failed");
	let current_dir = std::env::current_dir().expect("Failed to determine current directory");

	inotify.add_watch(current_dir, watch_mask::MODIFY)
		.expect("Failed to add inotify watch");

	let fs_listener = TcpListener::bind(("0.0.0.0", opts.port)).unwrap();
	let (mapping_tx, mapping_rx) = mpsc::channel();

	println!("Running...");
	if opts.nocache {
		println!("Caching disabled!");
	}

	match Mappings::from_file(MAPPINGS_FILENAME, !opts.nocache) {
		Ok(mappings) => {
			mapping_tx.send(mappings).unwrap();
			println!("Done.");
		}

		Err(err) => {
			println!("Error: {:?}", err);
		}
	}

	thread::spawn(move || fileserver::start(fs_listener, mapping_rx));

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
					mapping_tx.send(mappings).unwrap();
					println!("Done.");
				}

				Err(err) => {
					println!("Error: {:?}", err);
				}
			}
		}
	}
}
