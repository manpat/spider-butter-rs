#![feature(generators, generator_trait)]
#![feature(specialization)]
#![feature(box_syntax)]
#![feature(libc)]

extern crate inotify;
extern crate flate2;
extern crate libc;

use std::net::TcpListener;

use inotify::{event_mask, watch_mask, Inotify};
use std::thread;
use std::sync::mpsc;

mod fileserver;
mod coro_util;
mod tcp_util;
mod http;

mod mappings;
use mappings::*;

fn main() {
	let mut inotify = Inotify::init().expect("Inotify init failed");
	let current_dir = std::env::current_dir().expect("Failed to determine current directory");

	inotify.add_watch(current_dir, watch_mask::MODIFY)
		.expect("Failed to add inotify watch");

	let fs_listener = TcpListener::bind("0.0.0.0:8000").unwrap();
	let (mapping_tx, mapping_rx) = mpsc::channel();

	match Mappings::from_file(MAPPINGS_FILENAME) {
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

			match Mappings::from_file(MAPPINGS_FILENAME) {
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
