extern crate inotify;
extern crate flate2;

use std::net::TcpListener;

use inotify::{event_mask, watch_mask, Inotify};
use std::{thread, fs};
use std::sync::mpsc;
use std::io::Read;

mod fileserver;
mod http;

mod mappings;
use mappings::*;

const MAPPINGS_FILENAME: &'static str = "mappings.sb";

fn main() {
	let mut inotify = Inotify::init().expect("Inotify init failed");
	let current_dir = std::env::current_dir().expect("Failed to determine current directory");

	inotify.add_watch(current_dir, watch_mask::MODIFY)
		.expect("Failed to add inotify watch");

	let fs_listener = TcpListener::bind("0.0.0.0:8000").unwrap();
	let (mapping_tx, mapping_rx) = mpsc::channel();

	if let Ok(mappings) = load_mappings() {
		mapping_tx.send(mappings).unwrap();
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
			if let Ok(mappings) = load_mappings() {
				mapping_tx.send(mappings).unwrap();
			}
			println!("Done.");
		}
	}
}

fn load_mappings() -> std::io::Result<Mappings> {
	let mut file = fs::File::open(MAPPINGS_FILENAME)?;
	let mut contents = String::new();
	file.read_to_string(&mut contents)?;

	let mut mappings = Mappings::new();
	mappings.load_from(&contents);
	Ok(mappings)
}
