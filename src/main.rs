#![feature(generators, generator_trait)]
#![feature(specialization)]

use structopt::StructOpt;
use inotify::{event_mask, watch_mask, Inotify};

use acme_client::SignedCertificate;

use std::net::TcpListener;
use std::sync::mpsc;
use std::thread;

mod fileserver;
mod coro_util;
mod tcp_util;
mod http;

mod mappings;
use crate::mappings::*;
use crate::fileserver::FileserverCommand;

pub type SBResult<T> = Result<T, failure::Error>;

pub const CERT_FILENAME: &'static str = "certificate.pem";
pub const CHAIN_CERT_FILENAME: &'static str = "certificate_chain.pem";


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
		let cert = try_get_certificates(&opts, &fs_command_tx)?;
		cert.save_signed_certificate(CERT_FILENAME)
			.map_err(acme_err_to_failure)?;

		cert.save_signed_certificate_and_chain(None, CHAIN_CERT_FILENAME)
			.map_err(acme_err_to_failure)?;

		let sfs_listener = TcpListener::bind(("0.0.0.0", opts.tls_port)).unwrap();
		let (sfs_command_tx, sfs_command_rx) = mpsc::channel();

		sfs_command_tx.send(FileserverCommand::SetCert(cert)).unwrap();

		thread::spawn(move || fileserver::start(sfs_listener, sfs_command_rx));

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


fn acme_err_to_failure(err: acme_client::error::Error) -> failure::Error {
	failure::format_err!("{:?}", err)
}


fn try_get_certificates(opts: &Opts, fs_command_tx: &mpsc::Sender<FileserverCommand>) -> SBResult<SignedCertificate> {
	use acme_client::Directory;

	let directory = if opts.staging {
		Directory::from_url("https://acme-staging.api.letsencrypt.org/directory").map_err(acme_err_to_failure)?
	} else {
		Directory::lets_encrypt().map_err(acme_err_to_failure)?
	};

	let account = directory
		.account_registration()
		.register()
		.map_err(acme_err_to_failure)?;

	let _ = account.revoke_certificate_from_file(CERT_FILENAME);

	assert!(opts.domains.len() > 0);

	let mut auths = Vec::new();
	let mut challenges = Vec::new();
	let mut mapping = Mappings::new(true);

	for domain in opts.domains.iter() {
		let auth = account.authorization(domain)
			.map_err(acme_err_to_failure)?;

		auths.push(auth);
	}

	for (auth, domain) in auths.iter().zip(opts.domains.iter()) {
		let http_challenge = auth.get_http_challenge()
			.ok_or_else(|| failure::format_err!("HTTP Challenge not found"))?;

		println!("http auth for '{}':", domain);
		println!(" - token:    {}", http_challenge.token());
		println!(" - key_auth: {}", http_challenge.key_authorization());

		let path = format!("/.well-known/acme-challenge/{}", http_challenge.token());

		mapping.insert_data_mapping(&path, http_challenge.key_authorization())?;
		challenges.push(http_challenge);
	}

	fs_command_tx.send(FileserverCommand::NewMappings(mapping))?;
	thread::sleep(std::time::Duration::from_millis(500));

	println!("Validating...");

	for challenge in challenges {
		challenge.validate()
			.map_err(acme_err_to_failure)?;
	}

	println!("Validation successful");

	let domain_refs = opts.domains.iter()
		.map(String::as_str)
		.collect::<Vec<_>>();

	account.certificate_signer(&domain_refs)
		.sign_certificate()
		.map_err(acme_err_to_failure)
}