use std::sync::mpsc;
use std::thread;
use std::path::Path;
use std::fs;
use std::time::Duration;

use acme_client::SignedCertificate;
use acme_client::openssl;
use self::openssl::pkey::{PKey, Private};
use self::openssl::x509::X509;

use crate::SBResult;
use crate::mappings::Mappings;
use crate::fileserver::FileserverCommand;

pub type PrivateKey = PKey<Private>;

const CERT_FILENAME: &'static str = ".spiderbutter/certificate_chain.pem";
const STAGING_CERT_FILENAME: &'static str = ".spiderbutter/staging_certificate_chain.pem";

const INTERMEDIATE_CERT_FILENAME: &'static str = ".spiderbutter/intermediate_cert.pem";
const STAGING_INTERMEDIATE_CERT_FILENAME: &'static str = ".spiderbutter/staging_intermediate_cert.pem";

const PRIV_CERT_FILENAME: &'static str = ".spiderbutter/private_key.pem";
const STAGING_PRIV_CERT_FILENAME: &'static str = ".spiderbutter/staging_private_key.pem";

pub const RENEWAL_PERIOD_DAYS: i32 = 7;

pub fn certificate_filename(staging: bool) -> &'static str {
	if staging {
		STAGING_CERT_FILENAME.into()
	} else {
		CERT_FILENAME.into()
	}
}

pub fn intermediate_cert_filename(staging: bool) -> &'static str {
	if staging {
		STAGING_INTERMEDIATE_CERT_FILENAME.into()
	} else {
		INTERMEDIATE_CERT_FILENAME.into()
	}
}

pub fn private_key_filename(staging: bool) -> &'static str {
	if staging {
		STAGING_PRIV_CERT_FILENAME.into()
	} else {
		PRIV_CERT_FILENAME.into()
	}
}

pub struct Certificate {
	public_cert: X509,
	intermediate_cert: X509,
	private_key: PrivateKey,
}

impl Certificate {
	pub fn from_signed(cert: SignedCertificate) -> SBResult<Certificate> {
		let SignedCertificate {cert, intermediate_cert, pkey, ..} = cert;

		Ok(Certificate {
			public_cert: cert,
			intermediate_cert,
			private_key: pkey,
		})
	}

	pub fn from_pem(cert_raw: &[u8], intermediate_raw: &[u8], priv_raw: &[u8]) -> SBResult<Certificate> {
		let public_cert = X509::from_pem(&cert_raw)?;
		let intermediate_cert = X509::from_pem(&intermediate_raw)?;
		let private_key = PrivateKey::private_key_from_pem(&priv_raw)?;

		Ok(Certificate {
			public_cert,
			intermediate_cert,
			private_key
		})
	}

	pub fn days_till_expiry(&self) -> SBResult<i32> {
		enum Asn1TimeOpaque {}
		extern "C" { fn ASN1_TIME_diff(pday: *mut libc::c_int, psec: *mut libc::c_int, from: *const Asn1TimeOpaque, to: *const Asn1TimeOpaque) -> libc::c_int; }

		let mut day_offset = 0;
		let mut second_offset = 0;

		let success = unsafe {
			ASN1_TIME_diff(
				&mut day_offset,
				&mut second_offset,
				std::ptr::null(),
				std::mem::transmute(self.public_cert.not_after())
				// a dirty hack but openssl doesn't give me what I need
				// this is safe so long as not_after() implements ForeignTypeRef
			)
		};

		if success != 1 {
			failure::bail!("Failed to determine time to expiry")
		}

		Ok(day_offset)
	}

	pub fn certificate(&self) -> &X509 { &self.public_cert }
	pub fn intermediate(&self) -> &X509 { &self.intermediate_cert }
	pub fn private_key(&self) -> &PrivateKey { &self.private_key }
}


pub fn acquire_certificate(domains: &[String], fs_command_tx: &mpsc::Sender<FileserverCommand>, staging: bool) -> SBResult<Certificate> {
	let cert_path = Path::new(certificate_filename(staging));
	let intermediate_cert_path = Path::new(intermediate_cert_filename(staging));
	let priv_key_path = Path::new(private_key_filename(staging));

	if let Ok(cert) = load_certificate_from(cert_path, intermediate_cert_path, priv_key_path) {
		return Ok(cert)
	}

	let domains = domains.iter()
		.map(String::as_ref)
		.collect::<Vec<_>>();

	let cert = request_new_certificate(&domains, fs_command_tx, staging)?;

	if let Some(dir) = cert_path.parent() { fs::create_dir_all(dir)?; }
	if let Some(dir) = intermediate_cert_path.parent() { fs::create_dir_all(dir)?; }
	if let Some(dir) = priv_key_path.parent() { fs::create_dir_all(dir)?; }

	std::fs::write(cert_path, cert.cert.to_pem()?)?;
	std::fs::write(intermediate_cert_path, cert.intermediate_cert.to_pem()?)?;
	std::fs::write(priv_key_path, cert.pkey.private_key_to_pem_pkcs8()?)?;

	Certificate::from_signed(cert)
}



fn load_certificate_from(cert_path: &Path, intermediate_path: &Path, priv_key_path: &Path) -> SBResult<Certificate> {
	let cert_raw = fs::read(cert_path)?;
	let intermediate_raw = fs::read(intermediate_path)?;
	let priv_key_raw = fs::read(priv_key_path)?;

	let cert = Certificate::from_pem(&cert_raw, &intermediate_raw, &priv_key_raw)?;

	let days_till_expiry = cert.days_till_expiry()?;

	if days_till_expiry <= RENEWAL_PERIOD_DAYS {
		println!("Certificate exists but has expired or is near expiry - ignoring");
		failure::bail!("Certificate expired")
	}

	println!("Using existing certificate, expiry in {} days", days_till_expiry);

	Ok(cert)
}


fn request_new_certificate(domains: &[&str], fs_command_tx: &mpsc::Sender<FileserverCommand>, staging: bool) -> SBResult<SignedCertificate> {
	use acme_client::{AcmeClient, AcmeStatus, AccountRegistration, Authorization};

	assert!(domains.len() > 0);

	println!("Requesting certificate for {:?}", domains);

	let client = if staging {
		AcmeClient::lets_encrypt_staging(AccountRegistration::new())?
	} else {
		AcmeClient::lets_encrypt(AccountRegistration::new())?
	};

	let (mut order, order_location) = client.submit_order(domains)?;

	let mut challenges = Vec::new();
	let mut mapping = Mappings::new(true);

	for auth_uri in order.authorizations.iter() {
		let auth = client.fetch_authorization(auth_uri)?;

		let Authorization {
			challenges: auth_challenges,
			identifier,
			..
		} = auth;

		let challenge = auth_challenges.into_iter()
			.filter(|c| c.challenge_type.starts_with("http"))
			.next()
			.ok_or_else(|| failure::format_err!("HTTP Challenge not found for '{}'", identifier.uri))?;

		let challenge_key_auth = client.calculate_key_authorization(&challenge)?;

		let path = format!("/.well-known/acme-challenge/{}", challenge.token);
		mapping.insert_data_mapping(&path, challenge_key_auth)?;
		challenges.push(challenge);
	}

	fs_command_tx.send(FileserverCommand::NewMappings(mapping))?;
	thread::sleep(Duration::from_millis(200));

	for challenge in challenges.iter() {
		client.signal_challenge_ready(challenge)?;
	}

	loop {
		std::thread::sleep(std::time::Duration::from_millis(200));

		order = client.fetch_order(&order_location)?;

		match order.status {
			// It shouldn't really be in this state but wait anyway
			AcmeStatus::Pending => continue,

			// Server is still validating
			AcmeStatus::Processing => continue,

			// Ready to finalize
			AcmeStatus::Ready => break,

			// Already been finalized?
			AcmeStatus::Valid => break,

			AcmeStatus::Invalid => {
				failure::bail!("Authorization failed!")
			}
		}
	}

	let (cert, _) = client.finalize_order(&order)?;
	println!("Validation successful");
	Ok(cert)
}
