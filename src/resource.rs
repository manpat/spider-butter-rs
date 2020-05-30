use crate::SBResult;
use std::path::PathBuf;
use std::io::Write;

use flate2::Compression;
use flate2::write::{GzEncoder, DeflateEncoder};

use async_std::prelude::*;
use async_std::task;
use async_std::fs;

#[derive(Clone, Copy)]
pub enum Encoding {
	Uncompressed,
	Gzip,
	Deflate,
}


pub struct CachedResource {
	uncompressed_data: Vec<u8>,
	deflated_data: Vec<u8>,
	gzipped_data: Vec<u8>,
}


pub enum Resource {
	Cached(CachedResource),
	Reference(PathBuf),
}


impl CachedResource {
	pub fn empty() -> Self {
		Self {
			uncompressed_data: Vec::new(),
			deflated_data: Vec::new(),
			gzipped_data: Vec::new(),
		}
	}

	pub async fn process(uncompressed_data: Vec<u8>) -> SBResult<CachedResource> {
		let deflated_data = compress(uncompressed_data.clone(), Encoding::Deflate, false);
		let gzipped_data = compress(uncompressed_data.clone(), Encoding::Gzip, false);

		let (deflated_data, gzipped_data) = deflated_data.try_join(gzipped_data).await?;

		Ok(CachedResource {
			uncompressed_data,
			deflated_data,
			gzipped_data
		})
	}
}


impl Resource {
	pub async fn get_compressed(&self, enc: Encoding) -> SBResult<Vec<u8>> {
		match self {
			Resource::Cached(resource) => match enc {
				Encoding::Uncompressed => Ok(resource.uncompressed_data.clone()),
				Encoding::Deflate => Ok(resource.deflated_data.clone()),
				Encoding::Gzip => Ok(resource.gzipped_data.clone()),
			},

			Resource::Reference(path) => {
				println!("Processing {:?}", &path.as_path());
				let uncompressed_data = fs::read(&path).await?;

				match enc {
					Encoding::Uncompressed => Ok(uncompressed_data),
					enc => compress(uncompressed_data, enc, true).await,
				}
			}
		}
	}
}


async fn compress(data: Vec<u8>, encoding: Encoding, fast_compression: bool) -> SBResult<Vec<u8>> {
	let compression = if fast_compression { Compression::fast() } else { Compression::best() };

	match encoding {
		Encoding::Uncompressed => Ok(data),

		Encoding::Deflate => task::spawn_blocking(move || {
			let mut enc = DeflateEncoder::new(Vec::new(), compression);
			enc.write_all(&data)?;
			Ok(enc.finish()?)
		}).await,

		Encoding::Gzip => task::spawn_blocking(move || {
			let mut enc = GzEncoder::new(Vec::new(), compression);
			enc.write_all(&data)?;
			Ok(enc.finish()?)
		}).await
	}
}