use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::io::{self, Read, Write};
use std::fs;

use std::sync::Arc;

use flate2::Compression;
use flate2::write::{GzEncoder, DeflateEncoder};

pub const MAPPINGS_FILENAME: &'static str = "mappings.sb";

#[derive(Clone, Copy)]
pub enum Encoding {
	Uncompressed,
	Gzip,
	Deflate,
}

pub trait MappedAsset {
	fn get_encoding(&self, _: Encoding) -> io::Result<Vec<u8>>;
}

struct PreprocessedAsset {
	uncompressed_data: Vec<u8>,
	deflated_data: Vec<u8>,
	gzipped_data: Vec<u8>,
}

struct UnprocessedAsset {
	file_path: PathBuf,
}

pub struct Mappings {
	mappings: HashMap<String, PathBuf>,
	imported_mappings: Vec<PathBuf>,
	file_cache: HashMap<PathBuf, Arc<PreprocessedAsset>>,
	caching_enabled: bool,
}

impl Mappings {
	pub fn new(caching_enabled: bool) -> Self {
		Mappings {
			mappings: HashMap::new(),
			imported_mappings: Vec::new(),
			file_cache: HashMap::new(),
			caching_enabled,
		}
	}

	pub fn from_file(path: &str, caching_enabled: bool) -> io::Result<Mappings> {
		let mut file = fs::File::open(path)?;
		let mut contents = String::new();
		file.read_to_string(&mut contents)?;

		let mut mps = Mappings::new(caching_enabled);
		mps.load_from(&contents, Path::new(""))?;
		if caching_enabled {
			mps.process_mapped_assets()?;
		}

		Ok(mps)
	}

	fn load_from(&mut self, data: &str, prefix: &Path) -> io::Result<()> {
		let iter = data.lines()
			.map(|s| s.trim())
			.filter(|s| !s.is_empty() && !s.starts_with('#'));

		let mut imports = Vec::new();

		for mapping in iter {
			let partition = mapping.find("=>");
			if partition.is_none() {
				if mapping.starts_with("import") {
					imports.push(Path::new(mapping[6..].trim()));
				}

				continue
			}

			let (key, value) = mapping.split_at(partition.unwrap());
			let (key, value) = (key.trim_end(), value[2..].trim_start());

			let path = [prefix, Path::new(value)].iter().collect();

			println!("Adding mapping {} => {:?}", key, path);
			self.mappings.insert(key.to_owned(), path);
		}

		self.imported_mappings.extend(imports.iter().map(From::from));

		// TODO: Add inotify watches to imported mappings
		for import in imports {
			let path: PathBuf = [prefix, import, Path::new(MAPPINGS_FILENAME)].iter().collect();
			let prefix = path.parent().unwrap_or(Path::new(""));

			println!("Importing {:?}", prefix);

			let mut file = fs::File::open(&path)?;
			let mut contents = String::new();
			file.read_to_string(&mut contents)?;

			self.load_from(&contents, &prefix)?;
		}

		Ok(())
	}

	// TODO: Add inotify watches to assets
	fn process_mapped_assets(&mut self) -> io::Result<()> {
		use std::collections::hash_map::Entry;
		use std::time::Instant;

		println!("Compressing mapped assets...");
		let timer = Instant::now();

		for path in self.mappings.values() {
			let entry = self.file_cache.entry(path.clone());

			if let Entry::Occupied(_) = entry { continue; }

			println!("Compressing {:?}...", path);

			let mut uncompressed_data = Vec::new();

			match fs::File::open(path) {
				Ok(mut file) => {
					file.read_to_end(&mut uncompressed_data)?;
				}

				Err(_) => {
					println!("Failed to load file {:?}, skipping...", path);
					continue
				}
			}

			let compression = Compression::best();

			let mut enc = GzEncoder::new(Vec::new(), compression);
			enc.write_all(&uncompressed_data)?;
			let gzipped_data = enc.finish()?;

			let mut enc = DeflateEncoder::new(Vec::new(), compression);
			enc.write_all(&uncompressed_data)?;
			let deflated_data = enc.finish()?;

			println!("        {:.1}kB", uncompressed_data.len() as f32 / 2.0f32.powi(10));
			println!("gzip -> {:.1}kB", gzipped_data.len() as f32 / 2.0f32.powi(10));
			println!("defl -> {:.1}kB", gzipped_data.len() as f32 / 2.0f32.powi(10));

			entry.or_insert(Arc::new(PreprocessedAsset{
				uncompressed_data,
				deflated_data,
				gzipped_data
			}));
		}

		println!("Compression finished in {}s {:.2}ms",
			timer.elapsed().as_secs(),
			timer.elapsed().subsec_nanos() as f64/1000_000.0);

		Ok(())
	}

	pub fn get_route(&self, key: &str) -> Option<&PathBuf> {
		self.mappings.get(key)
	}

	pub fn get_asset(&self, key: &str) -> Option<Arc<MappedAsset>> {
		let route = self.get_route(key);

		if self.caching_enabled {
			route.iter()
				.filter_map(|&k| self.file_cache.get(k))
				.cloned()
				.next()
				.map(|a| a as Arc<MappedAsset>)
		} else {
			route.cloned()
				.map(|file_path| Arc::new(UnprocessedAsset {file_path}) as Arc<MappedAsset>)
		}
	}
}

impl MappedAsset for PreprocessedAsset {
	fn get_encoding(&self, encoding: Encoding) -> io::Result<Vec<u8>> {
		match encoding {
			Encoding::Uncompressed => Ok(self.uncompressed_data.clone()),
			Encoding::Deflate => Ok(self.deflated_data.clone()),
			Encoding::Gzip => Ok(self.gzipped_data.clone()),
		}
	}
}

impl MappedAsset for UnprocessedAsset {
	fn get_encoding(&self, encoding: Encoding) -> io::Result<Vec<u8>> {
		let mut uncompressed_data = Vec::new();

		println!("Processing {:?}", &self.file_path.as_path());

		fs::File::open(&self.file_path)?
			.read_to_end(&mut uncompressed_data)?;

		match encoding {
			Encoding::Uncompressed => Ok(uncompressed_data),

			Encoding::Deflate => {
				let mut enc = DeflateEncoder::new(Vec::new(), Compression::fast());
				enc.write_all(&uncompressed_data)?;
				Ok(enc.finish()?)
			}

			Encoding::Gzip => {
				let mut enc = GzEncoder::new(Vec::new(), Compression::fast());
				enc.write_all(&uncompressed_data)?;
				Ok(enc.finish()?)
			}
		}
	}
}
