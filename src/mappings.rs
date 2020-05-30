use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use async_std::task;
use async_std::fs;

use crate::SBResult;
use crate::resource::{Resource, CachedResource};

pub const MAPPINGS_FILENAME: &'static str = "mappings.sb";


#[derive(Debug)]
pub struct Mapping {
	pub path: PathBuf,
	pub content_type: Option<String>,
}

pub struct Mappings {
	mappings: HashMap<String, Mapping>,
	imported_mappings: Vec<PathBuf>,
	file_cache: HashMap<PathBuf, Arc<Resource>>,
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

	pub async fn from_file(path: &str, caching_enabled: bool) -> SBResult<Mappings> {
		let contents = fs::read_to_string(path).await?;

		let mut mps = Mappings::new(caching_enabled);
		mps.load_from(&contents, Path::new(""))?;
		if caching_enabled {
			mps.process_mapped_assets().await?;
		}

		Ok(mps)
	}

	pub async fn from_dir(path: &str, caching_enabled: bool) -> SBResult<Mappings> {
		let mut mps = Mappings::new(caching_enabled);
		mps.walk_directory(Path::new(path))?;

		if caching_enabled {
			mps.process_mapped_assets().await?;
		}

		Ok(mps)
	}

	pub async fn insert_data_mapping<T>(&mut self, key: &str, data: T) -> SBResult<()>
		where T: Into<Vec<u8>> {

		let resource = Resource::Cached(CachedResource::process(data.into()).await?);
		let content_type = None;

		self.file_cache.insert(key.into(), Arc::new(resource));
		self.mappings.insert(key.into(), Mapping{ path: key.into(), content_type });

		Ok(())
	}

	fn walk_directory(&mut self, path: &Path) -> SBResult<()> {
		for entry in std::fs::read_dir(path)? {
			let path = entry?.path();

			if path.is_dir() {
				self.walk_directory(&path.as_path())?;

			} else {
				let mut path_str = path
					.strip_prefix("./")
					.unwrap_or(&path)
					.to_str()
					.ok_or_else(|| failure::format_err!("Failed to walk directory"))?
					.to_owned();

				if path_str.contains(".spiderbutter") { continue }

				path_str.insert(0, '/');

				self.mappings.insert(path_str, Mapping{ path: path.into(), content_type: None });
			}
		}

		Ok(())
	}

	fn load_from(&mut self, data: &str, prefix: &Path) -> SBResult<()> {
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

			// extract content type
			let (value, content_type) = if let Some(pos) = value.find('[') {
				let (value, type_start) = value.split_at(pos);
				let content_type = type_start[1..].split(']').next().unwrap();
				(value.trim(), Some(content_type.trim().into()))
			} else {
				(value, None)
			};

			// TODO: exclude cert directory
			let path = [prefix, Path::new(value)].iter().collect();

			if let Some(content_type) = &content_type {
				println!("Adding mapping {} => {:?} [{}]", key, path, content_type);
			} else {
				println!("Adding mapping {} => {:?}", key, path);
			}
			self.mappings.insert(key.to_owned(), Mapping{ path, content_type });
		}

		self.imported_mappings.extend(imports.iter().map(From::from));

		// TODO: Add inotify watches to imported mappings
		for import in imports {
			let path: PathBuf = [prefix, import, Path::new(MAPPINGS_FILENAME)].iter().collect();
			let prefix = path.parent().unwrap_or(Path::new(""));

			println!("Importing {:?}", prefix);

			let contents = std::fs::read_to_string(&path)?;
			self.load_from(&contents, &prefix)?;
		}

		Ok(())
	}

	// TODO: Add inotify watches to assets
	async fn process_mapped_assets(&mut self) -> SBResult<()> {
		use std::collections::hash_map::Entry;
		use std::time::Instant;

		println!("Compressing mapped assets...");
		let timer = Instant::now();

		let mut tasks = Vec::new();

		for Mapping{path, ..} in self.mappings.values() {
			let entry = self.file_cache.entry(path.clone());

			if let Entry::Occupied(_) = entry { continue; }

			// Insert empty resource so we don't try to compress more than once
			entry.insert(Arc::new(Resource::Cached(CachedResource::empty())));

			println!("Compressing {:?}...", path);

			async fn process_resource(path: PathBuf) -> SBResult<CachedResource> {
				let data = fs::read(path).await?;
				CachedResource::process(data).await
			}

			let task = task::spawn(process_resource(path.clone()));
			tasks.push((task, path.clone()));
		}

		for (task, path) in tasks {
			match task.await {
				Ok(resource) => {
					self.file_cache.insert(path, Arc::new(Resource::Cached(resource)));
				}

				Err(_) => {
					println!("Failed to load file {:?}, skipping...", path);
					continue
				}
			}
		}


		println!("Compression finished in {}s {:.2}ms",
			timer.elapsed().as_secs(),
			timer.elapsed().subsec_nanos() as f64/1000_000.0);

		Ok(())
	}

	pub fn get_route(&self, key: &str) -> Option<&Mapping> {
		self.mappings.get(key)
	}

	pub fn get_asset(&self, route: &Path) -> Option<Arc<Resource>> {
		if self.caching_enabled {
			self.file_cache.get(route).cloned()

		} else {
			Some(Arc::new(Resource::Reference(route.to_owned())))
		}
	}
}

