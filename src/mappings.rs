use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::{io, fs};
use std::io::Read;

pub const MAPPINGS_FILENAME: &'static str = "mappings.sb";

pub struct Mappings {
	mappings: HashMap<String, PathBuf>,
}

impl Mappings {
	pub fn new() -> Self {
		Mappings {
			mappings: HashMap::new()
		}
	}

	pub fn from_file(path: &str) -> io::Result<Mappings> {
		let mut file = fs::File::open(path)?;
		let mut contents = String::new();
		file.read_to_string(&mut contents)?;

		let mut mps = Mappings::new();
		mps.load_from(&contents, Path::new(""))?;

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
			let (key, value) = (key.trim_right(), value[2..].trim_left());

			let mut path = [prefix, Path::new(value)].iter().collect();

			println!("Adding mapping {} => {:?}", key, path);
			self.mappings.insert(key.to_owned(), path);
		}

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

	pub fn get_route(&mut self, key: &str) -> Option<&PathBuf> {
		self.mappings.get(key)
	}
}