use std::collections::HashMap;
use std::path::PathBuf;

pub struct Mappings {
	mappings: HashMap<String, PathBuf>,
}

impl Mappings {
	pub fn new() -> Self {
		Mappings {
			mappings: HashMap::new()
		}
	}

	pub fn load_from(&mut self, data: &str) {
		let mut mappings = HashMap::new();

		let iter = data.lines()
			.map(|s| s.trim())
			.filter(|s| !s.is_empty() && !s.starts_with('#'));

		for mapping in iter {
			let partition = mapping.find("=>");
			if partition.is_none() { continue }

			let (key, value) = mapping.split_at(partition.unwrap());
			let (key, value) = (key.trim_right(), value[2..].trim_left());

			let value = value.into();

			println!("Adding mapping {} => {:?}", key, value);
			mappings.insert(key.to_owned(), value);
		}

		self.mappings = mappings;
	}

	pub fn get_route(&mut self, key: &str) -> Option<&PathBuf> {
		self.mappings.get(key)
	}
}