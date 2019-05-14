use std::collections::HashMap;
use crate::SBResult;

#[derive(Debug)]
pub struct Request<'a> {
	uri: &'a str,
	fields: HashMap<&'a str, &'a str>,
}

#[derive(Debug)]
pub struct Response<'a> {
	status_line: &'a str,
	fields: HashMap<&'a str, &'a str>,
}

impl<'a> Request<'a> {
	pub fn parse(data: &'a str) -> SBResult<Request<'a>> {
		let header_end = data.split("\r\n\r\n").next().unwrap();
		let mut lines = header_end.split_terminator("\r\n");
		let reqline = lines.next().unwrap_or("");

		let mut reqlineels = reqline.split_whitespace();

		if reqlineels.next().unwrap_or("") != "GET" {
			failure::bail!("Non-GET requests not supported");
		}

		let requri = reqlineels.next().unwrap_or("");
		let version = reqlineels.next().unwrap_or("");

		if version != "HTTP/1.0" && version != "HTTP/1.1" {
			failure::bail!("Invalid HTTP version");
		}

		let mut fields = HashMap::new();

		for line in lines {
			let mut line = line.splitn(2, ":").map(|s| s.trim());
			let key = line.next().unwrap();
			let value = match line.next() {
				Some(v) => v,
				None => continue
			};

			fields.insert(key, value);
		}

		Ok(Request {
			uri: requri,
			fields: fields,
		})
	}

	pub fn uri(&self) -> &str {
		self.uri
	}

	pub fn get(&self, key: &str) -> Option<&str> {
		self.fields.get(&key).cloned()
	}
}

impl<'a> Response<'a> {
	pub fn new(status: &'a str) -> Response<'a> {
		Response {
			status_line: status,
			fields: HashMap::new(),
		}
	}

	pub fn set(&mut self, key: &'a str, value: &'a str) {
		let _ = self.fields.insert(key, value);
	}

	pub fn into_bytes(&self) -> Vec<u8> {
		let fields = self.fields.iter().map(|(k, v)| format!("{}: {}", k, v));
		let mut response_str = std::iter::once(self.status_line.to_string())
			.chain(fields)
			.fold(String::new(), |mut acc, s| {
				acc.push_str(s.as_str());
				acc.push_str("\r\n");
				acc
			});

		response_str.push_str("\r\n");
		response_str.into_bytes()
	}
}
