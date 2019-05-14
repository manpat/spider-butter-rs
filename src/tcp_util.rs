use std::net::TcpStream;
use std::os::unix::io::AsRawFd;
use acme_client::openssl::ssl::SslStream;
use crate::SBResult;

use std::ops::Generator;
use std::io::Write;

pub trait TcpStreamExt {
	fn has_pending_writes(&self) -> bool;
	fn has_pending_reads(&self) -> bool;
	fn set_nonblocking(&self, _: bool) -> SBResult<()>;
}

impl TcpStreamExt for TcpStream {
	fn has_pending_writes(&self) -> bool {
		unsafe {
			let fd = self.as_raw_fd();

			let mut pending = 0i32;
			let ret = libc::ioctl(fd, libc::TIOCOUTQ, &mut pending as *mut i32);
			assert!(ret >= 0);

			pending > 0
		}
	}

	fn has_pending_reads(&self) -> bool {
		unsafe {
			let fd = self.as_raw_fd();

			let mut pending = 0i32;
			let ret = libc::ioctl(fd, libc::TIOCINQ, &mut pending as *mut i32);
			assert!(ret >= 0);

			pending > 0
		}
	}

	fn set_nonblocking(&self, nonblock: bool) -> SBResult<()> {
		(self as &TcpStream).set_nonblocking(nonblock)
			.map_err(|e| e.into())
	}
}

impl TcpStreamExt for SslStream<TcpStream> {
	fn has_pending_writes(&self) -> bool {
		unsafe {
			let fd = self.get_ref().as_raw_fd();

			let mut pending = 0i32;
			let ret = libc::ioctl(fd, libc::TIOCOUTQ, &mut pending as *mut i32);
			assert!(ret >= 0);

			pending > 0
		}
	}

	fn has_pending_reads(&self) -> bool {
		unsafe {
			let fd = self.get_ref().as_raw_fd();

			let mut pending = 0i32;
			let ret = libc::ioctl(fd, libc::TIOCINQ, &mut pending as *mut i32);
			assert!(ret >= 0);

			pending > 0
		}
	}

	fn set_nonblocking(&self, nonblock: bool) -> SBResult<()> {
		self.get_ref().set_nonblocking(nonblock)
			.map_err(|e| e.into())
	}
}


#[must_use]
pub fn write_async<'a, S>(stream: &'a mut S, bytes: &'a [u8]) -> impl Generator<Yield=(), Return=SBResult<()>> + 'a
	where S: TcpStreamExt + Write {

	use std::io::ErrorKind::{WouldBlock, Interrupted};

	move || {
		let mut cursor = 0;

		loop {
			let result = stream.write(&bytes[cursor..]);
			match result {
				Err(ref e) if e.kind() == WouldBlock => yield,
				Err(ref e) if e.kind() == Interrupted => yield,
				Err(e) => return Err(e.into()),
				Ok(sz) => {
					cursor += sz;
					if cursor >= bytes.len() { break }
					continue
				},
			};
		}

		Ok(())
	}
}