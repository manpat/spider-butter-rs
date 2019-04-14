use std::net::TcpStream;
use std::os::unix::io::AsRawFd;
use acme_client::openssl::ssl::SslStream;

pub trait TcpStreamExt {
	fn has_pending_writes(&self) -> bool;
	fn has_pending_reads(&self) -> bool;
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
}