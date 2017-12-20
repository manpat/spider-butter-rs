use std::net::TcpStream;
use std::os::unix::io::AsRawFd;
use libc::*;

pub trait TcpStreamExt {
	fn has_pending_writes(&self) -> bool;
	fn has_pending_reads(&self) -> bool;
}

impl TcpStreamExt for TcpStream {
	fn has_pending_writes(&self) -> bool {
		unsafe {
			let fd = self.as_raw_fd();

			let mut pending = 0i32;
			let ret = ioctl(fd, TIOCOUTQ, &mut pending as *mut i32);
			assert!(ret >= 0);

			pending > 0
		}
	}

	fn has_pending_reads(&self) -> bool {
		unsafe {
			let fd = self.as_raw_fd();

			let mut pending = 0i32;
			let ret = ioctl(fd, TIOCINQ, &mut pending as *mut i32);
			assert!(ret >= 0);

			pending > 0
		}
	}
}