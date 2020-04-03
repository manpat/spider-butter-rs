#![allow(dead_code)]

use std::ops::{Generator, GeneratorState};
use std::marker::Send;
use std::pin::Pin;

pub struct Task<R> {
	coro: Pin<Box<dyn Generator<Yield=(), Return=R>>>,
	valid: bool,
}

unsafe impl<R> Send for Task<R> where R: Send {}

impl<R> Task<R> {
	pub fn is_valid(&self) -> bool { self.valid }

	pub fn resume(&mut self) -> Option<R> {
		if !self.valid { return None }

		if let GeneratorState::Complete(yielded_value) = self.coro.as_mut().resume(()) {
			self.valid = false;
			Some(yielded_value)
		} else {
			None
		}
	}
}

impl<R, G> From<G> for Task<R> where G: 'static + Generator<Yield=(), Return=R> {
	fn from(gen: G) -> Self {
		Task {
			coro: Box::pin(gen),
			valid: true,
		}
	}
}

#[macro_export]
macro_rules! task_await {
	($coro:expr) => {{
		use std::pin::Pin;
		use std::ops::{Generator, GeneratorState};

		let mut c = $coro;

		loop {
			let pinned = unsafe {
				Pin::new_unchecked(&mut c)
			};

			if let GeneratorState::Complete(r) = pinned.resume(()) {
				break r
			}

			yield;
		}
	}}
}