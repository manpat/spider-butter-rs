#![allow(dead_code)]

use std::ops::{Generator, GeneratorState};
use std::marker::Send;
use std::pin::Pin;

pub struct Coro<Y> {
	coro: Pin<Box<dyn Generator<Yield=Y, Return=()>>>,
	valid: bool,
}

unsafe impl<Y> Send for Coro<Y> where Y: Send {}

impl<Y> Coro<Y> {
	pub fn is_valid(&self) -> bool { self.valid }

	pub fn resume(&mut self) -> Option<Y> {
		if !self.valid { return None }

		if let GeneratorState::Yielded(yielded_value) = self.coro.as_mut().resume() {
			Some(yielded_value)
		} else {
			self.valid = false;
			None
		}
	}
}

impl<Y, G> From<G> for Coro<Y> where G: 'static + Generator<Yield=Y, Return=()> {
	fn from(gen: G) -> Self {
		Coro {
			coro: Box::pin(gen),
			valid: true,
		}
	}
}

impl<Y> Iterator for Coro<Y> {
	type Item = Y;
	fn next(&mut self) -> Option<Self::Item> { self.resume() }
}

#[macro_export]
macro_rules! coro_await {
	($coro:expr) => {{
		use std::pin::Pin;
		use std::ops::{Generator, GeneratorState};

		let mut c = $coro;

		loop {
			let pinned = unsafe {
				Pin::new_unchecked(&mut c)
			};

			if let GeneratorState::Complete(r) = pinned.resume() {
				break r
			}

			yield;
		}
	}};

	($coro:expr, yield $yield_expr:expr) => {{
		use std::pin::Pin;
		use std::ops::{Generator, GeneratorState};

		let mut c = $coro;

		loop {
			let pinned = unsafe {
				Pin::new_unchecked(&mut c)
			};

			if let GeneratorState::Complete(r) = pinned.resume() {
				break r
			}

			yield $yield_expr;
		}
	}};
}