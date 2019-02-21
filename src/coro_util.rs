#![allow(dead_code)]

use std::ops::{Generator, GeneratorState};
use std::marker::Send;
use std::pin::Pin;

pub struct Coro<Y> {
	pub value: Option<Y>,
	
	valid: bool,
	coro: Pin<Box<dyn Generator<Yield=Y, Return=()>>>,
}

unsafe impl<Y> Send for Coro<Y> where Y: Send {}

impl<Y> Coro<Y> {
	pub fn is_valid(&self) -> bool { self.valid }
}

impl<Y, G> From<G> for Coro<Y> where G: 'static + Generator<Yield=Y, Return=()> {
	fn from(gen: G) -> Self {
		Coro {
			coro: Box::pin(gen),
			value: None,
			valid: true,
		}
	}
}

impl<Y> Iterator for Coro<Y> {
	type Item = Y;
	default fn next(&mut self) -> Option<Self::Item> {
		if !self.valid { return None }

		if let GeneratorState::Yielded(yielded_value) = Pin::new(&mut self.coro).resume() {
			Some(yielded_value)
		} else {
			self.valid = false;
			None
		}
	}
}

impl<Y: Clone> Iterator for Coro<Y> {
	fn next(&mut self) -> Option<Self::Item> {
		if !self.valid { return None }

		if let GeneratorState::Yielded(yielded_value) = Pin::new(&mut self.coro).resume() {
			self.value = Some(yielded_value);
			self.value.clone()
		} else {
			self.valid = false;
			None
		}
	}
}
