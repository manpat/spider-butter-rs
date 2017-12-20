use std::ops::{Generator, GeneratorState};
use std::marker::Send;

pub struct Coro<Y> {
	pub value: Option<Y>,
	
	valid: bool,
	coro: Box<Generator<Yield=Y, Return=()>>,
}

unsafe impl<Y> Send for Coro<Y> where Y: Send {}

impl<Y> Coro<Y> {
	pub fn is_valid(&self) -> bool { self.valid }
}

impl<Y, G> From<G> for Coro<Y> where G: 'static + Generator<Yield=Y, Return=()> {
	fn from(gen: G) -> Self {
		Coro {
			coro: box gen,
			value: None,
			valid: true,
		}
	}
}

impl<Y> Iterator for Coro<Y> {
	type Item = Y;
	default fn next(&mut self) -> Option<Self::Item> {
		if !self.valid { return None }

		if let GeneratorState::Yielded(yielded_value) = self.coro.resume() {
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

		if let GeneratorState::Yielded(yielded_value) = self.coro.resume() {
			self.value = Some(yielded_value);
			self.value.clone()
		} else {
			self.valid = false;
			None
		}
	}
}

pub struct StackCoro<Y, G: Generator<Yield=Y, Return=()>> {
	pub value: Option<Y>,

	valid: bool,
	coro: G,
}

unsafe impl<Y, G> Send for StackCoro<Y, G> where Y: Send, G: Send + Generator<Yield=Y, Return=()> {}

impl<Y, G> StackCoro<Y, G> where G: Generator<Yield=Y, Return=()> {
	pub fn is_valid(&self) -> bool { self.valid }
}

impl<Y, G> From<G> for StackCoro<Y, G> where G: Generator<Yield=Y, Return=()> {
	fn from(gen: G) -> Self {
		StackCoro {
			coro: gen,
			value: None,
			valid: true,
		}
	}
}

impl<Y, G> Iterator for StackCoro<Y, G> where G: Generator<Yield=Y, Return=()> {
	type Item = Y;
	default fn next(&mut self) -> Option<Self::Item> {
		if !self.valid { return None }

		if let GeneratorState::Yielded(yielded_value) = self.coro.resume() {
			Some(yielded_value)
		} else {
			self.valid = false;
			None
		}
	}
}

impl<Y, G> Iterator for StackCoro<Y, G> where Y: Clone, G: Generator<Yield=Y, Return=()> {
	fn next(&mut self) -> Option<Self::Item> {
		if !self.valid { return None }

		if let GeneratorState::Yielded(yielded_value) = self.coro.resume() {
			self.value = Some(yielded_value);
			self.value.clone()
		} else {
			self.valid = false;
			None
		}
	}
}
