use bytes::Bytes;
use hyper::Chunk;
use reqwest::r#async::Chunk as AsyncChunk;
use std::{
	io::{
		self,
		Error as IoError,
		Read,
		Result as IoResult,
	},
	sync::mpsc,
};

pub struct ChunkReader{
	inner: mpsc::Receiver<AsyncChunk>,
	leftover: Option<Bytes>,
}

impl ChunkReader {
	pub fn new(inner: mpsc::Receiver<AsyncChunk>) -> Self {
		Self {
			inner,
			leftover: None,
		}
	}
}

impl Read for ChunkReader {
	fn read(&mut self, buf: &mut [u8]) -> IoResult<usize> {
		let init = buf.len();
		let mut remaining = init;

		// Might start with a "leftover" chunk, also need
		// to then loop on trying to receive further chunks.
		let mut current = None;
		
		while remaining > 0 {
			current = self.leftover.take();

			let ask_new = if let Some(c) = &mut current {
				let open = remaining.min(c.len());
				buf[..open].copy_from_slice(&c.split_to(open));

				remaining -= open;

				c.is_empty()
			} else {
				true
			};

			self.leftover = if ask_new {
				let mesg = self.inner.recv();

				if mesg.is_err() {
					return Err(IoError::new(
						io::ErrorKind::UnexpectedEof,
						"Chunk Sources disconnected.",
					));
				}

				mesg.ok()
					.map(Into::into)
					.map(Chunk::into_bytes)
			} else {
				current
			};

			if self.leftover.is_none() { break; }
		}

		Ok(init - remaining)
	}
}