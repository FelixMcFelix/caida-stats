mod stats;

use bytes::Bytes;
use etherparse::{
	IpHeader,
	PacketHeaders,
	ReadError as EtherReadError,
	TransportHeader,
};
use futures::{
	Future,
	Stream,
};
use http::Error as HttpError;
use hyper::{
	rt,
	Chunk,
};
use libflate::gzip::MultiDecoder as Decoder;
use pcap_file::{
	Error as PcapError,
	Packet,
	PcapReader,
};
use reqwest::{
	r#async::{
		Chunk as AsyncChunk,
		Client as AsyncClient,
		RequestBuilder as AsyncRequestBuilder,
	},
	Client,
	Error as ReqwestError,
};
use select::{
	document::Document,
	predicate::Name,
};
use stats::{
	PacketVolumeStats,
	VolumeStat,
};
use std::{
	error::Error,
	fmt,
	fs::{
		self,
		File,
	},
	io::{
		self,
		Error as IoError,
		Read,
		Result as IoResult,
	},
	sync::{
		mpsc,
	},
	thread,
};

const DATA_URL: &str = "https://data.caida.org/datasets/passive-2018/equinix-nyc/";

fn main() -> LocalResult<()> {
	// Get/process username
	// print!("User: ");
	// io::stdout().flush();
	// let mut user = String::new();
	// io::stdin().read_line(&mut user);
	// while user.ends_with('\n') || user.ends_with('\r') {
	// 	user.pop();
	// }

	let user = "k.simpson.1@research.gla.ac.uk";

	// Get password.
	let password = rpassword::prompt_password_stdout("Password:")?;
	println!();

	let client = Client::new();
	let async_client = AsyncClient::new();

	// Top-level request
	let resp = client.get(DATA_URL)
		.basic_auth(&user, Some(&password))
		.send()?;

	let doc = Document::from_read(resp)?;

	let mut new_root = DATA_URL.to_string();
	let start_index = DATA_URL.len();

	// Narrow down to the set of correct pages...
	for link in get_important_links(&doc) {
		// Create that dir here, to save stats to the right location...
		let _ = fs::create_dir_all(link);

		new_root.push_str(link);

		let clip_len = new_root.len();

		// Download that page, do the same trick again...
		let resp = client.get(&new_root)
			.basic_auth(&user, Some(&password))
			.send()?;

		let doc = Document::from_read(resp)?;

		let files = get_important_links(&doc)
			.filter(|s| s.ends_with(".pcap.gz"));

		let mut ron_files = vec![];

		for file in files {
			new_root.push_str(file);
			let before_ron_len = new_root.len();
			new_root.push_str(".ron");
			// Check if stats already written to disk.
			if let Ok(local_file) = File::open(&new_root[start_index..]) {
				ron_files.push(local_file);
			} else {
				let async_resp = async_client.get(&new_root[..before_ron_len])
					.basic_auth(&user, Some(&password));

				println!("DLing {}", &new_root[..before_ron_len]);

				// Create file and do some stream magic...
				// ron_files.push(
					process_file(
						async_resp,
						&new_root[start_index..],
					)?
				// );
			}

			// dbg!(file);
			new_root.truncate(clip_len);
		}

		// Now combine stuff from all files...
		// TODO

		new_root.truncate(start_index);
	}


	Ok(())
}

struct ChunkReader{
	inner: mpsc::Receiver<AsyncChunk>,
	leftover: Option<Bytes>,
}

impl ChunkReader {
	fn new(inner: mpsc::Receiver<AsyncChunk>) -> Self {
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

				c.len() == 0
			} else {
				true
			};

			self.leftover = if ask_new {
				let mesg = self.inner.recv();

				if let Err(_) = mesg {
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

fn process_file(request: AsyncRequestBuilder, out_file: &str) -> LocalResult<()> {
	let (tx, rx) = mpsc::sync_channel(4096);

	thread::spawn(move || {
		println!("Started child thread.");
		let safe_tx = tx;
		let a = request.send()
			.map_err(|e| println!("Error sending request: {:?}", e))
			.and_then(|resp| {
				println!("Got a response... {:?}", resp.headers());
				resp.into_body()
					.map_err(|e| println!("Bad response: {:?}", e))
					.for_each(move |chunk| {
						safe_tx
							.send(chunk)
							.map_err(|e|
								println!("Critically failed to send... {:?}", e)
							)
					})
			}).map_err(|e| println!("Error handling response: {:?}", e));

		rt::run(a);
		println!("Stopped child thread.");
	});

	let stream = ChunkReader::new(rx);
	let gzip_stream = Decoder::new(stream)?;
	let pcap_stream = PcapReader::new(gzip_stream)?;

	let mut stats_ongoing: PacketVolumeStats = Default::default();

	let mut i = 0;

	for pcap in pcap_stream {
		if let Ok(pcap) = pcap {
			let Packet {header, data} = pcap;
			if let Err(e) = packet_volume(&mut stats_ongoing, &data) {
				println!("Weird packet: {:?}, len: {}, {:x?}, proto: {}", e, &data.len(), &data, data[9]);
			}
		}

		i += 1;

		if i % 10000 == 0 {
			dbg!(stats_ongoing);
		}
	}



	Ok(())
}

fn packet_volume(stats: &mut PacketVolumeStats, data: &[u8]) -> Result<(), EtherReadError> {
	let pkt = PacketHeaders::from_ip_slice(data)?;

	let pkt_size = match pkt.ip {
		Some(IpHeader::Version4(h)) => h.payload_len,
		Some(IpHeader::Version6(h)) => h.payload_length,
		_ => 0,
	}.into();

	match pkt.transport {
		Some(TransportHeader::Tcp(h)) => stats.tcp.packet(pkt_size),
		Some(TransportHeader::Udp(h)) => match h.destination_port {
			80 | 443 => stats.quic.packet(pkt_size),
			_ => stats.udp_non_quic.packet(pkt_size),
		},
		_ => stats.other.packet(pkt_size),
	}

	// println!("{:?}", pkt);

	Ok(())
}

fn get_important_links(doc: &Document) -> impl Iterator<Item = &str> {
	// If element text matches href, then it's one of the links we care about.
	doc.find(Name("a"))
		.filter_map(|tag| {
			tag.attr("href")
				.filter(|&href| href == tag.text().as_str())
		})
}

#[derive(Debug)]
enum LocalError {
	Http(HttpError),
	Io(IoError),
	Pcap(PcapError),
	Reqwest(ReqwestError),
}

impl Error for LocalError {
	fn description(&self) -> &str {
		use LocalError::*;

		match self {
			Http(e) => e.description(),
			Io(e) => e.description(),
			Pcap(e) => e.description(),
			Reqwest(e) => e.description(),
		}
	}
}

impl fmt::Display for LocalError {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		use LocalError::*;

		match self {
			Http(e) => e.fmt(f),
			Io(e) => e.fmt(f),
			Pcap(e) => e.fmt(f),
			Reqwest(e) => e.fmt(f),
		}
	}
}

impl From<HttpError> for LocalError {
	fn from(t: HttpError) -> Self {
		LocalError::Http(t)
	}
}

impl From<IoError> for LocalError {
	fn from(t: IoError) -> Self {
		LocalError::Io(t)
	}
}

impl From<PcapError> for LocalError {
	fn from(t: PcapError) -> Self {
		LocalError::Pcap(t)
	}
}

impl From<ReqwestError> for LocalError {
	fn from(t: ReqwestError) -> Self {
		LocalError::Reqwest(t)
	}
}

type LocalResult<T> = Result<T, LocalError>;
