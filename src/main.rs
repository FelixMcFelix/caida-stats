mod chunkreader;
mod error;
mod stats;

use crate::{
	chunkreader::ChunkReader,
	error::*,
	stats::*,
};
use csv::WriterBuilder;
use etherparse::{
	IpHeader,
	IpTrafficClass,
	PacketHeaders,
	ReadError as EtherReadError,
	TransportHeader,
};
use futures::{
	future::{
		self,
		Either,
		Loop,
	},
	Future,
	Stream,
};
use hyper::rt;
use libflate::gzip::MultiDecoder as Decoder;
use parking_lot::RwLock;
use pcap_file::{
	Packet,
	PcapReader,
};
use rand::Rng;
use reqwest::{
	r#async::Client as AsyncClient,
	Client,
};
use ron::{
	de,
	ser,
};
use select::{
	document::Document,
	predicate::Name,
};
use serde::Serialize;
use std::{
	fs::{
		self,
		File,
	},
	io::{
		self,
		Write,
	},
	sync::{
		mpsc,
		Arc,
	},
	thread,
	time::{
		Duration,
		Instant,
	},
};
use tokio::timer::Delay;

type Pvs = PacketVolumeStats;
type Pvs3 = (Pvs, Pvs, Pvs);
type OutPartition = (&'static str, fn(Pvs3) -> Pvs);

const DATA_URL: &str = "https://data.caida.org/datasets/passive-2018/equinix-nyc/";
const MIN_RETRY_DELAY: u64 = 1_000;
const MAX_RETRY_DELAY: u64 = 5_000;

const MONTHS: &[&str] = &["Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
const MONTH_PATCHES: &[usize] = &[10, 5, 2, 1];
const RESULTS_DIR: &str = "results/";

type ClientData = (AsyncClient, String, String);
type LockedClientData = Arc<RwLock<ClientData>>;

fn main() -> LocalResult<()> {
	// Get/process username
	print!("User: ");
	io::stdout().flush()?;
	let mut user = String::new();
	io::stdin().read_line(&mut user)?;
	while user.ends_with('\n') || user.ends_with('\r') {
		user.pop();
	}

	// Get password.
	let password = rpassword::prompt_password_stdout("Password: ")?;
	println!();

	let client = Client::new();
	let async_client = Arc::new(RwLock::new((AsyncClient::new(), user.clone(), password.clone())));

	// Top-level request
	let resp = client.get(DATA_URL)
		.basic_auth(&user, Some(&password))
		.send()?;

	let doc = Document::from_read(resp)?;

	let mut new_root = DATA_URL.to_string();
	let start_index = DATA_URL.len();

	let mut month_stats = vec![];

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

			let dir_a = file.contains("dirA");

			// Check if stats already written to disk.
			if let Ok(local_file) = File::open(&new_root[start_index..]) {
				ron_files.push((local_file, dir_a));
			} else {
				// Create file and do some stream magic...
				ron_files.push((
					process_file(
						async_client.clone(),
						new_root.clone(),
						start_index,
						before_ron_len,
					)?,
					dir_a,
				));
			}

			new_root.truncate(clip_len);
		}

		// Now combine stuff from all files...
		// We should get 3 sets of counts for each month: 
		let all_files = ron_files.into_iter()
			.map(|(f, d)|
				(de::from_reader::<_, Pvs>(f).expect("Couldn't unpack file..."), d)
			);

		let (a_total, b_total) = all_files
			.fold(
				(Pvs::default(), Pvs::default()),
				|(acc_a, acc_b), (x, dir_a)| if dir_a {
					(acc_a + x, acc_b)
				} else {
					(acc_a, acc_b + x)
				},
			);

		let all_total = a_total + b_total;

		new_root.truncate(start_index);

		month_stats.push((all_total, a_total, b_total));
	}

	let settings: [OutPartition; 3] = {
		[
			("biDir", pvs_0),
			("dirA", pvs_1),
			("dirB", pvs_2),
		]
	};

	let _ = fs::create_dir_all(RESULTS_DIR);
	let month_stats = month_stats.into_iter();

	#[inline]
	fn patch_size_string(patch_size: usize, i: usize) -> String {
		if patch_size > 1 {
			format!("{}-{}", MONTHS[i - patch_size + 1], MONTHS[i])
		} else {
			format!("{}", MONTHS[i])
		}
	}

	for patch_size in MONTH_PATCHES {
		for (name_mod, extract_fn) in &settings {
			// let mut wb = WriterBuilder::new().has_headers(false);
			let mut wrt = WriterBuilder::new()
				.has_headers(false)
				.from_path(format!("{0}{1}-{2}.csv", RESULTS_DIR, name_mod, patch_size))?;
			let mut current_stat = None;

			for (i, month) in month_stats.clone().map(extract_fn).enumerate() {
				current_stat = if let Some(s) = current_stat {
					Some(s + month)
				} else {
					Some(month)
				};

				if (i + 1) % patch_size == 0 {
					// Write out the row.
					wrt.serialize(VolumeStatRow::new(
						&patch_size_string(*patch_size, i),
						current_stat.expect("...")
					))?;
					current_stat = None;
				}
			}

			if let Some(c) = current_stat {
				wrt.serialize(VolumeStatRow::new(
					&patch_size_string(*patch_size, month_stats.len() - 1),
					c,
				))?;
			}
		}
	}

	Ok(())
}

fn pvs_0(x: Pvs3) -> Pvs { x.0 }
fn pvs_1(x: Pvs3) -> Pvs { x.1 }
fn pvs_2(x: Pvs3) -> Pvs { x.2 }

fn save_and_scan_back<S>(out_file: &str, to_save: S) -> LocalResult<File>
	where S: Serialize
{
	// Scanning would make sense, but doesn't seem to work for whatever reason.
	{
		let mut out = File::create(out_file)?;
		out.write_all(ser::to_string(&to_save)?.as_bytes())?;
		// out.seek(SeekFrom::Start(0))?;
	}

	File::open(out_file).map_err(Into::into)
}

fn process_file(
		client_data: LockedClientData,
		file_string: String,
		new_index: usize,
		url_index: usize,
	) -> LocalResult<File> {
	let (tx, rx) = mpsc::sync_channel(4096);
	let out_file = &file_string[new_index..];

	let file_string_inner = file_string.clone();
	let url_index_inner = url_index;

	thread::spawn(move || {
		println!("Started child thread.");
		let safe_tx = tx;

		// Need to loop until we don't get a 503.
		let request = {
			let data_lock = client_data.clone();
			let (ref client, ref user, ref password) = *data_lock.read();

			client.get(&file_string_inner[..url_index])
				.basic_auth(&user, Some(&password))
		};

		let a = request.send()
			.map(move |resp| (resp, client_data))
			.map_err(|e| println!("Error sending request: {:?}", e))
			.and_then(move |x| future::loop_fn(x, move |(resp, client_data)| {
				// Server might have 503'd us. Keep trying.
				if let Some(a) = resp.headers().get("connection") {
					// Have to destructure, THEN compare...
					if a == "close" {
						let request = {
							let data_lock = client_data.clone();
							let (ref client, ref user, ref password) = *data_lock.read();

							client.get(&file_string_inner[..url_index_inner])
								.basic_auth(&user, Some(&password))
						};
						
						Either::A(
							Delay::new(
								Instant::now() +
								Duration::from_millis(
									rand::thread_rng().gen_range(
										MIN_RETRY_DELAY,
										MAX_RETRY_DELAY,
									)
								)
							)
							.map_err(|_| ())
							.and_then(move |_|
								request.send()
									.map(move |r| Loop::Continue((r, client_data)))
									.map_err(|e|
										println!("Error sending request: {:?}", e)
									)
							)
						)
					} else {
						Either::B(future::ok(Loop::Break(resp)))
					}
				} else {
					Either::B(future::ok(Loop::Break(resp)))
				}
			}))
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

	let mut stats_ongoing = Pvs::default();

	for (i, pcap) in pcap_stream.enumerate() {//.take(100) {
		if let Ok(pcap) = pcap {
			let Packet { data, .. } = pcap;
			if packet_volume(&mut stats_ongoing, &data).is_err() {
				// I know from looking at the data that it probably died for two reasons...
				// 1: chopped in the middle of the TCP options block (due to variable length SACK).
				// 2: No UDP header (???)
				// This function should do simpler mining...
				if let Err(e) = packet_volume_emergency(&mut stats_ongoing, &data) {
					println!("Weird packet: {:?}, len: {}, {:x?}, proto: {}", e, &data.len(), &data, data[9]);
				}
			}
		}

		if i % 100_000 == 0 {
			println!("{}: {} = {:?}", out_file, i, stats_ongoing);
		}
	}

	save_and_scan_back(out_file, stats_ongoing)
}

fn packet_volume(stats: &mut Pvs, data: &[u8]) -> Result<(), EtherReadError> {
	let pkt = PacketHeaders::from_ip_slice(data)?;

	let pkt_size = match pkt.ip {
		Some(IpHeader::Version4(h)) => h.payload_len,
		Some(IpHeader::Version6(h)) => h.payload_length,
		_ => 0,
	}.into();

	match pkt.transport {
		Some(TransportHeader::Tcp(_h)) => stats.tcp.packet(pkt_size),
		Some(TransportHeader::Udp(h)) => match (h.destination_port, h.source_port) {
			(80, _) | (443, _) |
			(_, 80) | (_, 443) => stats.udp_quic.packet(pkt_size),
			_ => stats.udp_non_quic.packet(pkt_size),
		},
		_ => stats.other.packet(pkt_size),
	}

	Ok(())
}

fn packet_volume_emergency(stats: &mut Pvs, data: &[u8]) -> Result<(), EtherReadError> {
	let (ip, _rest) = IpHeader::read_from_slice(data)?;

	let (len, proto) = match ip {
		IpHeader::Version4(h) => (h.payload_len.into(), h.protocol),
		IpHeader::Version6(h) => (h.payload_length.into(), h.traffic_class),
	};

	const UDP: u8 = IpTrafficClass::Udp as u8;
	const TCP: u8 = IpTrafficClass::Tcp as u8;

	match proto {
		UDP => stats.udp_unknown.packet(len),
		TCP => stats.tcp.packet(len),
		_ =>  stats.other.packet(len),
	}

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
