use serde::{Deserialize, Serialize};
use std::ops::{Add, AddAssign};

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Serialize)]
pub struct VolumeStat {
	pub count: u64,
	pub volume: u64,
}

impl Default for VolumeStat {
	fn default() -> Self {
		Self {
			count: 0,
			volume: 0,
		}
	}
}

impl VolumeStat {
	pub fn packet(&mut self, size: u64) {
		self.count+= 1;
		self.volume += size;
	}

	// pub fn packet_unsized(&mut self) {
	// 	self.count+= 1;
	// }
}

impl Add for VolumeStat {
	type Output = Self;

	fn add(self, other: Self) -> Self {
		Self {
			count: self.count + other.count,
			volume: self.volume + other.volume,
		}
	}
}

impl AddAssign for VolumeStat {
	fn add_assign(&mut self, other: Self) {
		self.count += other.count;
		self.volume += other.volume;
	}
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Serialize)]
pub struct PacketVolumeStats {
	pub udp_non_quic: VolumeStat,
	pub quic: VolumeStat,
	pub tcp: VolumeStat,
	pub other: VolumeStat,
}

impl Default for PacketVolumeStats {
	fn default() -> Self {
		let stat: VolumeStat = Default::default();
		Self {
			udp_non_quic: stat,
			quic: stat,
			tcp: stat,
			other: stat,
		}
	}
}