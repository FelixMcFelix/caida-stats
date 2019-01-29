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
	pub udp_unknown: VolumeStat,
	pub udp_quic: VolumeStat,
	pub tcp: VolumeStat,
	pub other: VolumeStat,
}

impl Default for PacketVolumeStats {
	fn default() -> Self {
		let stat: VolumeStat = Default::default();
		Self {
			udp_non_quic: stat,
			udp_unknown: stat,
			udp_quic: stat,
			tcp: stat,
			other: stat,
		}
	}
}

impl Add for PacketVolumeStats {
	type Output = Self;

	fn add(self, other_stats: Self) -> Self {
		Self {
			udp_non_quic: self.udp_non_quic + other_stats.udp_non_quic,
			udp_unknown: self.udp_unknown + other_stats.udp_unknown,
			udp_quic: self.udp_quic + other_stats.udp_quic,
			tcp: self.tcp + other_stats.tcp,
			other: self.other + other_stats.other,
		}
	}
}

impl AddAssign for PacketVolumeStats {
	fn add_assign(&mut self, other: Self) {
		self.udp_non_quic += other.udp_non_quic;
		self.udp_unknown += other.udp_unknown;
		self.udp_quic += other.udp_quic;
		self.tcp += other.tcp;
		self.other += other.other;
	}
}

#[derive(Debug, Deserialize, Serialize)]
pub struct VolumeStatRow<'a> {
	pub month_range: &'a str,
	pub stats: PacketVolumeStats,

	pub frac_pkts_congestion_aware: f64,
	pub frac_bytes_congestion_aware: f64,

	pub frac_pkts_tcp: f64,
	pub frac_bytes_tcp: f64,

	pub frac_pkts_udp: f64,
	pub frac_bytes_udp: f64,

	pub frac_pkts_other: f64,
	pub frac_bytes_other: f64,
}

impl<'a> VolumeStatRow<'a> {
	pub fn new(month_range: &'a str, stats: PacketVolumeStats) -> Self {
		let udp = stats.udp_quic + stats.udp_non_quic + stats.udp_unknown;
		let ca = stats.udp_quic + stats.tcp;
		let total = stats.tcp + udp + stats.other;

		let t_c = total.count as f64;
		let t_v = total.volume as f64;

		Self {
			month_range,
			stats,

			frac_pkts_congestion_aware: (ca.count as f64) / t_c,
			frac_bytes_congestion_aware: (ca.volume as f64) / t_v,

			frac_pkts_tcp: (stats.tcp.count as f64) / t_c,
			frac_bytes_tcp: (stats.tcp.volume as f64) / t_v,

			frac_pkts_udp: (udp.count as f64) / t_c,
			frac_bytes_udp: (udp.volume as f64) / t_v,

			frac_pkts_other: (stats.other.count as f64) / t_c,
			frac_bytes_other: (stats.other.volume as f64) / t_v,
		}
	}
}