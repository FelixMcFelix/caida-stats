use csv::Error as CsvError;
use http::Error as HttpError;
use pcap_file::Error as PcapError;
use reqwest::Error as ReqwestError;
use ron::{
	de::Error as RonDeError,
	ser::Error as RonSerError,
};
use std::{
	error::Error,
	fmt,
	io::Error as IoError,
};

#[derive(Debug)]
pub enum LocalError {
	Csv(CsvError),
	Http(HttpError),
	Io(IoError),
	Pcap(PcapError),
	Reqwest(ReqwestError),
	RonDe(RonDeError),
	RonSer(RonSerError),
}

impl Error for LocalError {
	fn description(&self) -> &str {
		use LocalError::*;

		match self {
			Csv(e) => e.description(),
			Http(e) => e.description(),
			Io(e) => e.description(),
			Pcap(e) => e.description(),
			Reqwest(e) => e.description(),
			RonDe(e) => e.description(),
			RonSer(e) => e.description(),
		}
	}
}

impl fmt::Display for LocalError {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		use LocalError::*;

		match self {
			Csv(e) => e.fmt(f),
			Http(e) => e.fmt(f),
			Io(e) => e.fmt(f),
			Pcap(e) => e.fmt(f),
			Reqwest(e) => e.fmt(f),
			RonDe(e) => e.fmt(f),
			RonSer(e) => e.fmt(f),
		}
	}
}

impl From<CsvError> for LocalError {
	fn from(t: CsvError) -> Self {
		LocalError::Csv(t)
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

impl From<RonDeError> for LocalError {
	fn from(t: RonDeError) -> Self {
		LocalError::RonDe(t)
	}
}

impl From<RonSerError> for LocalError {
	fn from(t: RonSerError) -> Self {
		LocalError::RonSer(t)
	}
}

pub type LocalResult<T> = Result<T, LocalError>;