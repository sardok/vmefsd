use vsock::{VsockStream, VsockAddr};
use fortanix_vme_abi::SERVER_PORT;
use std::io;

pub struct VmeClient {
    stream: VsockStream,
}

impl VmeClient {
    pub fn new(cid: u32) -> io::Result<Self> {
        let addr = VsockAddr::new(cid, SERVER_PORT);
        let stream = VsockStream::connect(&addr)?;
        Ok(Self { stream })
    }
}
