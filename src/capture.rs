use libc::tpacket_versions::TPACKET_V2;
use libc::{
    bind, c_int, c_void, close, ioctl, mmap, munmap, packet_mreq, poll, pollfd, setsockopt,
    sockaddr, sockaddr_ll, socket, tpacket2_hdr, tpacket_req, AF_PACKET, ETH_P_ALL, IFNAMSIZ,
    MAP_FAILED, MAP_SHARED, PACKET_ADD_MEMBERSHIP, PACKET_MR_PROMISC, PACKET_RX_RING,
    PACKET_VERSION, POLLIN, PROT_READ, PROT_WRITE, SOCK_RAW, SOL_PACKET,
};
use std::ffi::CString;
use std::mem;

// TP_STATUS flags
const TP_STATUS_KERNEL: u32 = 0;
const TP_STATUS_USER: u32 = 1;

// ioctl request number for getting interface index
const SIOCGIFINDEX: libc::c_ulong = 0x8933;

// ifreq structure for ioctl
#[repr(C)]
union IfReqData {
    ifindex: c_int,
    pad: [u8; 24],
}

#[repr(C)]
struct IfReq {
    ifr_name: [u8; IFNAMSIZ],
    data: IfReqData,
}

pub struct Capture {
    fd: i32,
    ring: *mut u8,
    ring_size: usize,
    frame_size: usize,
    frame_count: usize,
    frame_idx: usize,
}

// SAFETY: Capture owns the mmap'd memory and fd exclusively.
// The *mut u8 pointer is only accessed through &mut self methods.
unsafe impl Send for Capture {}

impl Capture {
    pub fn open(interface: &str, snaplen: usize, promisc: bool) -> Result<Self, String> {
        // Create AF_PACKET SOCK_RAW socket
        let fd = unsafe { socket(AF_PACKET, SOCK_RAW, (ETH_P_ALL as u16).to_be() as c_int) };
        if fd < 0 {
            return Err(format!(
                "socket(AF_PACKET, SOCK_RAW) failed: {}",
                std::io::Error::last_os_error()
            ));
        }

        // Get interface index
        let ifindex = match unsafe { get_ifindex(fd, interface) } {
            Ok(idx) => idx,
            Err(e) => {
                unsafe { close(fd) };
                return Err(e);
            }
        };

        // Set TPACKET_V2
        let version: c_int = TPACKET_V2 as c_int;
        let ret = unsafe {
            setsockopt(
                fd,
                SOL_PACKET,
                PACKET_VERSION,
                &version as *const c_int as *const c_void,
                mem::size_of::<c_int>() as u32,
            )
        };
        if ret < 0 {
            unsafe { close(fd) };
            return Err(format!(
                "setsockopt(PACKET_VERSION) failed: {}",
                std::io::Error::last_os_error()
            ));
        }

        // Setup ring buffer parameters
        // block_size must be a multiple of PAGE_SIZE; use 4096
        // frame_size must accommodate tpacket2_hdr + snaplen
        let block_size: u32 = 4096;
        let block_count: u32 = 256;
        let frame_size: u32 = next_pow2(mem::size_of::<tpacket2_hdr>() + snaplen + 32) as u32;
        // frame_size must not exceed block_size
        let frame_size = if frame_size > block_size {
            block_size
        } else {
            frame_size
        };
        let frame_count: u32 = (block_size / frame_size) * block_count;

        let req = tpacket_req {
            tp_block_size: block_size,
            tp_block_nr: block_count,
            tp_frame_size: frame_size,
            tp_frame_nr: frame_count,
        };

        let ret = unsafe {
            setsockopt(
                fd,
                SOL_PACKET,
                PACKET_RX_RING,
                &req as *const tpacket_req as *const c_void,
                mem::size_of::<tpacket_req>() as u32,
            )
        };
        if ret < 0 {
            unsafe { close(fd) };
            return Err(format!(
                "setsockopt(PACKET_RX_RING) failed: {}",
                std::io::Error::last_os_error()
            ));
        }

        // mmap the ring buffer
        let ring_size = (block_size * block_count) as usize;
        let ring = unsafe {
            mmap(
                std::ptr::null_mut(),
                ring_size,
                PROT_READ | PROT_WRITE,
                MAP_SHARED,
                fd,
                0,
            )
        };
        if ring == MAP_FAILED {
            unsafe { close(fd) };
            return Err(format!(
                "mmap() failed: {}",
                std::io::Error::last_os_error()
            ));
        }

        // Bind to the interface
        let mut sll: sockaddr_ll = unsafe { mem::zeroed() };
        sll.sll_family = AF_PACKET as u16;
        sll.sll_protocol = (ETH_P_ALL as u16).to_be();
        sll.sll_ifindex = ifindex;

        let ret = unsafe {
            bind(
                fd,
                &sll as *const sockaddr_ll as *const sockaddr,
                mem::size_of::<sockaddr_ll>() as u32,
            )
        };
        if ret < 0 {
            unsafe {
                munmap(ring, ring_size);
                close(fd);
            }
            return Err(format!(
                "bind() failed: {}",
                std::io::Error::last_os_error()
            ));
        }

        // Set promiscuous mode if requested
        if promisc {
            let mut mreq: packet_mreq = unsafe { mem::zeroed() };
            mreq.mr_ifindex = ifindex;
            mreq.mr_type = PACKET_MR_PROMISC as u16;

            let ret = unsafe {
                setsockopt(
                    fd,
                    SOL_PACKET,
                    PACKET_ADD_MEMBERSHIP,
                    &mreq as *const packet_mreq as *const c_void,
                    mem::size_of::<packet_mreq>() as u32,
                )
            };
            if ret < 0 {
                unsafe {
                    munmap(ring, ring_size);
                    close(fd);
                }
                return Err(format!(
                    "setsockopt(PACKET_ADD_MEMBERSHIP) failed: {}",
                    std::io::Error::last_os_error()
                ));
            }
        }

        Ok(Capture {
            fd,
            ring: ring as *mut u8,
            ring_size,
            frame_size: frame_size as usize,
            frame_count: frame_count as usize,
            frame_idx: 0,
        })
    }

    pub fn next_packet(&mut self) -> Option<&[u8]> {
        loop {
            // Pointer to the current frame header in the ring
            let frame_offset = self.frame_idx * self.frame_size;
            // SAFETY: frame_offset is always within [0, ring_size)
            let hdr_ptr = unsafe { self.ring.add(frame_offset) as *mut tpacket2_hdr };

            // Check frame status
            let status = unsafe { (*hdr_ptr).tp_status };

            if status & TP_STATUS_USER == 0 {
                // Frame not ready — poll with 1 second timeout
                let mut pfd = pollfd {
                    fd: self.fd,
                    events: POLLIN,
                    revents: 0,
                };
                let ret = unsafe { poll(&mut pfd, 1, 1000) };
                if ret <= 0 {
                    // Timeout or error — no packet available right now
                    return None;
                }
                continue;
            }

            // Frame is ready — extract packet slice
            let mac_offset = unsafe { (*hdr_ptr).tp_mac } as usize;
            let snaplen = unsafe { (*hdr_ptr).tp_snaplen } as usize;

            // SAFETY: tp_mac and tp_snaplen come from the kernel via the ring buffer.
            // They are guaranteed to fit within frame_size.
            let packet = unsafe {
                let data_ptr = self.ring.add(frame_offset + mac_offset);
                std::slice::from_raw_parts(data_ptr, snaplen)
            };

            // We need to return the slice and then advance the frame.
            // Because we can't easily do both in safe Rust (borrow + mutation),
            // we capture the raw parts and reconstruct after advancing.
            let data_ptr = unsafe { self.ring.add(frame_offset + mac_offset) };
            let len = snaplen;

            // Return frame to kernel
            unsafe {
                (*hdr_ptr).tp_status = TP_STATUS_KERNEL;
            }

            // Advance frame index (wrapping)
            self.frame_idx = (self.frame_idx + 1) % self.frame_count;

            // SAFETY: data_ptr points into the mmap'd ring which lives as long as self.
            // The lifetime of the returned slice is tied to &mut self.
            let _ = packet; // suppress unused variable warning
            return Some(unsafe { std::slice::from_raw_parts(data_ptr, len) });
        }
    }
}

impl Drop for Capture {
    fn drop(&mut self) {
        unsafe {
            munmap(self.ring as *mut c_void, self.ring_size);
            close(self.fd);
        }
    }
}

/// Get interface index for the given interface name.
///
/// # Safety
/// `fd` must be a valid open socket file descriptor.
unsafe fn get_ifindex(fd: i32, name: &str) -> Result<i32, String> {
    if name.len() >= IFNAMSIZ {
        return Err(format!(
            "interface name '{}' too long (max {})",
            name,
            IFNAMSIZ - 1
        ));
    }

    let mut req: IfReq = mem::zeroed();

    let name_cstr = CString::new(name)
        .map_err(|_| format!("interface name '{}' contains a null byte", name))?;
    let name_bytes = name_cstr.as_bytes_with_nul();
    req.ifr_name[..name_bytes.len()].copy_from_slice(name_bytes);

    #[allow(clippy::cast_possible_wrap)]
    let ret = ioctl(fd, SIOCGIFINDEX as _, &mut req as *mut IfReq);
    if ret < 0 {
        return Err(format!(
            "ioctl(SIOCGIFINDEX) for '{}' failed: {}",
            name,
            std::io::Error::last_os_error()
        ));
    }

    Ok(req.data.ifindex)
}

/// Round `n` up to the next power of two (or `n` itself if already a power of two).
fn next_pow2(n: usize) -> usize {
    if n == 0 {
        return 1;
    }
    let mut p = 1usize;
    while p < n {
        p <<= 1;
    }
    p
}

#[cfg(test)]
mod tests {
    use super::next_pow2;

    #[test]
    fn next_pow2_values() {
        assert_eq!(next_pow2(0), 1);
        assert_eq!(next_pow2(1), 1);
        assert_eq!(next_pow2(2), 2);
        assert_eq!(next_pow2(3), 4);
        assert_eq!(next_pow2(128), 128);
        assert_eq!(next_pow2(129), 256);
        assert_eq!(next_pow2(4096), 4096);
        assert_eq!(next_pow2(4097), 8192);
    }
}
