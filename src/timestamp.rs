use std::io;
use std::net::SocketAddr;
use std::os::fd::AsRawFd;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::io::Interest;
use tokio::net::UdpSocket;

/// Enables kernel nanosecond receive timestamps (`SO_TIMESTAMPNS`) on supported Unix targets.
pub fn enable_kernel_timestamps(socket: &UdpSocket) -> io::Result<()> {
    #[cfg(target_os = "linux")]
    unsafe {
        let fd = socket.as_raw_fd();
        let enabled: libc::c_int = 1;
        let ret = libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_TIMESTAMPNS,
            &enabled as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
        if ret != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

/// Receives a UDP datagram and returns `(bytes_read, peer_addr, monotonic_instant)`.
/// Uses `recvmsg` + `SCM_TIMESTAMPNS` on Linux to eliminate user-space scheduling jitter.
pub async fn recv_with_timestamp(
    socket: &UdpSocket,
    buf: &mut [u8],
) -> io::Result<(usize, SocketAddr, Instant)> {
    #[cfg(target_os = "linux")]
    {
        socket
            .async_io(Interest::READABLE, || recvmsg_linux(socket.as_raw_fd(), buf))
            .await
    }

    #[cfg(not(target_os = "linux"))]
    {
        let (len, src) = socket.recv_from(buf).await?;
        Ok((len, src, Instant::now()))
    }
}

#[cfg(target_os = "linux")]
fn recvmsg_linux(fd: std::os::fd::RawFd, buf: &mut [u8]) -> io::Result<(usize, SocketAddr, Instant)> {
    let mut iov = libc::iovec {
        iov_base: buf.as_mut_ptr() as *mut libc::c_void,
        iov_len: buf.len(),
    };

    let mut addr_storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let mut cmsg_buf = [0u8; 128];

    let mut msghdr: libc::msghdr = unsafe { std::mem::zeroed() };
    msghdr.msg_name = &mut addr_storage as *mut _ as *mut libc::c_void;
    msghdr.msg_namelen = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    msghdr.msg_iov = &mut iov;
    msghdr.msg_iovlen = 1;
    msghdr.msg_control = cmsg_buf.as_mut_ptr() as *mut libc::c_void;
    msghdr.msg_controllen = cmsg_buf.len();

    let n = unsafe { libc::recvmsg(fd, &mut msghdr, 0) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }

    let now_instant = Instant::now();
    let now_sys = SystemTime::now();
    let mut recv_instant = now_instant;

    // Parse ancillary control messages for SCM_TIMESTAMPNS
    unsafe {
        let mut cmsg = libc::CMSG_FIRSTHDR(&msghdr);
        while !cmsg.is_null() {
            if (*cmsg).cmsg_level == libc::SOL_SOCKET && (*cmsg).cmsg_type == libc::SCM_TIMESTAMPNS
            {
                let ts_ptr = libc::CMSG_DATA(cmsg) as *const libc::timespec;
                let ts = *ts_ptr;
                if ts.tv_sec >= 0 && ts.tv_nsec >= 0 {
                    let kernel_wall = UNIX_EPOCH
                        + Duration::new(ts.tv_sec as u64, ts.tv_nsec as u32);
                    if let Ok(delta) = now_sys.duration_since(kernel_wall) {
                        // Reconstruct monotonic Instant at exact kernel packet arrival
                        if delta < Duration::from_secs(5) {
                            recv_instant = now_instant - delta;
                        }
                    }
                }
                break;
            }
            cmsg = libc::CMSG_NXTHDR(&msghdr, cmsg);
        }
    }

    let peer = sockaddr_to_std(&addr_storage, msghdr.msg_namelen)?;
    Ok((n as usize, peer, recv_instant))
}

#[cfg(target_os = "linux")]
fn sockaddr_to_std(
    storage: &libc::sockaddr_storage,
    len: libc::socklen_t,
) -> io::Result<SocketAddr> {
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};
    match storage.ss_family as libc::c_int {
        libc::AF_INET if (len as usize) >= std::mem::size_of::<libc::sockaddr_in>() => {
            let sin = unsafe { &*(storage as *const _ as *const libc::sockaddr_in) };
            let ip = Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr));
            let port = u16::from_be(sin.sin_port);
            Ok(SocketAddr::V4(SocketAddrV4::new(ip, port)))
        }
        libc::AF_INET6 if (len as usize) >= std::mem::size_of::<libc::sockaddr_in6>() => {
            let sin6 = unsafe { &*(storage as *const _ as *const libc::sockaddr_in6) };
            let ip = Ipv6Addr::from(sin6.sin6_addr.s6_addr);
            let port = u16::from_be(sin6.sin6_port);
            Ok(SocketAddr::V6(SocketAddrV6::new(
                ip,
                port,
                sin6.sin6_flowinfo,
                sin6.sin6_scope_id,
            )))
        }
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Unsupported socket address family",
        )),
    }
}
