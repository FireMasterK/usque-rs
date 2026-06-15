use std::collections::VecDeque;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant as StdInstant};

use bytes::{Bytes, BytesMut};
use etherparse::{NetHeaders, PacketHeaders, PayloadSlice, TransportHeader};
use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{self, Device, Medium};
use smoltcp::socket::{tcp, udp};
use smoltcp::time::Instant;
use smoltcp::wire::{
    HardwareAddress, IpAddress, IpCidr, IpEndpoint, IpListenEndpoint, Ipv4Address, Ipv6Address,
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpListener;
use tokio::sync::{mpsc, Mutex, Notify};
use tokio::task::JoinHandle;

struct StackClock {
    start: StdInstant,
}

impl StackClock {
    fn new() -> Self {
        Self {
            start: StdInstant::now(),
        }
    }

    fn now(&self) -> Instant {
        Instant::from_millis(self.start.elapsed().as_millis() as i64)
    }
}

struct ChannelPhy {
    rx: VecDeque<Bytes>,
    tx: mpsc::UnboundedSender<Bytes>,
    recent_syns: Arc<std::sync::Mutex<VecDeque<SynFingerprint>>>,
    /// Reusable transmit scratch buffer. The smoltcp driver creates
    /// a new `TxToken` for every transmit but only one is alive at a
    /// time; this means the scratch buffer is safe to share. Holding
    /// it in an `Arc<std::sync::Mutex<_>>` inside the `TxToken` lets
    /// us *swap* it for a fresh `BytesMut` after each `consume()`
    /// while still letting the device live inside the
    /// `Send + Sync` `StackShared`.
    ///
    /// The scratch is recreated after every `consume()` rather than
    /// reused: `BytesMut::split_to(len).freeze()` advances the
    /// underlying `Arc<Vec<u8>>` pointer by `len` and `clear()` does
    /// not move it back, so a long-lived scratch would shrink its
    /// apparent capacity to zero after enough transmits (same class
    /// of bug as `TunnelSupervisor::run_pumps`'s `to_tunnel`).
    tx_scratch: Arc<std::sync::Mutex<BytesMut>>,
}

impl ChannelPhy {
    fn new(tx: mpsc::UnboundedSender<Bytes>) -> Self {
        Self {
            rx: VecDeque::new(),
            tx,
            recent_syns: Arc::new(std::sync::Mutex::new(VecDeque::with_capacity(16))),
            tx_scratch: Arc::new(std::sync::Mutex::new(BytesMut::new())),
        }
    }

    fn push_rx(&mut self, packet: Bytes) {
        // The RST-ACK normalization step needs an in-place mutation
        // of the buffer. We can't get a `&mut [u8]` from a `Bytes`
        // (the API is immutable), so we copy. The packet is small
        // (≤ MTU bytes) and this is one allocation per inbound
        // packet; the larger copy (DgramBuffer → Bytes) happens
        // upstream in the H3 receiver and is unavoidable with
        // datagram-socket 0.8. Future work: change the channel to
        // carry `BytesMut` directly so the copy can be elided.
        let mut owned = packet.to_vec();
        self.normalize_inbound_rst_ack(&mut owned);
        self.rx.push_back(Bytes::from(owned));
    }

    fn normalize_inbound_rst_ack(&self, packet: &mut [u8]) {
        let Ok(mut headers) = PacketHeaders::from_ip_slice(packet) else {
            return;
        };
        let tcp = match &mut headers.transport {
            Some(TransportHeader::Tcp(header)) => header,
            _ => return,
        };
        if !(tcp.rst
            && tcp.ack
            && !tcp.syn
            && !tcp.fin
            && !tcp.psh
            && !tcp.urg
            && !tcp.ece
            && !tcp.cwr
            && !tcp.ns)
        {
            return;
        }

        let (local_ip, remote_ip) = match &headers.net {
            Some(NetHeaders::Ipv4(ipv4, _)) => (
                IpAddr::V4(ipv4.destination.into()),
                IpAddr::V4(ipv4.source.into()),
            ),
            Some(NetHeaders::Ipv6(ipv6, _)) => (
                IpAddr::V6(ipv6.destination.into()),
                IpAddr::V6(ipv6.source.into()),
            ),
            Some(NetHeaders::Arp(_)) | None => return,
        };

        let mut recent_syns = self.recent_syns.lock().expect("recent_syns poisoned");
        let Some((idx, _syn)) = recent_syns.iter().enumerate().find(|(_, syn)| {
            syn.src == local_ip
                && syn.dst == remote_ip
                && syn.sport == tcp.destination_port
                && syn.dport == tcp.source_port
                && syn.seq == tcp.acknowledgment_number
        }) else {
            return;
        };

        tcp.acknowledgment_number = tcp.acknowledgment_number.wrapping_add(1);
        let payload = match headers.payload {
            PayloadSlice::Tcp(payload) => payload,
            _ => return,
        };

        let ip_header_len = match &mut headers.net {
            Some(NetHeaders::Ipv4(ipv4, _)) => {
                tcp.checksum = tcp.calc_checksum_ipv4(ipv4, payload).unwrap_or_default();
                ipv4.header_len()
            }
            Some(NetHeaders::Ipv6(ipv6, _)) => {
                tcp.checksum = tcp.calc_checksum_ipv6(ipv6, payload).unwrap_or_default();
                ipv6.header_len()
            }
            Some(NetHeaders::Arp(_)) | None => return,
        };

        let tcp_header_len = tcp.header_len();
        if packet.len() < ip_header_len + tcp_header_len {
            return;
        }

        match &mut headers.net {
            Some(NetHeaders::Ipv4(ipv4, _)) => {
                let mut ip_cursor = std::io::Cursor::new(&mut packet[..ip_header_len]);
                if ipv4.write(&mut ip_cursor).is_err() {
                    return;
                }
            }
            Some(NetHeaders::Ipv6(ipv6, _)) => {
                let mut ip_cursor = std::io::Cursor::new(&mut packet[..ip_header_len]);
                if ipv6.write(&mut ip_cursor).is_err() {
                    return;
                }
            }
            Some(NetHeaders::Arp(_)) | None => return,
        }

        let mut tcp_cursor =
            std::io::Cursor::new(&mut packet[ip_header_len..ip_header_len + tcp_header_len]);
        if tcp.write(&mut tcp_cursor).is_err() {
            return;
        }
        recent_syns.remove(idx);
    }
}

struct RxToken {
    buffer: Bytes,
}

impl phy::RxToken for RxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.buffer)
    }
}

struct TxToken {
    scratch: Arc<std::sync::Mutex<BytesMut>>,
    tx: mpsc::UnboundedSender<Bytes>,
    recent_syns: Arc<std::sync::Mutex<VecDeque<SynFingerprint>>>,
}

// SAFETY: smoltcp's driver creates at most one TxToken at a time and
// drops it before the next `transmit()` call, so the scratch mutex
// is only ever contended by the borrow inside `consume` itself.
unsafe impl Send for TxToken {}
unsafe impl Sync for TxToken {}

impl phy::TxToken for TxToken {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let result = {
            let mut scratch = self.scratch.lock().expect("tx_scratch poisoned");
            scratch.clear();
            if scratch.capacity() < len {
                scratch.reserve(len);
            }
            // `BytesMut::Deref` is `&[u8]` whose length is `len`, not
            // `capacity`. To get a `&mut [u8]` of `len` bytes we have to
            // use `spare_capacity_mut` (which exposes the tail of the
            // allocation up to `capacity - len`) and then commit it with
            // `set_len` after the closure returns.
            let spare = scratch.spare_capacity_mut();
            // Uninitialized memory is fine to expose to the closure
            // because smoltcp's contract is "fill it with a packet of
            // exactly `len` bytes".
            let slice: &mut [u8] =
                unsafe { std::slice::from_raw_parts_mut(spare.as_mut_ptr().cast::<u8>(), len) };
            let result = f(slice);
            // Commit the bytes the closure wrote.
            unsafe {
                scratch.set_len(len);
            }
            result
        };

        // Detach the just-written prefix into a `Bytes` for the
        // channel, then *swap the scratch* for a fresh one. We can't
        // just `clear()` and reuse: `BytesMut::split_to(len).freeze()`
        // advances the underlying `Arc<Vec<u8>>` pointer by `len`, so
        // a long-lived scratch would shrink to zero capacity and
        // smoltcp would start handing us zero-length transmit slices
        // (same class of bug as the supervisor's `to_tunnel`).
        //
        // Sizing: the new scratch starts at `max(prev_cap, len)`, so
        // the allocation grows monotonically to the largest packet
        // we have ever seen and then stops. The old `BytesMut` (whose
        // remaining tail capacity is `prev_cap - len` after the
        // `split_to`) is dropped here; the underlying `Vec<u8>` is
        // freed unless the frozen `Bytes` still holds a reference.
        let (used, new_cap) = {
            let mut scratch = self.scratch.lock().expect("tx_scratch poisoned");
            let prev_cap = scratch.capacity();
            let used = scratch.split_to(len).freeze();
            (used, prev_cap.max(len))
        };
        *self.scratch.lock().expect("tx_scratch poisoned") = BytesMut::with_capacity(new_cap);

        // Record SYN fingerprints for outbound SYNs.
        if let Ok(headers) = PacketHeaders::from_ip_slice(&used) {
            if let (Some(net), Some(TransportHeader::Tcp(tcp))) = (headers.net, headers.transport) {
                if tcp.syn && !tcp.ack && !tcp.rst {
                    let (src, dst) = match net {
                        NetHeaders::Ipv4(ipv4, _) => (
                            IpAddr::V4(ipv4.source.into()),
                            IpAddr::V4(ipv4.destination.into()),
                        ),
                        NetHeaders::Ipv6(ipv6, _) => (
                            IpAddr::V6(ipv6.source.into()),
                            IpAddr::V6(ipv6.destination.into()),
                        ),
                        NetHeaders::Arp(_) => return result,
                    };
                    let mut recent_syns = self.recent_syns.lock().expect("recent_syns poisoned");
                    if recent_syns.len() >= 16 {
                        recent_syns.pop_front();
                    }
                    recent_syns.push_back(SynFingerprint {
                        src,
                        dst,
                        sport: tcp.source_port,
                        dport: tcp.destination_port,
                        seq: tcp.sequence_number,
                    });
                }
            }
        }
        // Truncate the `Bytes` to the actual amount the closure
        // consumed; smoltcp may not have written all `len` bytes.
        let _ = self.tx.send(used);
        result
    }
}

impl Device for ChannelPhy {
    type RxToken<'a> = RxToken;
    type TxToken<'a> = TxToken;

    fn capabilities(&self) -> phy::DeviceCapabilities {
        let mut caps = phy::DeviceCapabilities::default();
        caps.max_transmission_unit = 1280;
        caps.medium = Medium::Ip;
        caps.checksum.ipv4 = phy::Checksum::Tx;
        caps.checksum.tcp = phy::Checksum::Tx;
        caps.checksum.udp = phy::Checksum::Tx;
        caps
    }

    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        self.rx.pop_front().map(|buffer| {
            (
                RxToken { buffer },
                TxToken {
                    scratch: Arc::clone(&self.tx_scratch),
                    tx: self.tx.clone(),
                    recent_syns: Arc::clone(&self.recent_syns),
                },
            )
        })
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        Some(TxToken {
            scratch: Arc::clone(&self.tx_scratch),
            tx: self.tx.clone(),
            recent_syns: Arc::clone(&self.recent_syns),
        })
    }
}

#[derive(Clone, Copy)]
struct SynFingerprint {
    src: IpAddr,
    dst: IpAddr,
    sport: u16,
    dport: u16,
    seq: u32,
}

struct StackInner {
    iface: Interface,
    device: ChannelPhy,
    sockets: SocketSet<'static>,
}

impl StackInner {
    fn poll(&mut self, clock: &StackClock) {
        for _ in 0..4 {
            self.iface
                .poll(clock.now(), &mut self.device, &mut self.sockets);
        }
    }
}

pub struct StackShared {
    inner: Mutex<StackInner>,
    notify: Notify,
    clock: StackClock,
}

pub struct VirtualTcpStream {
    handle: SocketHandle,
    shared: Arc<StackShared>,
}

impl AsyncRead for VirtualTcpStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let mut inner = match this.shared.inner.try_lock() {
            Ok(inner) => inner,
            Err(_) => {
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
        };

        let socket = inner.sockets.get_mut::<tcp::Socket>(this.handle);
        let unfilled = buf.initialize_unfilled();
        match socket.recv_slice(unfilled) {
            Ok(0) => match socket.state() {
                tcp::State::Closed | tcp::State::TimeWait => Poll::Ready(Ok(())),
                _ => {
                    inner.poll(&this.shared.clock);
                    drop(inner);
                    cx.waker().wake_by_ref();
                    Poll::Pending
                }
            },
            Ok(n) => {
                buf.advance(n);
                Poll::Ready(Ok(()))
            }
            Err(tcp::RecvError::InvalidState) => {
                Poll::Ready(Err(io::ErrorKind::NotConnected.into()))
            }
            Err(tcp::RecvError::Finished) => Poll::Ready(Ok(())),
        }
    }
}

impl AsyncWrite for VirtualTcpStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let mut inner = match this.shared.inner.try_lock() {
            Ok(inner) => inner,
            Err(_) => {
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
        };

        let socket = inner.sockets.get_mut::<tcp::Socket>(this.handle);
        match socket.send_slice(buf) {
            Ok(0) => {
                inner.poll(&this.shared.clock);
                drop(inner);
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            Ok(n) => {
                inner.poll(&this.shared.clock);
                this.shared.notify.notify_waiters();
                Poll::Ready(Ok(n))
            }
            Err(tcp::SendError::InvalidState) => {
                Poll::Ready(Err(io::ErrorKind::NotConnected.into()))
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if let Ok(mut inner) = this.shared.inner.try_lock() {
            inner.sockets.get_mut::<tcp::Socket>(this.handle).close();
            inner.poll(&this.shared.clock);
        }
        Poll::Ready(Ok(()))
    }
}

pub struct VirtualUdpSocket {
    handle: SocketHandle,
    shared: Arc<StackShared>,
}

impl VirtualUdpSocket {
    pub async fn send_to(&self, data: &[u8], dest: SocketAddr) -> io::Result<()> {
        let meta = udp::UdpMetadata::from(IpEndpoint {
            addr: IpAddress::from(dest.ip()),
            port: dest.port(),
        });

        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            {
                let mut inner = self.shared.inner.lock().await;
                let socket = inner.sockets.get_mut::<udp::Socket>(self.handle);
                match socket.send_slice(data, meta) {
                    Ok(()) => {
                        inner.poll(&self.shared.clock);
                        self.shared.notify.notify_waiters();
                        return Ok(());
                    }
                    Err(udp::SendError::BufferFull) => {}
                    Err(udp::SendError::Unaddressable) => {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "udp send failed",
                        ));
                    }
                }
            }

            if tokio::time::Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "udp send timed out",
                ));
            }
            let _ = tokio::time::timeout(Duration::from_millis(50), self.shared.notify.notified())
                .await;
        }
    }

    pub async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            {
                let mut inner = self.shared.inner.lock().await;
                let socket = inner.sockets.get_mut::<udp::Socket>(self.handle);
                match socket.recv_slice(buf) {
                    Ok((n, meta)) => {
                        let addr = SocketAddr::new(
                            ip_address_to_std(meta.endpoint.addr),
                            meta.endpoint.port,
                        );
                        return Ok((n, addr));
                    }
                    Err(udp::RecvError::Exhausted) => {
                        inner.poll(&self.shared.clock);
                    }
                    Err(udp::RecvError::Truncated) => {
                        return Err(io::Error::new(io::ErrorKind::InvalidData, "udp truncated"));
                    }
                }
            }

            if tokio::time::Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "udp recv timed out",
                ));
            }
            let _ = tokio::time::timeout(Duration::from_millis(50), self.shared.notify.notified())
                .await;
        }
    }
}

fn ip_address_to_std(addr: IpAddress) -> IpAddr {
    match addr {
        IpAddress::Ipv4(v4) => IpAddr::V4(v4),
        IpAddress::Ipv6(v6) => IpAddr::V6(v6),
    }
}

pub struct VirtualStack {
    shared: Arc<StackShared>,
    activity: Arc<Notify>,
    _poll_task: JoinHandle<()>,
}

impl VirtualStack {
    pub fn start(
        local_v4: Option<IpAddr>,
        local_v6: Option<IpAddr>,
        _mtu: usize,
        from_tunnel: mpsc::UnboundedReceiver<Bytes>,
        to_tunnel: mpsc::UnboundedSender<Bytes>,
        activity: Arc<Notify>,
    ) -> Self {
        let mut device = ChannelPhy::new(to_tunnel.clone());
        let mut config = Config::new(HardwareAddress::Ip);
        config.random_seed = rand::random();
        let clock = StackClock::new();
        let mut iface = Interface::new(config, &mut device, clock.now());

        iface.update_ip_addrs(|ip_addrs| {
            if let Some(v4) = local_v4 {
                let _ = ip_addrs.push(IpCidr::new(IpAddress::from(v4), 32));
            }
            if let Some(v6) = local_v6 {
                let _ = ip_addrs.push(IpCidr::new(IpAddress::from(v6), 128));
            }
        });

        if local_v4.is_some() {
            let _ = iface
                .routes_mut()
                .add_default_ipv4_route(Ipv4Address::UNSPECIFIED);
        }
        if local_v6.is_some() {
            let _ = iface
                .routes_mut()
                .add_default_ipv6_route(Ipv6Address::UNSPECIFIED);
        }

        let inner = StackInner {
            iface,
            device,
            sockets: SocketSet::new(vec![]),
        };

        let shared = Arc::new(StackShared {
            inner: Mutex::new(inner),
            notify: Notify::new(),
            clock,
        });

        let poll_shared = Arc::clone(&shared);
        let poll_task = tokio::spawn(async move {
            run_poll_loop(from_tunnel, poll_shared).await;
        });

        Self {
            shared,
            activity,
            _poll_task: poll_task,
        }
    }

    pub fn wake(&self) {
        self.activity.notify_one();
    }

    pub async fn bind_udp(&self) -> io::Result<VirtualUdpSocket> {
        self.wake();

        let handle = {
            let mut inner = self.shared.inner.lock().await;
            let rx_buffer =
                udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 4], vec![0u8; 65535]);
            let tx_buffer =
                udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 4], vec![0u8; 65535]);
            let mut socket = udp::Socket::new(rx_buffer, tx_buffer);
            let local_port = 49152 + rand::random::<u16>() % 16384;
            socket
                .bind(IpListenEndpoint {
                    addr: None,
                    port: local_port,
                })
                .map_err(|_| io::Error::new(io::ErrorKind::AddrInUse, "udp bind failed"))?;
            inner.sockets.add(socket)
        };

        Ok(VirtualUdpSocket {
            handle,
            shared: Arc::clone(&self.shared),
        })
    }

    pub async fn dial_tcp(&self, addr: SocketAddr) -> io::Result<VirtualTcpStream> {
        self.wake();

        let handle = {
            let mut inner = self.shared.inner.lock().await;
            let rx_buffer = tcp::SocketBuffer::new(vec![0; 65535]);
            let tx_buffer = tcp::SocketBuffer::new(vec![0; 65535]);
            let mut socket = tcp::Socket::new(rx_buffer, tx_buffer);
            let remote_ip = IpAddress::from(addr.ip());
            let local_port = 49152 + rand::random::<u16>() % 16384;
            socket
                .connect(inner.iface.context(), (remote_ip, addr.port()), local_port)
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "tcp connect failed"))?;
            inner.sockets.add(socket)
        };

        let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
        loop {
            {
                let mut inner = self.shared.inner.lock().await;
                inner.poll(&self.shared.clock);
                let state = inner.sockets.get::<tcp::Socket>(handle).state();
                match state {
                    tcp::State::Established => {
                        return Ok(VirtualTcpStream {
                            handle,
                            shared: Arc::clone(&self.shared),
                        });
                    }
                    tcp::State::Closed | tcp::State::TimeWait => {
                        return Err(io::Error::new(
                            io::ErrorKind::ConnectionRefused,
                            "tcp connection closed",
                        ));
                    }
                    _ => {}
                }
            }

            if tokio::time::Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "tcp connect timed out",
                ));
            }

            let _ = tokio::time::timeout(Duration::from_millis(50), self.shared.notify.notified())
                .await;
        }
    }

    pub async fn listen_tcp(&self, addr: SocketAddr) -> io::Result<TcpListener> {
        self.wake();
        TcpListener::bind(addr).await
    }
}

async fn run_poll_loop(mut from_tunnel: mpsc::UnboundedReceiver<Bytes>, shared: Arc<StackShared>) {
    loop {
        tokio::select! {
            packet = from_tunnel.recv() => {
                let Some(packet) = packet else { break };
                let mut inner = shared.inner.lock().await;
                inner.device.push_rx(packet);
                inner.poll(&shared.clock);
                shared.notify.notify_waiters();
            }
            _ = tokio::time::sleep(Duration::from_millis(10)) => {
                let mut inner = shared.inner.lock().await;
                inner.poll(&shared.clock);
                shared.notify.notify_waiters();
            }
        }
    }
}
