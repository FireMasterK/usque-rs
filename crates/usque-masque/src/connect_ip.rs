use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use tokio::sync::{mpsc, Mutex, Notify};
use tokio_quiche::ClientH3Controller;
use tokio_quiche::QuicConnection;

use crate::session::{PacketSession, SessionError};

pub(crate) struct H3ConnectionGuard {
    pub _conn: QuicConnection,
    pub _controller: ClientH3Controller,
}

pub(crate) enum Transport {
    H3Quiche {
        out: mpsc::Sender<Bytes>,
        _guard: Arc<H3ConnectionGuard>,
    },
    H2 {
        out: mpsc::Sender<Bytes>,
    },
}

pub struct ConnectIpSession {
    incoming: Arc<Mutex<VecDeque<Vec<u8>>>>,
    notify: Arc<Notify>,
    transport: Transport,
    closed: Arc<AtomicBool>,
}

impl ConnectIpSession {
    pub(crate) fn new(transport: Transport) -> Self {
        Self {
            incoming: Arc::new(Mutex::new(VecDeque::new())),
            notify: Arc::new(Notify::new()),
            transport,
            closed: Arc::new(AtomicBool::new(false)),
        }
    }

    pub(crate) fn from_parts(
        incoming: Arc<Mutex<VecDeque<Vec<u8>>>>,
        notify: Arc<Notify>,
        transport: Transport,
        closed: Arc<AtomicBool>,
    ) -> Self {
        Self {
            incoming,
            notify,
            transport,
            closed,
        }
    }

    pub fn incoming_queue(&self) -> Arc<Mutex<VecDeque<Vec<u8>>>> {
        Arc::clone(&self.incoming)
    }

    pub fn notify(&self) -> Arc<Notify> {
        Arc::clone(&self.notify)
    }

    pub fn closed_flag(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.closed)
    }
}

#[async_trait]
impl PacketSession for ConnectIpSession {
    async fn read_packet(&mut self, buf: &mut [u8]) -> Result<usize, SessionError> {
        loop {
            if let Some(packet) = self.incoming.lock().await.pop_front() {
                let n = packet.len().min(buf.len());
                buf[..n].copy_from_slice(&packet[..n]);
                return Ok(n);
            }
            if self.closed.load(Ordering::Relaxed) {
                return Err(SessionError::Closed);
            }
            self.notify.notified().await;
        }
    }

    async fn write_packet(&mut self, packet: &[u8]) -> Result<Option<Vec<u8>>, SessionError> {
        let mut packet = packet.to_vec();
        match &self.transport {
            Transport::H3Quiche { out, .. } => {
                let payload = crate::datagram::encode_h3_datagram_payload(&mut packet)
                    .map_err(SessionError::Other)?;
                out.send(payload).await.map_err(|_| SessionError::Closed)?;
            }
            Transport::H2 { out } => {
                let payload = crate::datagram::encode_h2_datagram_capsule(&mut packet)
                    .map_err(SessionError::Other)?;
                out.send(payload).await.map_err(|_| SessionError::Closed)?;
            }
        }
        Ok(None)
    }

    async fn close(&mut self) -> Result<(), SessionError> {
        self.closed.store(true, Ordering::Relaxed);
        self.notify.notify_waiters();
        Ok(())
    }
}
