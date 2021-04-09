/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use core::ops::{Deref, DerefMut};
use core::pin::Pin;
use core::task::{Context, Poll};

use hyper::client::connect::{Connection, Connected};

// TLS protocol reference from RFC 8446

// a magic that tells you if a tls record is client hello (2 comparisons!)
fn is_hello(data: &[u8]) -> bool {
    // type == handshake && msg_type == client_hello
    data[0] == 0x16 && data[5] == 0x01
}

// find where to cut
fn find_sni(data: &[u8]) -> Option<usize> {
    // uint16 ProtocolVersion;
    // opaque Random[32];
    //
    // uint8 CipherSuite[2];    /* Cryptographic suite selector */
    //
    // struct {
    //     ProtocolVersion legacy_version = 0x0303;    /* TLS v1.2 */
    //     Random random;
    //     opaque legacy_session_id<0..32>;
    //     CipherSuite cipher_suites<2..2^16-2>;
    //     opaque legacy_compression_methods<1..2^8-1>;
    //     Extension extensions<8..2^16-1>;
    // } ClientHello;

    // skip all headers we're not interested in

    fn u16_at(data: &[u8], at: usize) -> u16 {
        let arr = [data[at], data[at + 1]];
        u16::from_be_bytes(arr)
    }

    // skip up to `random`
    let mut offset = 5 + 4 + 2 + 32;

    // legacy_session_id
    offset += 1 + data[offset] as usize;

    // cipher_suites
    offset += 2 + u16_at(data, offset) as usize;

    // legacy_compression_methods
    offset += 1 + data[offset] as usize;

    // extensions
    let ext_end = offset + 2 + u16_at(data, offset) as usize;

    offset += 2;
    while offset < ext_end {
        // extension_type == server_name
        if u16_at(data, offset) == 0u16 {
            offset += 2;
            let sni_len = u16_at(data, offset) as usize;

            return Some(offset + sni_len / 2);
        } else {
            offset += 2;
            offset += 2 + u16_at(data, offset) as usize;
        }
    }

    None
}

// split a tls record half into fragments.
// if multiple tls records of same type are send, the server should
// identify them as 'fragmented' and reassemble them up to a single record.
fn fragmentate(data: &[u8]) -> (Vec<u8>, Vec<u8>) {
    // struct {
    //     ContentType type;
    //     ProtocolVersion legacy_record_version;
    //     uint16 length;
    //     opaque fragment[TLSPlaintext.length];
    // } TLSPlaintext; (Vec<u8>, Vec<u8>) {

    // split the payload into half
    let mid = find_sni(data).unwrap_or(5 + (data.len() - 5) / 2);
    let (left, right) = data.split_at(mid);

    // we'll keep `type` and `legacy_record_version` as same as original,
    // but `length` will be changed to the chunk's size.

    // left contains header; payload length is len - 5
    let size_bytes = ((left.len() - 5) as u16).to_be_bytes();
    let mut first = left.to_vec();
    first[3] = size_bytes[0];
    first[4] = size_bytes[1];

    let size_bytes = (right.len() as u16).to_be_bytes();
    let mut second = vec![
        data[0],
        data[1], data[2], 
        size_bytes[0], size_bytes[1]
    ];

    second.extend_from_slice(right);

    (first, second)
}

#[derive(Debug)]
enum DetourState {
    // not sending a fragment; passthrough
    Normal,
    // currently sending fragments
    SendFirst(Vec<u8>, Vec<u8>), // first, second
    SendSecond(Vec<u8>, usize),  // second, first_written
}

/// a thin wrapper to bypass DPI(deep packet inspectation)
#[derive(Debug)]
pub struct Detour<T: AsyncWrite> {
    sock: T,
    state: DetourState,
}

impl<T: AsyncWrite> Detour<T> {
    /// make a new detour from a stream
    pub fn new(sock: T) -> Self {
        Self {
            sock,
            state: DetourState::Normal,
        }
    }

    // consume a pin to self into a pin to sock
    fn sock(self: Pin<&mut Self>) -> Pin<&mut T> {
        unsafe { Pin::new_unchecked(&mut self.get_unchecked_mut().sock) }
    }

    /// consume self, return inner socket
    pub fn into_inner(self) -> T {
        self.sock
    }
}

// to access internal socket
impl<T: AsyncWrite> Deref for Detour<T> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        &self.sock
    }
}

impl<T: AsyncWrite> DerefMut for Detour<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.sock
    }
}

impl<T: AsyncWrite + Connection> Connection for Detour<T> {
    fn connected(&self) -> Connected {
        self.sock.connected()
    }
}

// handy boilerplate for generics which require both read and write
impl<T: AsyncRead + AsyncWrite> AsyncRead for Detour<T> {
    fn poll_read(
        self: Pin<&mut Self>, 
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>
    ) -> Poll<tokio::io::Result<()>> {
        self.sock().poll_read(cx, buf)
    }
}

impl<T: AsyncWrite> AsyncWrite for Detour<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8]
    ) -> Poll<tokio::io::Result<usize>> {
        // passthrough if the message isn't client hello (need not be fragmented)
        if !is_hello(buf) {
            return self.sock().poll_write(cx, buf);
        }

        // consume the pin out; we must not move self and its member from now on
        let _self = unsafe { self.get_unchecked_mut() };

        match &_self.state {
            // this call is the first time to be polled to send this buf
            DetourState::Normal => {
                // the fragments will be send in the next poll
                let (first, second) = fragmentate(buf);
                _self.state = DetourState::SendFirst(first, second);
                Poll::Pending
            },
            DetourState::SendFirst(first, second) => {
                // both ref_self and ref_self.sock won't move so it's safe to pin
                let sock = unsafe { Pin::new_unchecked(&mut _self.sock) };

                match sock.poll_write(cx, first) {
                    // the second fragment is left
                    Poll::Ready(Ok(n)) => {
                        // can't move out of second so it's the only option...
                        let second = second.clone();
                        _self.state = DetourState::SendSecond(second, n);
                        cx.waker().wake_by_ref();
                        Poll::Pending
                    },
                    others => others
                }
            }
            DetourState::SendSecond(second, written) => {
                let sock = unsafe { Pin::new_unchecked(&mut _self.sock) };

                match sock.poll_write(cx, &second) {
                    // all fragments are send; go back to Normal
                    Poll::Ready(Ok(n)) => {
                        let res = written + n;
                        _self.state = DetourState::Normal;
                        Poll::Ready(Ok(res))
                    },
                    others => others
                }
            },
        }
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<tokio::io::Result<()>> {
        self.sock().poll_flush(cx)
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<tokio::io::Result<()>> {
        self.sock().poll_shutdown(cx)
    }
}
