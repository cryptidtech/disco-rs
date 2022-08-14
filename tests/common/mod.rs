#![allow(dead_code)]
use crate::xeddsa::DiscoSession;
use disco_rs::session::MSG_MAX_LEN;

pub fn send_and_recv(sender: &mut DiscoSession, recver: &mut DiscoSession) {
    let mut pt = [0u8; MSG_MAX_LEN];
    let mut ct = [0u8; MSG_MAX_LEN];

    println!("\n\nSEND HANDSHAKE");
    println!("PT[{}..{}]: {:02x?}", 0, 0, &pt[0..0]);

    // send
    let end = sender
        .send_message(&[], &mut ct)
        .expect("failed to send message");

    println!("CT[{}..{}]: {:02x?}", 0, end, &ct[0..end]);

    // recv
    let (i, o) = recver
        .recv_message(&ct[0..end], &mut pt)
        .expect("failed to recv message");

    assert_eq!(i, end);

    println!("\n\nRECV HANDSHAKE");
    println!("PT[{}..{}]: {:02x?}", 0, o, &pt[0..o]);
}

pub fn send(
    session: &mut DiscoSession,
    order: &Vec<usize>,
    pt: &[u8],
    pti: &Vec<(usize, usize)>,
    ct: &mut [u8],
    cti: &mut Vec<(usize, usize)>,
    keyed_after: usize,
) {
    let mut out_start;
    let mut out_end = 0;
    let mut count = 0;
    for i in order {
        // keyed_after specifies how many messages must be sent before the session becomes
        // keyed (i.e. encrypted).
        if count >= keyed_after {
            assert!(session.is_keyed());
        } else {
            assert!(!session.is_keyed());
        }

        // get the start and end indexes of the plaintext message to send
        let (start, end) = pti[*i];

        println!("\n\nSEND {}", *i);
        println!("PT[{}..{}]: {:02x?}", start, end, &pt[start..end]);

        // send
        out_start = out_end;
        out_end += session
            .send_message(&pt[start..end], &mut ct[out_start..])
            .expect("failed to send message");

        // record the start and end indexes of the ciphertext messages
        cti.push((out_start, out_end));

        println!(
            "CT[{}..{}]: {:02x?}",
            out_start,
            out_end,
            &ct[out_start..out_end]
        );

        count += 1;
    }
}

pub fn recv(
    session: &mut DiscoSession,
    order: &Vec<usize>,
    pt: &mut [u8],
    ct: &[u8],
    cti: &Vec<(usize, usize)>,
    keyed_after: usize,
) {
    let mut out_start;
    let mut out_end = 0;
    let mut count = 0;
    for i in order {
        // keyed_after specifies how many message must be received before the session becomes
        // keyed (i.e. encrypted).
        if count >= keyed_after {
            assert!(session.is_keyed());
        } else {
            assert!(!session.is_keyed());
        }

        // get the start and end indexes of the ciphertext message to recv
        let (start, end) = cti[*i];

        println!("\n\nRECV {}", *i);
        println!("CT[{}..{}]: {:02x?}", start, end, &ct[start..end]);

        // recv
        out_start = out_end;
        let (i, o) = session
            .recv_message(&ct[start..end], &mut pt[out_start..])
            .expect("failed to recv message");
        out_end += o;

        // make sure we processed the full ciphertext
        assert_eq!(i, end - start);

        println!(
            "PT[{}..{}]: {:02x?}",
            out_start,
            out_end,
            &pt[out_start..out_end]
        );

        count += 1;
    }
}
