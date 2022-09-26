use super::vhu_vsock::{Error, Result, CONN_TX_BUF_SIZE};
use std::{io::Write, num::Wrapping};
use vm_memory::{bitmap::BitmapSlice, VolatileSlice};

#[derive(Debug)]
pub struct LocalTxBuf {
    /// Buffer holding data to be forwarded to a host-side application
    buf: Vec<u8>,
    /// Index into buffer from which data can be consumed from the buffer
    head: Wrapping<u32>,
    /// Index into buffer from which data can be added to the buffer
    tail: Wrapping<u32>,
}

impl LocalTxBuf {
    /// Create a new instance of LocalTxBuf.
    pub fn new() -> Self {
        Self {
            buf: vec![0; CONN_TX_BUF_SIZE as usize],
            head: Wrapping(0),
            tail: Wrapping(0),
        }
    }

    /// Check if the buf is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Add new data to the tx buffer, push all or none.
    /// Returns LocalTxBufFull error if space not sufficient.
    pub(crate) fn push<B: BitmapSlice>(&mut self, data_buf: &VolatileSlice<B>) -> Result<()> {
        if CONN_TX_BUF_SIZE as usize - self.len() < data_buf.len() {
            // Tx buffer is full
            return Err(Error::LocalTxBufFull);
        }

        // Get index into buffer at which data can be inserted
        let tail_idx = self.tail.0 as usize % CONN_TX_BUF_SIZE as usize;

        // Check if we can fit the data buffer between head and end of buffer
        let len = std::cmp::min(CONN_TX_BUF_SIZE as usize - tail_idx, data_buf.len());
        let txbuf = &mut self.buf[tail_idx..tail_idx + len];
        data_buf.copy_to(txbuf);

        // Check if there is more data to be wrapped around
        if len < data_buf.len() {
            let remain_txbuf = &mut self.buf[..(data_buf.len() - len)];
            data_buf.copy_to(remain_txbuf);
        }

        // Increment tail by the amount of data that has been added to the buffer
        self.tail += Wrapping(data_buf.len() as u32);

        Ok(())
    }

    /// Flush buf data to stream.
    pub(crate) fn flush_to<S: Write>(&mut self, stream: &mut S) -> Result<usize> {
        if self.is_empty() {
            // No data to be flushed
            return Ok(0);
        }

        // Get index into buffer from which data can be read
        let head_idx = self.head.0 as usize % CONN_TX_BUF_SIZE as usize;

        // First write from head to end of buffer
        let len = std::cmp::min(CONN_TX_BUF_SIZE as usize - head_idx, self.len());
        let written = stream
            .write(&self.buf[head_idx..(head_idx + len)])
            .map_err(Error::LocalTxBufFlush)?;

        // Increment head  by amount of data that has been flushed to the stream
        self.head += Wrapping(written as u32);

        // If written length is less than the expected length we can try again in the future
        if written < len {
            return Ok(written);
        }

        // The head index has wrapped around the end of the buffer, we call self again
        Ok(written + self.flush_to(stream).unwrap_or(0))
    }

    /// Return amount of data in the buffer.
    fn len(&self) -> usize {
        (self.tail - self.head).0 as usize
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_txbuf_len() {
        let mut loc_tx_buf = LocalTxBuf::new();

        // Zero length tx buf
        assert_eq!(loc_tx_buf.len(), 0);

        // finite length tx buf
        loc_tx_buf.head = Wrapping(0);
        loc_tx_buf.tail = Wrapping(CONN_TX_BUF_SIZE);
        assert_eq!(loc_tx_buf.len(), CONN_TX_BUF_SIZE as usize);

        loc_tx_buf.tail = Wrapping(CONN_TX_BUF_SIZE / 2);
        assert_eq!(loc_tx_buf.len(), (CONN_TX_BUF_SIZE / 2) as usize);

        loc_tx_buf.head = Wrapping(256);
        assert_eq!(loc_tx_buf.len(), 32512);
    }

    #[test]
    fn test_txbuf_is_empty() {
        let mut loc_tx_buf = LocalTxBuf::new();

        // empty tx buffer
        assert!(loc_tx_buf.is_empty());

        // non empty tx buffer
        loc_tx_buf.tail = Wrapping(CONN_TX_BUF_SIZE);
        assert!(!loc_tx_buf.is_empty());
    }

    #[test]
    fn test_txbuf_push() {
        let mut loc_tx_buf = LocalTxBuf::new();
        let mut buf = [0; CONN_TX_BUF_SIZE as usize];
        let data = unsafe { VolatileSlice::new(buf.as_mut_ptr(), buf.len()) };

        // push data into empty tx buffer
        let res_push = loc_tx_buf.push(&data);
        assert!(res_push.is_ok());
        assert_eq!(loc_tx_buf.head, Wrapping(0));
        assert_eq!(loc_tx_buf.tail, Wrapping(CONN_TX_BUF_SIZE));

        // push data into full tx buffer
        let res_push = loc_tx_buf.push(&data);
        assert!(res_push.is_err());

        // head and tail wrap at full
        loc_tx_buf.head = Wrapping(CONN_TX_BUF_SIZE);
        let res_push = loc_tx_buf.push(&data);
        assert!(res_push.is_ok());
        assert_eq!(loc_tx_buf.tail, Wrapping(CONN_TX_BUF_SIZE * 2));

        // only tail wraps at full
        let mut buf = vec![1; 4];
        let data = unsafe { VolatileSlice::new(buf.as_mut_ptr(), buf.len()) };
        let mut cmp_data = vec![1; 4];
        cmp_data.append(&mut vec![0; (CONN_TX_BUF_SIZE - 4) as usize]);
        loc_tx_buf.head = Wrapping(4);
        loc_tx_buf.tail = Wrapping(CONN_TX_BUF_SIZE);
        let res_push = loc_tx_buf.push(&data);
        assert!(res_push.is_ok());
        assert_eq!(loc_tx_buf.head, Wrapping(4));
        assert_eq!(loc_tx_buf.tail, Wrapping(CONN_TX_BUF_SIZE + 4));
        assert_eq!(loc_tx_buf.buf, cmp_data);
    }

    #[test]
    fn test_txbuf_flush_to() {
        let mut loc_tx_buf = LocalTxBuf::new();

        // data to be flushed
        let mut buf = vec![1; CONN_TX_BUF_SIZE as usize];
        let data = unsafe { VolatileSlice::new(buf.as_mut_ptr(), buf.len()) };

        // target to which data is flushed
        let mut cmp_vec = Vec::with_capacity(data.len());

        // flush no data
        let res_flush = loc_tx_buf.flush_to(&mut cmp_vec);
        assert!(res_flush.is_ok());
        assert_eq!(res_flush.unwrap(), 0);

        // flush data of CONN_TX_BUF_SIZE amount
        let res_push = loc_tx_buf.push(&data);
        assert!(res_push.is_ok());
        let res_flush = loc_tx_buf.flush_to(&mut cmp_vec);
        if let Ok(n) = res_flush {
            assert_eq!(loc_tx_buf.head, Wrapping(n as u32));
            assert_eq!(loc_tx_buf.tail, Wrapping(CONN_TX_BUF_SIZE));
            assert_eq!(n, cmp_vec.len());
            assert_eq!(cmp_vec, buf[..n]);
        }

        // wrapping head flush
        let mut buf = vec![0; (CONN_TX_BUF_SIZE / 2) as usize];
        buf.append(&mut vec![1; (CONN_TX_BUF_SIZE / 2) as usize]);
        let data = unsafe { VolatileSlice::new(buf.as_mut_ptr(), buf.len()) };

        loc_tx_buf.head = Wrapping(0);
        loc_tx_buf.tail = Wrapping(0);
        let res_push = loc_tx_buf.push(&data);
        assert!(res_push.is_ok());
        cmp_vec.clear();
        loc_tx_buf.head = Wrapping(CONN_TX_BUF_SIZE / 2);
        loc_tx_buf.tail = Wrapping(CONN_TX_BUF_SIZE + (CONN_TX_BUF_SIZE / 2));
        let res_flush = loc_tx_buf.flush_to(&mut cmp_vec);
        if let Ok(n) = res_flush {
            assert_eq!(
                loc_tx_buf.head,
                Wrapping(CONN_TX_BUF_SIZE + (CONN_TX_BUF_SIZE / 2))
            );
            assert_eq!(
                loc_tx_buf.tail,
                Wrapping(CONN_TX_BUF_SIZE + (CONN_TX_BUF_SIZE / 2))
            );
            assert_eq!(n, cmp_vec.len());
            let mut data = vec![1; (CONN_TX_BUF_SIZE / 2) as usize];
            data.append(&mut vec![0; (CONN_TX_BUF_SIZE / 2) as usize]);
            assert_eq!(cmp_vec, data[..n]);
        }
    }
}
