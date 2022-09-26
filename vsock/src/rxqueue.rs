use super::rxops::RxOps;

#[derive(Debug, Eq, PartialEq)]
pub struct RxQueue {
    /// Bitmap of rx operations.
    queue: u8,
}

impl RxQueue {
    /// New instance of RxQueue.
    pub fn new() -> Self {
        RxQueue { queue: 0_u8 }
    }

    /// Enqueue a new rx operation into the queue.
    pub fn enqueue(&mut self, op: RxOps) {
        self.queue |= op.bitmask();
    }

    /// Dequeue an rx operation from the queue.
    pub fn dequeue(&mut self) -> Option<RxOps> {
        match self.peek() {
            Some(req) => {
                self.queue &= !req.bitmask();
                Some(req)
            }
            None => None,
        }
    }

    /// Peek into the queue to check if it contains an rx operation.
    pub fn peek(&self) -> Option<RxOps> {
        if self.contains(RxOps::Request.bitmask()) {
            return Some(RxOps::Request);
        }
        if self.contains(RxOps::Rw.bitmask()) {
            return Some(RxOps::Rw);
        }
        if self.contains(RxOps::Response.bitmask()) {
            return Some(RxOps::Response);
        }
        if self.contains(RxOps::CreditUpdate.bitmask()) {
            return Some(RxOps::CreditUpdate);
        }
        if self.contains(RxOps::Reset.bitmask()) {
            Some(RxOps::Reset)
        } else {
            None
        }
    }

    /// Check if the queue contains a particular rx operation.
    pub fn contains(&self, op: u8) -> bool {
        (self.queue & op) != 0
    }

    /// Check if there are any pending rx operations in the queue.
    pub fn pending_rx(&self) -> bool {
        self.queue != 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_contains() {
        let mut rxqueue = RxQueue::new();
        rxqueue.queue = 31;

        assert!(rxqueue.contains(RxOps::Request.bitmask()));
        assert!(rxqueue.contains(RxOps::Rw.bitmask()));
        assert!(rxqueue.contains(RxOps::Response.bitmask()));
        assert!(rxqueue.contains(RxOps::CreditUpdate.bitmask()));
        assert!(rxqueue.contains(RxOps::Reset.bitmask()));

        rxqueue.queue = 0;
        assert!(!rxqueue.contains(RxOps::Request.bitmask()));
        assert!(!rxqueue.contains(RxOps::Rw.bitmask()));
        assert!(!rxqueue.contains(RxOps::Response.bitmask()));
        assert!(!rxqueue.contains(RxOps::CreditUpdate.bitmask()));
        assert!(!rxqueue.contains(RxOps::Reset.bitmask()));
    }

    #[test]
    fn test_enqueue() {
        let mut rxqueue = RxQueue::new();

        rxqueue.enqueue(RxOps::Request);
        assert!(rxqueue.contains(RxOps::Request.bitmask()));

        rxqueue.enqueue(RxOps::Rw);
        assert!(rxqueue.contains(RxOps::Rw.bitmask()));

        rxqueue.enqueue(RxOps::Response);
        assert!(rxqueue.contains(RxOps::Response.bitmask()));

        rxqueue.enqueue(RxOps::CreditUpdate);
        assert!(rxqueue.contains(RxOps::CreditUpdate.bitmask()));

        rxqueue.enqueue(RxOps::Reset);
        assert!(rxqueue.contains(RxOps::Reset.bitmask()));
    }

    #[test]
    fn test_peek() {
        let mut rxqueue = RxQueue::new();

        rxqueue.queue = 31;
        assert_eq!(rxqueue.peek(), Some(RxOps::Request));

        rxqueue.queue = 30;
        assert_eq!(rxqueue.peek(), Some(RxOps::Rw));

        rxqueue.queue = 28;
        assert_eq!(rxqueue.peek(), Some(RxOps::Response));

        rxqueue.queue = 24;
        assert_eq!(rxqueue.peek(), Some(RxOps::CreditUpdate));

        rxqueue.queue = 16;
        assert_eq!(rxqueue.peek(), Some(RxOps::Reset));
    }

    #[test]
    fn test_dequeue() {
        let mut rxqueue = RxQueue::new();
        rxqueue.queue = 31;

        assert_eq!(rxqueue.dequeue(), Some(RxOps::Request));
        assert!(!rxqueue.contains(RxOps::Request.bitmask()));

        assert_eq!(rxqueue.dequeue(), Some(RxOps::Rw));
        assert!(!rxqueue.contains(RxOps::Rw.bitmask()));

        assert_eq!(rxqueue.dequeue(), Some(RxOps::Response));
        assert!(!rxqueue.contains(RxOps::Response.bitmask()));

        assert_eq!(rxqueue.dequeue(), Some(RxOps::CreditUpdate));
        assert!(!rxqueue.contains(RxOps::CreditUpdate.bitmask()));

        assert_eq!(rxqueue.dequeue(), Some(RxOps::Reset));
        assert!(!rxqueue.contains(RxOps::Reset.bitmask()));
    }

    #[test]
    fn test_pending_rx() {
        let mut rxqueue = RxQueue::new();
        assert!(!rxqueue.pending_rx());

        rxqueue.queue = 1;
        assert!(rxqueue.pending_rx());
    }
}
