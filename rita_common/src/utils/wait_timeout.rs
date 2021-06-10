//! Copied from here https://gist.github.com/alexcrichton/871b5bf058a2ce77ac4fedccf3fda9c9
//! turns out poll with timeout is quite complex. It has also been adapted by myself to use
//! notify without a really good understanding of the internals. The park/unpark version
//! paniced about every 24 hours this version is not correct I don't think for arbitrary futures
//! but is correct for our trivial case of a single future on a thread. We'll see how it holds up
use futures01::executor::Notify;
use futures01::executor::{self, Spawn};
use futures01::{Async, Future};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

pub enum WaitResult<F: Future> {
    Ok(F::Item),
    Err(F::Error),
    TimedOut(Spawn<F>),
}

pub fn wait_timeout<F: Future>(f: F, dur: Duration) -> WaitResult<F> {
    let start = Instant::now();
    let mut task = executor::spawn(f);
    let thread = Arc::new(ThreadNotify::new(thread::current()));

    loop {
        let cur = Instant::now();
        if cur >= (start + dur) {
            return WaitResult::TimedOut(task);
        }
        match task.poll_future_notify(&thread, 0) {
            Ok(Async::Ready(e)) => return WaitResult::Ok(e),
            Ok(Async::NotReady) => {}
            Err(e) => return WaitResult::Err(e),
        }

        thread.park(dur);
    }

    struct ThreadNotify {
        thread: thread::Thread,
        ready: AtomicBool,
    }

    impl ThreadNotify {
        fn new(thread: thread::Thread) -> ThreadNotify {
            ThreadNotify {
                thread,
                ready: AtomicBool::new(false),
            }
        }

        fn park(&self, dur: Duration) {
            if !self.ready.swap(false, Ordering::SeqCst) {
                thread::park_timeout(dur);
            }
        }
    }

    impl Notify for ThreadNotify {
        fn notify(&self, _id: usize) {
            self.ready.store(true, Ordering::SeqCst);
            self.thread.unpark()
        }
    }
}
