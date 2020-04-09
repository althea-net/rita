/// Copied from here https://gist.github.com/alexcrichton/871b5bf058a2ce77ac4fedccf3fda9c9
/// turns out poll with timeout is quite complex, turned off warnings becuase we've already
/// scoped these as futures01
use futures01::executor::{self, Spawn};
#[allow(deprecated)]
use futures01::task::Unpark;
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
    let now = Instant::now();
    let mut task = executor::spawn(f);
    let thread = Arc::new(ThreadUnpark::new(thread::current()));

    loop {
        let cur = Instant::now();
        if cur >= now + dur {
            return WaitResult::TimedOut(task);
        }
        #[allow(deprecated)]
        match task.poll_future(thread.clone()) {
            Ok(Async::Ready(e)) => return WaitResult::Ok(e),
            Ok(Async::NotReady) => {}
            Err(e) => return WaitResult::Err(e),
        }

        thread.park(now + dur - cur);
    }

    struct ThreadUnpark {
        thread: thread::Thread,
        ready: AtomicBool,
    }

    impl ThreadUnpark {
        fn new(thread: thread::Thread) -> ThreadUnpark {
            ThreadUnpark {
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

    #[allow(deprecated)]
    impl Unpark for ThreadUnpark {
        fn unpark(&self) {
            self.ready.store(true, Ordering::SeqCst);
            self.thread.unpark()
        }
    }
}
