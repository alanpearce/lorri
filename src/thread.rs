//! A thread pool for panicking immediately after any monitored threads
//! panic.
//!
//! The key implementation detail is each thread spawned gets a
//! DeathCertificate which sends a message on Drop. This allows us to
//! join a thread once we know it has completed execution, meaning
//! we don't block joining one thread while another thread has panicked
//! already.

use chan::Receiver;
use crossbeam_channel as chan;
use slog::debug;
use std::any::Any;
use std::collections::HashMap;
use std::thread;
use std::thread::ThreadId;

use crate::Never;

struct Thread {
    name: String,
    join_handle: thread::JoinHandle<()>,
}

/// This thread died, and why.
pub struct Dead<Err> {
    /// id of the thread
    pub thread_id: ThreadId,
    /// cause of death
    pub cause: Cause<Err>,
}

/// Cause of death
pub enum Cause<Err> {
    /// Natural causes
    Natural(Result<(), Err>),
    /// Thread paniced and then died
    Paniced(Box<dyn Any + Send>),
}

/// A thread pool for joining many threads at once, panicking
/// if any of the threads panicked.
pub struct Pool<Err> {
    threads: HashMap<ThreadId, Thread>,
    tx: chan::Sender<Dead<Err>>,
    rx: chan::Receiver<Dead<Err>>,
    logger: slog::Logger,
}

impl<Err> Pool<Err> {
    /// Construct a new thread pool.
    pub fn new(logger: slog::Logger) -> Pool<Err> {
        let (tx, rx) = chan::unbounded();
        Pool {
            threads: HashMap::new(),
            tx,
            rx,
            logger,
        }
    }

    /// Spawn a sub-thread which is joined at the same time as all the
    /// remaining threads.
    pub fn spawn<N, F>(&mut self, name: N, f: F) -> Result<(), std::io::Error>
    where
        N: Into<String>,
        F: FnOnce() -> Result<(), Err>,
        F: std::panic::UnwindSafe,
        F: Send + 'static,
        Err: Send + 'static,
    {
        let name = name.into();
        let name2 = name.clone();
        let builder = thread::Builder::new().name(name.clone());
        let logger = self.logger.clone();

        let tx = self.tx.clone();
        let handle = builder.spawn(move || {
            let thread_id = thread::current().id();
            let cause = match std::panic::catch_unwind(f) {
                Ok(res) => Cause::Natural(res),
                Err(panic) => Cause::Paniced(panic),
            };
            match tx.send(Dead { thread_id, cause }) {
                Ok(()) => {}
                Err(chan::SendError(_)) => {
                    debug!(logger, "thread died, but pool paniced"; "thread_name" => &name2)
                }
            }
        })?;

        self.threads.insert(
            handle.thread().id(),
            Thread {
                name,
                join_handle: handle,
            },
        );

        Ok(())
    }

    /// Attempt to join all threads, and if any of them panicked,
    /// also panic this thread.
    pub fn join_all_or_panic(&mut self) -> Result<(), Err> {
        loop {
            if self.threads.is_empty() {
                return Ok(());
            }

            let death = self
                .rx
                .recv()
                .expect("thread pool: Failed to receive a ThreadResult, even though there are more threads.");

            let thread = self
                .threads
                .remove(&death.thread_id)
                .expect("thread pool: Failed to find thread ID in handle table");

            let name = thread.name;
            thread
                .join_handle
                .join()
                // If the thread panics without an unwindable panic,
                // there’s nothing we can do here.
                // Otherwise the stack is unrolled via Cause::Paniced
                .unwrap_or_else(|_any| {
                    panic!(
                        "thread pool: thread {} paniced and we were unable to unwind it",
                        name
                    )
                });

            match death.cause {
                // The thread died successfully
                Cause::Natural(Ok(())) => {}
                // The thread didn’t panic, it returned an error, so we return early
                // TODO: this will not join all threads?? Why is the return here? Sounds wrong.
                Cause::Natural(Err(err)) => return Err(err),
                Cause::Paniced(panic) => std::panic::resume_unwind(panic),
            }
        }
    }
}

/// This value should be returned from a racing thread when the stop signal has been received. Do not construct (TODO: how to prevent other modules from constructing?)
#[derive(Debug)]
pub struct StopReceived();

/// Race two closures.
///
/// Each closure is passed a channel that is sent a single message when the other closure has finished.
/// Ideally, the closure then stops, but it’s up to the closure, we cannot interrupt threads (cooperative multitasking).
#[allow(private_bounds)]
pub fn race<F, G, Res>(logger: &slog::Logger, first: F, second: G) -> Res
where
    F: FnOnce(Receiver<StopReceived>) -> Result<Res, StopReceived>,
    F: std::panic::UnwindSafe,
    F: Send + 'static,
    G: FnOnce(Receiver<StopReceived>) -> Result<Res, StopReceived>,
    G: std::panic::UnwindSafe,
    G: Send + 'static,
    Res: Send + 'static,
{
    let (one_res_tx, one_res_rx) = chan::bounded(1);
    let (two_res_tx, two_res_rx) = chan::bounded(1);
    let (one_stop_tx, one_stop_rx) = chan::bounded::<StopReceived>(1);
    let (two_stop_tx, two_stop_rx) = chan::bounded::<StopReceived>(1);
    let mut thread: Pool<Never> = Pool::new(logger.clone());
    thread.spawn("racing thread 1", move || {
        let res = first(one_stop_rx);
        match one_res_tx.try_send(res) {
            Ok(()) => Ok(()),
            Err(err) => panic!("unable to send the first racing result, because the channel was disconnected (should never happen): {:?}", err)
        }
    }).expect("unable to spawn racing thread, should not happen");
    thread.spawn("racing thread 2", move || {
        let res = second(two_stop_rx);
        match two_res_tx.try_send(res) {
            Ok(()) => Ok(()),
            Err(err) => panic!("unable to send the second racing result, because the channel was disconnected (should never happen): {:?}", err)
        }
    }).expect("unable to spawn racing thread, should not happen");

    let res = chan::select! {
        recv(one_res_rx) -> res => res,
        recv(two_res_rx) -> res => res,
    }
    .expect("Could not receive async results");
    // ask the channels to stop
    let _ = one_stop_tx.try_send(StopReceived());
    let _ = two_stop_tx.try_send(StopReceived());
    // join both threads
    thread.join_all_or_panic().unwrap_or_else(|n| n.never());
    res.expect("Should never receive a stop message, because we already got the result from the other thread.")
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    #[test]
    fn test_race() {
        // one stops when requested, two will ignore the stop command entirely but send a msg after 10ms
        let mk = |timeout1, timeout2, two_msg_tx: Option<chan::Sender<()>>| {
            race(
                &crate::logging::test_logger(),
                move |stop| {
                    chan::select! {
                        recv(stop) -> s => {
                            println!("1: received request to stop, stopping");
                            Err(s.unwrap())
                        },
                        recv(chan::after(timeout1)) -> _ =>  {
                            println!("1: timed out, returning result");
                            Ok("1: myresult")
                        }
                    }
                },
                move |_stop| {
                    chan::select! {
                        recv(chan::after(timeout2)) -> _ =>  {
                            println!("2: timed out, returning result");
                            Ok("2: otherresult")
                        }
                        recv(chan::after(Duration::from_millis(10))) -> _ => {
                            match two_msg_tx {
                                Some(tx) => tx.send(()).unwrap(),
                                None => {}
                                }
                            Ok("hit the message timeout")
                        }
                    }
                },
            )
        };
        let one = mk(Duration::from_millis(5), Duration::from_millis(10), None);
        assert_eq!(one, "1: myresult", "one was shorter");
        let two = mk(Duration::from_millis(100), Duration::from_millis(5), None);
        assert_eq!(two, "2: otherresult", "two was shorter");

        let (two_msg_tx, two_msg_rx) = chan::bounded::<()>(1);
        let three = mk(
            Duration::from_millis(5),
            Duration::from_millis(1000),
            Some(two_msg_tx),
        );
        assert_eq!(three, "1: myresult", "one finishes, while two still runs");
        two_msg_rx
            .recv_timeout(Duration::from_millis(30))
            .expect("We expect the other thread to send a message after the first one won the race")
    }
}
