//! Actix utils is mostly a wrapper for TrustDNS so that we can kill it and restart it
//! I assume it holds some sort of internal socket prevents it from operating if you plug
//! in the wan port after initializing it. We may replace that with simple syncronous name
//! resolution which is slower but almost not enough to care.

use actix::actors::resolver::{Resolve, Resolver};
use actix::*;
use futures::Future;

use actix::actors::resolver::ResolverError;
use failure::Error;
use std::collections::VecDeque;
use std::net::SocketAddr;
use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};

pub struct KillActor;

impl Message for KillActor {
    type Result = Result<(), Error>;
}

impl Handler<KillActor> for ResolverWrapper {
    type Result = Result<(), Error>;

    fn handle(&mut self, _: KillActor, ctx: &mut Context<Self>) -> Self::Result {
        self.inner.do_send(KillActor);
        ctx.stop();
        Ok(())
    }
}

impl Handler<KillActor> for Resolver {
    type Result = Result<(), Error>;

    fn handle(&mut self, _: KillActor, ctx: &mut Context<Self>) -> Self::Result {
        ctx.stop();
        Ok(())
    }
}

impl Actor for ResolverWrapper {
    type Context = Context<Self>;

    fn started(&mut self, _ctx: &mut Context<Self>) {
        trace!("resolver wrapper started!");
    }
}

pub struct ResolverWrapper {
    pub inner: Addr<Resolver>,
}

impl Supervised for ResolverWrapper {}

impl SystemService for ResolverWrapper {}

impl Default for ResolverWrapper {
    fn default() -> ResolverWrapper {
        ResolverWrapper {
            inner: Resolver::new(ResolverConfig::default(), ResolverOpts::default()).start(),
        }
    }
}

impl Handler<Resolve> for ResolverWrapper {
    type Result = ResponseFuture<VecDeque<SocketAddr>, ResolverError>;

    fn handle(&mut self, msg: Resolve, _: &mut Self::Context) -> Self::Result {
        Box::new(self.inner.send(msg).then(|x| x.unwrap()))
    }
}
