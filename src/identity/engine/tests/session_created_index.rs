//! The realm session list pages in created-time order with a key cursor
//! (#847).
//!
//! Before, a page read one page of the live-session index, which is in
//! session-id (random) order, and the status filter and the sort applied to
//! that page only. "Newest first" did not show the newest sessions, and a
//! filtered page could show fewer rows than exist.

use super::*;

use std::collections::BTreeSet;
use std::sync::atomic::Ordering;

use super::session_list_reads::counting_engine;
use crate::identity::search::SortDir;
use crate::identity::search::{SessionCursorPage, SessionPageCursor, SessionStatusFilter};

const MINUTE: i64 = 60 * 1_000_000;

/// Creates `n` sessions for `user`, one minute apart, oldest first.
fn sessions_a_minute_apart(
    engine: &EmbeddedIdentityEngine,
    clock: &FakeClock,
    realm: &RealmId,
    user: &User,
    n: usize,
) -> Vec<Session> {
    (0..n)
        .map(|_| {
            clock.advance(MINUTE);
            engine
                .create_session(realm, user.id(), &SessionContext::default())
                .expect("create session")
        })
        .collect()
}

fn page(
    engine: &EmbeddedIdentityEngine,
    realm: &RealmId,
    dir: SortDir,
    status: SessionStatusFilter,
    cursor: &SessionPageCursor,
    limit: u32,
) -> SessionCursorPage {
    engine
        .session_page_by_cursor(realm, dir, status, cursor, limit)
        .expect("session page")
}

fn ids(sessions: &[Session]) -> Vec<SessionId> {
    sessions.iter().map(|s| s.id().clone()).collect()
}

/// Every page from the first, following `next`, in order.
fn walk_all(
    engine: &EmbeddedIdentityEngine,
    realm: &RealmId,
    dir: SortDir,
    status: SessionStatusFilter,
    limit: u32,
) -> Vec<SessionCursorPage> {
    let mut pages = vec![page(
        engine,
        realm,
        dir,
        status,
        &SessionPageCursor::First,
        limit,
    )];
    while let Some(next) = pages.last().and_then(|p| p.next.clone()) {
        pages.push(page(
            engine,
            realm,
            dir,
            status,
            &SessionPageCursor::After(next),
            limit,
        ));
        assert!(pages.len() < 100, "the walk must end");
    }
    pages
}

#[test]
fn pages_walk_every_live_session_once_in_created_order() {
    const PAGE: u32 = 10;
    let (_dir, counting, engine, clock) = counting_engine();
    let realm = create_test_realm(&engine);
    let user = create_test_user(&engine, &realm);
    let sessions = sessions_a_minute_apart(&engine, &clock, &realm, &user, 30);
    for i in [5, 17, 29] {
        engine
            .revoke_session(&realm, sessions[i].id())
            .expect("revoke session");
    }
    let oldest_first: Vec<SessionId> = sessions
        .iter()
        .enumerate()
        .filter(|(i, _)| ![5, 17, 29].contains(i))
        .map(|(_, s)| s.id().clone())
        .collect();
    let newest_first: Vec<SessionId> = oldest_first.iter().rev().cloned().collect();

    for (dir, expected) in [
        (SortDir::Desc, &newest_first),
        (SortDir::Asc, &oldest_first),
    ] {
        counting.session_reads.store(0, Ordering::SeqCst);
        let pages = walk_all(&engine, &realm, dir, SessionStatusFilter::All, PAGE);
        let reads = counting.session_reads.load(Ordering::SeqCst);
        let walked: Vec<SessionId> = pages.iter().flat_map(|p| ids(&p.sessions)).collect();
        assert_eq!(
            &walked, expected,
            "{dir:?}: every live session once, in order"
        );
        assert_eq!(pages.len(), 3, "{dir:?}: 27 sessions in pages of 10");
        assert!(
            pages.iter().all(|p| p.total == 27),
            "{dir:?}: the live total"
        );
        assert_eq!(pages[0].prev, None, "{dir:?}: no page before the first");
        assert!(
            reads <= pages.len() * (PAGE as usize + 2),
            "{dir:?}: {reads} session reads for {} pages",
            pages.len()
        );

        // The previous page of the second page is the first page.
        let back = page(
            &engine,
            &realm,
            dir,
            SessionStatusFilter::All,
            &SessionPageCursor::Before(pages[1].prev.clone().expect("a previous page")),
            PAGE,
        );
        assert_eq!(
            ids(&back.sessions),
            ids(&pages[0].sessions),
            "{dir:?}: back"
        );
        assert_eq!(back.prev, None, "{dir:?}: back to the first page");
        assert!(
            back.next.is_some(),
            "{dir:?}: the first page has a next page"
        );
    }
}

#[test]
fn a_status_filter_fills_the_page_from_the_walk() {
    let (_dir, _counting, engine, clock) = counting_engine();
    let realm = create_test_realm(&engine);
    let user = create_test_user(&engine, &realm);
    let old = sessions_a_minute_apart(&engine, &clock, &realm, &user, 15);
    // Every old session is past its expiry; the sweep did not run.
    clock.advance(IdentityConfig::default().session.ttl_micros);
    let new = sessions_a_minute_apart(&engine, &clock, &realm, &user, 15);

    let active = walk_all(
        &engine,
        &realm,
        SortDir::Desc,
        SessionStatusFilter::Active,
        10,
    );
    let walked: Vec<SessionId> = active.iter().flat_map(|p| ids(&p.sessions)).collect();
    let expected: Vec<SessionId> = ids(&new).into_iter().rev().collect();
    assert_eq!(walked, expected, "the active sessions, newest first");
    assert_eq!(active[0].sessions.len(), 10, "a full first page");
    assert!(active.iter().all(|p| p.total == 30));

    let expired = walk_all(
        &engine,
        &realm,
        SortDir::Desc,
        SessionStatusFilter::Expired,
        10,
    );
    let walked: Vec<SessionId> = expired.iter().flat_map(|p| ids(&p.sessions)).collect();
    let expected: Vec<SessionId> = ids(&old).into_iter().rev().collect();
    assert_eq!(walked, expected, "the expired sessions, newest first");
    assert_eq!(
        expired[0].sessions.len(),
        10,
        "a full first page past 15 active ones"
    );
}

#[test]
fn a_filtered_walk_stops_at_its_bound() {
    const BOUND: usize = 20;
    let (_dir, counting, engine, clock) = counting_engine();
    let realm = create_test_realm(&engine);
    let user = create_test_user(&engine, &realm);
    sessions_a_minute_apart(&engine, &clock, &realm, &user, 50);

    counting.session_reads.store(0, Ordering::SeqCst);
    let first = engine
        .session_page_walk(
            &realm,
            SortDir::Desc,
            SessionStatusFilter::Expired,
            &SessionPageCursor::First,
            10,
            BOUND,
        )
        .expect("session page");
    let reads = counting.session_reads.load(Ordering::SeqCst);
    assert_eq!(first.sessions.len(), 0, "no session is expired");
    assert!(
        first.next.is_some(),
        "the walk stopped at its bound, not at the end"
    );
    assert!(
        reads <= BOUND + 2,
        "{reads} session reads for a bound of {BOUND}"
    );

    let mut pages = 1;
    let mut next = first.next;
    while let Some(after) = next {
        next = engine
            .session_page_walk(
                &realm,
                SortDir::Desc,
                SessionStatusFilter::Expired,
                &SessionPageCursor::After(after),
                10,
                BOUND,
            )
            .expect("session page")
            .next;
        pages += 1;
        assert!(pages < 10, "the walk must end");
    }
    assert_eq!(pages, 3, "50 sessions in walks of at most {BOUND}");
}

#[test]
fn only_a_create_and_a_removal_write_the_created_index() {
    let (_dir, counting, engine, _clock) = counting_engine();
    let realm = create_test_realm(&engine);
    let user = create_test_user(&engine, &realm);

    counting.created_index_writes.store(0, Ordering::SeqCst);
    let session = engine
        .create_session(&realm, user.id(), &SessionContext::default())
        .expect("create session");
    assert_eq!(
        counting.created_index_writes.swap(0, Ordering::SeqCst),
        2,
        "a create puts one key in each created-time index"
    );

    engine
        .refresh_session(&realm, session.id())
        .expect("refresh");
    assert_eq!(
        counting.created_index_writes.swap(0, Ordering::SeqCst),
        0,
        "a refresh writes no created-time index key"
    );

    engine.revoke_session(&realm, session.id()).expect("revoke");
    assert_eq!(
        counting.created_index_writes.swap(0, Ordering::SeqCst),
        2,
        "a revocation deletes both keys"
    );
}

#[test]
fn a_cursor_session_that_no_longer_exists_gives_the_first_page() {
    let (_dir, _counting, engine, clock) = counting_engine();
    let realm = create_test_realm(&engine);
    let user = create_test_user(&engine, &realm);
    let sessions = sessions_a_minute_apart(&engine, &clock, &realm, &user, 3);
    let gone = SessionId::new(uuid::Uuid::new_v4());

    let page = page(
        &engine,
        &realm,
        SortDir::Desc,
        SessionStatusFilter::All,
        &SessionPageCursor::After(gone),
        10,
    );
    let expected: BTreeSet<SessionId> = ids(&sessions).into_iter().collect();
    assert_eq!(page.sessions.len(), 3);
    assert_eq!(
        ids(&page.sessions).into_iter().collect::<BTreeSet<_>>(),
        expected
    );
    assert_eq!(page.prev, None);
}
