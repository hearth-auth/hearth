//! Streaming merge of sorted key sources: the memtable maps and the SSTs.
//!
//! [`EmbeddedStorageEngine::visit_keys`](crate::storage::StorageEngine::visit_keys)
//! walks a key range across every source at once, holding one position per
//! source instead of collecting the range. Counting a million keys this way
//! holds no key at all (#447).

use std::ops::ControlFlow;

use crate::storage::StorageError;

/// A position in one sorted key source, restricted to a single realm's
/// `[start, end)` window.
pub(crate) trait KeyCursor {
    /// The key at this position and whether it is live (`false` for a
    /// tombstone), or `None` once the window is exhausted.
    fn current(&self) -> Option<(&[u8], bool)>;

    /// Moves to the next key in the window.
    ///
    /// # Errors
    ///
    /// Any error reading the next block of an SST.
    fn advance(&mut self) -> Result<(), StorageError>;
}

/// Visits, in key order, each key that is live in the newest source holding
/// it, until every source is exhausted or `visit` breaks.
///
/// `cursors` MUST be ordered newest first: where several sources hold a key,
/// the first one decides whether it is live or deleted.
///
/// # Errors
///
/// Any error a cursor returns while advancing.
pub(crate) fn visit_merged(
    cursors: &mut [Box<dyn KeyCursor + '_>],
    visit: &mut dyn FnMut(&[u8]) -> ControlFlow<()>,
) -> Result<(), StorageError> {
    loop {
        // The newest source holding the smallest key: strict `<` keeps the
        // first (newest) of equal keys.
        let mut winner: Option<usize> = None;
        for (i, cursor) in cursors.iter().enumerate() {
            let Some((key, _)) = cursor.current() else {
                continue;
            };
            let smaller = match winner {
                None => true,
                Some(w) => cursors[w].current().is_some_and(|(best, _)| key < best),
            };
            if smaller {
                winner = Some(i);
            }
        }
        let Some(w) = winner else {
            return Ok(());
        };

        // No source before the winner holds its key (it would have won), so
        // only the older sources after it can hold a superseded copy.
        let [newest, older @ ..] = &mut cursors[w..] else {
            return Ok(());
        };
        let Some((key, alive)) = newest.current() else {
            return Ok(());
        };
        for cursor in older.iter_mut() {
            if cursor.current().is_some_and(|(k, _)| k == key) {
                cursor.advance()?;
            }
        }
        if alive && visit(key).is_break() {
            return Ok(());
        }
        newest.advance()?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A sorted in-memory source.
    struct VecCursor {
        keys: Vec<(&'static [u8], bool)>,
        pos: usize,
    }

    impl VecCursor {
        fn boxed(keys: &[(&'static [u8], bool)]) -> Box<dyn KeyCursor> {
            Box::new(Self {
                keys: keys.to_vec(),
                pos: 0,
            })
        }
    }

    impl KeyCursor for VecCursor {
        fn current(&self) -> Option<(&[u8], bool)> {
            self.keys.get(self.pos).copied()
        }

        fn advance(&mut self) -> Result<(), StorageError> {
            self.pos += 1;
            Ok(())
        }
    }

    fn merged(cursors: &mut [Box<dyn KeyCursor + '_>]) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        visit_merged(cursors, &mut |key| {
            out.push(key.to_vec());
            ControlFlow::Continue(())
        })
        .expect("merge");
        out
    }

    #[test]
    fn the_newest_source_decides_whether_a_key_is_live() {
        let mut cursors = [
            // newest: deletes b, rewrites c
            VecCursor::boxed(&[(b"b", false), (b"c", true)]),
            // middle: re-creates d deleted below, deletes e
            VecCursor::boxed(&[(b"d", true), (b"e", false)]),
            // oldest
            VecCursor::boxed(&[(b"a", true), (b"b", true), (b"d", false), (b"e", true)]),
        ];
        assert_eq!(
            merged(&mut cursors),
            vec![b"a".to_vec(), b"c".to_vec(), b"d".to_vec()]
        );
    }

    #[test]
    fn a_key_in_every_source_is_visited_once() {
        let mut cursors = [
            VecCursor::boxed(&[(b"k", true), (b"z", true)]),
            VecCursor::boxed(&[(b"k", true)]),
            VecCursor::boxed(&[(b"a", true), (b"k", true)]),
        ];
        assert_eq!(
            merged(&mut cursors),
            vec![b"a".to_vec(), b"k".to_vec(), b"z".to_vec()]
        );
    }

    #[test]
    fn a_break_stops_the_walk() {
        let mut cursors = [VecCursor::boxed(&[
            (b"a", true),
            (b"b", true),
            (b"c", true),
        ])];
        let mut seen = Vec::new();
        visit_merged(&mut cursors, &mut |key| {
            seen.push(key.to_vec());
            if seen.len() == 2 {
                ControlFlow::Break(())
            } else {
                ControlFlow::Continue(())
            }
        })
        .expect("merge");
        assert_eq!(seen, vec![b"a".to_vec(), b"b".to_vec()]);
    }

    #[test]
    fn no_sources_visit_nothing() {
        assert_eq!(merged(&mut []), Vec::<Vec<u8>>::new());
    }
}
