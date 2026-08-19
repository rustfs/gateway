// Copyright 2026 RustFS Team
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! What reading a POST Object form's file part costs, measured rather than described.
//!
//! Responsible for: proving that the heap the form reader consumes does not grow with the size of
//! the file it reads, over a path that genuinely walks every byte of that file — which is the only
//! evidence that the ceiling is enforced *before* the file is buffered rather than after.
//! NOT responsible for: how long the read takes. Time on a shared runner is noise, and a gate that
//! is noise gets turned off. Nor for the ordering rules themselves; `form_limits.rs` owns those.
//! Upstream: `rustfs-gateway-http`, `dhat`. Downstream: nothing.
//!
//! # Why an assertion would not have done
//!
//! "The limit is checked first" is exactly the kind of claim that reads identically whether it is
//! true or not: a reader that collected the whole part and then compared its length would produce
//! the same rejection, the same status and the same log line. The difference between the two is
//! visible in one place only — the heap — so that is where this file looks. The instrument is the
//! one rustfs/gateway#225 established for the request path: two runs of the same code at two input
//! sizes, compared against each other rather than against a number somebody once measured, with a
//! floor that refuses a run in which the profiler saw nothing.

use std::process::Command;

use rustfs_gateway_http::{FileStep, FormLimits, FormReader, FormStep};

/// The profiler needs to be the global allocator for `dhat::HeapStats` to mean anything.
#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

/// The two sizes, and the ratio between them is the instrument.
const SMALL: usize = 64 * 1024;
/// Two hundred and fifty-six times the smaller file.
const LARGE: usize = 256 * SMALL;

/// The frame size the body is fed in, held constant across both runs.
///
/// Constant on purpose: if the larger run were fed in larger frames, a per-frame allocation would
/// cancel out and the measurement would stop being able to see one. With the frame size fixed the
/// larger run takes 256 times as many pushes, so anything allocated per push shows up multiplied
/// by 256 rather than hidden.
const FRAME: usize = 8 * 1024;

const BOUNDARY: &str = "----RustFSFormBoundaryUgKDlSmVe0Ep8Wd";

const PROBE_ENV: &str = "RUSTFS_GATEWAY_FORM_ALLOCATION_PROBE";
const PROBE_SENTINEL: &str = "rustfs-gateway form allocation probe: ";
const PROBE_TEST: &str = "a_form_reads_a_file_without_a_heap_that_grows_with_it";

/// A form whose `file` part is `len` bytes of position-dependent content.
fn body(len: usize) -> Vec<u8> {
    let mut body = Vec::with_capacity(len + 4096);
    body.extend_from_slice(
        format!("--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"key\"\r\n\r\nuploads/payload.bin\r\n").as_bytes(),
    );
    body.extend_from_slice(
        format!("--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"policy\"\r\n\r\ncontent-length-range\r\n").as_bytes(),
    );
    body.extend_from_slice(
        format!(
            "--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"payload.bin\"\r\n\
             Content-Type: application/octet-stream\r\n\r\n"
        )
        .as_bytes(),
    );
    body.extend((0..len).map(|index| (index % 251) as u8));
    body.extend_from_slice(b"\r\n");
    body.extend_from_slice(format!("--{BOUNDARY}--\r\n").as_bytes());
    body
}

/// Reads one whole form, counting the file bytes and keeping none of them.
///
/// The counter is the point: a sink that collected would put the whole file on the heap and make
/// this measurement about the sink instead of about the reader. Every byte is still visited — the
/// returned count is asserted against the file length, so a reader that skipped the content could
/// not satisfy it.
fn read(body: &[u8], ceiling: u64) -> u64 {
    let mut reader = Some(
        FormReader::new(&format!("multipart/form-data; boundary={BOUNDARY}"), FormLimits::default())
            .expect("a well-formed content type"),
    );
    let mut file = None;
    let mut delivered = 0u64;
    let mut cursor = 0usize;

    while cursor < body.len() {
        let take = FRAME.min(body.len() - cursor);
        let mut slice = &body[cursor..cursor + take];
        cursor += take;

        if let Some(mut head) = reader.take() {
            match head.push(slice).expect("the form head parses") {
                FormStep::NeedMore => {
                    reader = Some(head);
                    continue;
                }
                FormStep::FileReached { consumed } => {
                    file = Some(head.into_file(ceiling).expect("the file part was reached"));
                    slice = &slice[consumed..];
                }
            }
        }

        let Some(reading) = file.as_mut() else {
            panic!("the reader is either reading the head or the file");
        };
        let mut sink = |bytes: &[u8]| delivered += bytes.len() as u64;
        if let FileStep::Complete { file_bytes } = reading.push(slice, &mut sink).expect("a legal file part") {
            assert_eq!(file_bytes, delivered, "the reader's count and the sink's disagree");
        }
    }
    delivered
}

/// What one read of a `len`-byte file costs: blocks allocated, and bytes allocated.
///
/// The body, the warm-up read and everything else that is not the measured read happen before the
/// profiler exists, so the window holds one read and nothing else.
fn cost(len: usize) -> (u64, u64) {
    let body = body(len);
    let ceiling = LARGE as u64;
    let warm = read(&body, ceiling);
    assert_eq!(warm, len as u64, "the warm-up read did not deliver the whole file");

    let profiler = dhat::Profiler::builder().testing().build();
    let delivered = read(&body, ceiling);
    let stats = dhat::HeapStats::get();
    drop(profiler);

    assert_eq!(delivered, len as u64, "the measured read did not deliver the whole file");
    (stats.total_blocks, stats.total_bytes)
}

/// Runs one isolated probe process at `len` and reads back what it measured.
///
/// One process per size, for the reason `crates/gateway/tests/request_allocations.rs` gives:
/// `dhat` profiles a whole process, and the tests in this binary run in parallel threads.
fn measure(len: usize) -> (u64, u64) {
    let executable = std::env::current_exe().expect("the active test binary has a path");
    let output = Command::new(executable)
        .args(["--exact", PROBE_TEST, "--nocapture"])
        .env(PROBE_ENV, len.to_string())
        .output()
        .expect("the isolated allocation probe starts");
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    assert!(
        output.status.success(),
        "the {len}-byte allocation probe failed:\n{stdout}{}",
        String::from_utf8_lossy(&output.stderr)
    );
    // Parsed rather than assumed. A probe that crashed before measuring, or one whose name no
    // longer selects a test, exits successfully with no line to find — which is the shape that
    // would turn this whole file into two zeroes compared against each other.
    let line = stdout
        .lines()
        .find_map(|line| line.strip_prefix(PROBE_SENTINEL))
        .unwrap_or_else(|| panic!("the {len}-byte allocation probe measured nothing:\n{stdout}"));
    let mut parts = line.split_whitespace();
    let blocks = parts.next().and_then(|text| text.parse().ok());
    let bytes = parts.next().and_then(|text| text.parse().ok());
    match (blocks, bytes) {
        (Some(blocks), Some(bytes)) => (blocks, bytes),
        _ => panic!("the {len}-byte allocation probe printed `{line}`, which is not two numbers"),
    }
}

/// How many more heap *blocks* the larger read may take than the smaller one.
///
/// Reasoned rather than measured. Both runs allocate the same fixed set — the delimiter, the head
/// buffer, the field strings, the carry and the scratch — and nothing in the file loop is supposed
/// to allocate at all, so the honest expectation is zero and this is slack for allocator
/// bookkeeping that does not cancel exactly between two separately constructed readers.
///
/// What it does not leave room for is the thing this line exists to catch. The larger run makes
/// 2,048 pushes against the smaller run's 8; one allocation per push therefore puts it 2,040
/// blocks above, and collecting the part into a growing buffer puts it eleven doublings and
/// sixteen mebibytes above. Both are recorded as mutations on the pull request.
const BLOCK_HEADROOM: u64 = 16;

/// Allocator bookkeeping that does not scale with the file, so it cancels between the two runs but
/// not exactly. Small next to a single copy of even the smaller file.
const BYTES_HEADROOM: u64 = 8 * 1024;

/// What a run that measured nothing looks like, and the floor that refuses it.
///
/// `dhat::HeapStats::get()` does not panic when no `dhat::Alloc` is installed — it answers zero,
/// and two zeroes satisfy every bound on their difference. Reading a form allocates a delimiter, a
/// head buffer, three field strings, a carry and a scratch; these floors sit an order of magnitude
/// under that, low enough never to be the reason a legitimate tightening goes red and far enough
/// above zero to catch an allocator that is not installed.
const MEASURED_BLOCKS_FLOOR: u64 = 4;
/// The byte counterpart of [`MEASURED_BLOCKS_FLOOR`].
const MEASURED_BYTES_FLOOR: u64 = 256;

/// Negative — a file two hundred and fifty-six times larger does not cost two hundred and
/// fifty-six times as much heap.
///
/// # What this proves that `form_limits.rs` cannot
///
/// `c-lim-0028` asserts that a 1 KiB policy stops a large file at 1 KiB. That assertion is
/// satisfied by a reader which buffers the whole part and then measures it — the rejection, the
/// byte count and the log line are identical either way. The difference is on the heap, and it is
/// the difference between a limit and a report about a buffer that already exists.
///
/// So this reads a file *within* its ceiling, at two sizes, and requires the cost of the read to
/// be a function of the reader rather than of the file. A reader that cannot hold the file cannot
/// have been measuring it after the fact.
#[test]
fn a_form_reads_a_file_without_a_heap_that_grows_with_it() {
    if let Some(len) = std::env::var_os(PROBE_ENV) {
        let len: usize = len.to_string_lossy().parse().expect("a file size");
        let (blocks, bytes) = cost(len);
        println!("{PROBE_SENTINEL}{blocks} {bytes}");
        return;
    }

    let (small_blocks, small_bytes) = measure(SMALL);
    let (large_blocks, large_bytes) = measure(LARGE);
    println!("small file {SMALL}: {small_blocks} blocks, {small_bytes} bytes");
    println!("large file {LARGE}: {large_blocks} blocks, {large_bytes} bytes");

    // First: that anything was measured at all. Everything below is a statement about the
    // difference between two numbers, and two zeroes have no difference.
    for (label, blocks, bytes) in [("small", small_blocks, small_bytes), ("large", large_blocks, large_bytes)] {
        assert!(
            blocks >= MEASURED_BLOCKS_FLOOR && bytes >= MEASURED_BYTES_FLOOR,
            "the {label} probe recorded {blocks} blocks and {bytes} bytes, which is less than \
             reading a form can possibly cost: the profiler saw nothing, so every bound below is \
             comparing one unmeasured run against another. Check that a `#[global_allocator]` of \
             `dhat::Alloc` is still declared in this file."
        );
    }

    let block_growth = large_blocks.saturating_sub(small_blocks);
    assert!(
        block_growth <= BLOCK_HEADROOM,
        "reading a file {}x larger took {block_growth} more allocations ({small_blocks} -> \
         {large_blocks}). Something in the file loop allocates per push or per byte, which means \
         the reader is accumulating the part it is supposed to be bounding.",
        LARGE / SMALL
    );

    let byte_growth = large_bytes.saturating_sub(small_bytes);
    assert!(
        byte_growth <= BYTES_HEADROOM,
        "reading a file {}x larger allocated {byte_growth} more bytes ({small_bytes} -> \
         {large_bytes}). One copy of the larger file alone would be {LARGE} bytes, so the reader \
         is holding the file rather than passing it through.",
        LARGE / SMALL
    );
}
