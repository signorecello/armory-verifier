//! GoTEE Trusted Applet — Ultra Honk ZK proof verifier.
//!
//! Runs as a freestanding Rust binary inside ARM TrustZone Secure World
//! under the GoTEE supervisor on the USB Armory MK II.
//!
//! Communication with Normal World uses a shared memory buffer with a
//! simple fixed-offset protocol:
//!
//! ```text
//! Request  (Normal World → Secure World):
//!   [0..4]   command     : u32 (1 = VERIFY)
//!   [4..8]   proof_len   : u32
//!   [8..12]  vk_len      : u32
//!   [12..16] pi_len      : u32
//!   [16..20] vk_hash_len : u32  (0 = no hash, treated as zero)
//!   [20..]   proof | vk | pi | vk_hash  (concatenated)
//!
//! Response (Secure World → Normal World):
//!   [0..4]   status      : i32  (1=VALID, 0=INVALID, -1=ERROR)
//! ```

#![no_std]
#![no_main]

extern crate alloc;

use core::panic::PanicInfo;
use core::slice;
use linked_list_allocator::LockedHeap;

// ---------------------------------------------------------------------------
// Global allocator (heap region defined by linker script)
// ---------------------------------------------------------------------------

#[global_allocator]
static ALLOCATOR: LockedHeap = LockedHeap::empty();

extern "C" {
    static __heap_start: u8;
    static __heap_end: u8;
}

unsafe fn init_heap() {
    let heap_start = unsafe { &__heap_start as *const u8 as usize };
    let heap_end = unsafe { &__heap_end as *const u8 as usize };
    let heap_size = heap_end - heap_start;
    unsafe {
        ALLOCATOR.lock().init(heap_start as *mut u8, heap_size);
    }
}

// ---------------------------------------------------------------------------
// Wire protocol constants
// ---------------------------------------------------------------------------

const CMD_VERIFY: u32 = 1;
const HEADER_SIZE: usize = 20;

const STATUS_VALID: i32 = 1;
const STATUS_INVALID: i32 = 0;
const STATUS_ERROR: i32 = -1;

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

/// Shared memory base address and size are provided by the GoTEE supervisor.
/// The exact mechanism depends on the GoTEE Rust applet ABI — this is a
/// placeholder that matches the GoTEE-example convention where the applet
/// receives a pointer to the shared region via a register or fixed address.
///
/// TODO: Wire up to GoTEE's actual applet entry ABI once the supervisor
/// integration is complete. For now this serves as the reference
/// implementation of the protocol handler.
///
/// # Safety
/// `shared_buf` must point to a valid shared memory region of at least
/// `shared_len` bytes, mapped by the GoTEE supervisor.
#[no_mangle]
pub unsafe extern "C" fn _start(shared_buf: *mut u8, shared_len: usize) -> ! {
    // Initialise the heap allocator (once, at boot)
    unsafe { init_heap() };

    // Process the request
    let status = if shared_len >= HEADER_SIZE {
        let buf = unsafe { slice::from_raw_parts(shared_buf, shared_len) };
        process_request(buf)
    } else {
        STATUS_ERROR
    };

    // Write the response status into the first 4 bytes of shared memory
    if shared_len >= 4 {
        let out = unsafe { slice::from_raw_parts_mut(shared_buf, 4) };
        out.copy_from_slice(&status.to_le_bytes());
    }

    // Return to the GoTEE supervisor (halt in a loop — the supervisor
    // handles the actual world switch back to Normal World).
    loop {
        core::hint::spin_loop();
    }
}

fn process_request(buf: &[u8]) -> i32 {
    // Parse header (little-endian u32 fields)
    let command = u32::from_le_bytes(buf[0..4].try_into().unwrap());
    if command != CMD_VERIFY {
        return STATUS_ERROR;
    }

    let proof_len = u32::from_le_bytes(buf[4..8].try_into().unwrap()) as usize;
    let vk_len = u32::from_le_bytes(buf[8..12].try_into().unwrap()) as usize;
    let pi_len = u32::from_le_bytes(buf[12..16].try_into().unwrap()) as usize;
    let vk_hash_len = u32::from_le_bytes(buf[16..20].try_into().unwrap()) as usize;

    let total_payload = proof_len + vk_len + pi_len + vk_hash_len;
    if buf.len() < HEADER_SIZE + total_payload {
        return STATUS_ERROR;
    }

    // Slice out the individual buffers
    let data = &buf[HEADER_SIZE..];
    let proof_bytes = &data[..proof_len];
    let vk_bytes = &data[proof_len..proof_len + vk_len];
    let pi_bytes = &data[proof_len + vk_len..proof_len + vk_len + pi_len];
    let vk_hash_bytes = if vk_hash_len > 0 {
        Some(&data[proof_len + vk_len + pi_len..proof_len + vk_len + pi_len + vk_hash_len])
    } else {
        None
    };

    // Run the verifier
    let valid = armory_verifier::verify(proof_bytes, vk_bytes, pi_bytes, vk_hash_bytes);

    if valid {
        STATUS_VALID
    } else {
        STATUS_INVALID
    }
}

// ---------------------------------------------------------------------------
// Panic handler (required for no_std)
// ---------------------------------------------------------------------------

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    // In TrustZone Secure World there is nowhere to print to.
    // Halt — the GoTEE supervisor will detect the applet stall.
    loop {
        core::hint::spin_loop();
    }
}
