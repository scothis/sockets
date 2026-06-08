use crate::{_rt, exports, wit_future};

#[doc(hidden)]
#[allow(unused_unsafe)]
pub mod wit_futures_vtable0_alt {
    #[cfg(not(target_arch = "wasm32"))]
    unsafe extern "C" fn cancel_write(_: u32) -> u32 {
        unreachable!()
    }
    #[cfg(not(target_arch = "wasm32"))]
    unsafe extern "C" fn cancel_read(_: u32) -> u32 {
        unreachable!()
    }
    #[cfg(not(target_arch = "wasm32"))]
    unsafe extern "C" fn drop_writable(_: u32) {
        unreachable!()
    }
    #[cfg(not(target_arch = "wasm32"))]
    unsafe extern "C" fn drop_readable(_: u32) {
        unreachable!()
    }
    #[cfg(not(target_arch = "wasm32"))]
    unsafe extern "C" fn new() -> u64 {
        unreachable!()
    }
    #[cfg(not(target_arch = "wasm32"))]
    unsafe extern "C" fn start_read(_: u32, _: *mut u8) -> u32 {
        unreachable!()
    }
    #[cfg(not(target_arch = "wasm32"))]
    unsafe extern "C" fn start_write(_: u32, _: *const u8) -> u32 {
        unreachable!()
    }
    #[cfg(target_arch = "wasm32")]
    #[link(wasm_import_module = "wasi:sockets/types@0.3.0-rc-2026-03-15")]
    unsafe extern "C" {
        #[link_name = "[future-new-1][method]tcp-socket.send"]
        fn new() -> u64;
        #[link_name = "[future-cancel-write-1][method]tcp-socket.send"]
        fn cancel_write(_: u32) -> u32;
        #[link_name = "[future-cancel-read-1][method]tcp-socket.send"]
        fn cancel_read(_: u32) -> u32;
        #[link_name = "[future-drop-writable-1][method]tcp-socket.send"]
        fn drop_writable(_: u32);
        #[link_name = "[future-drop-readable-1][method]tcp-socket.send"]
        fn drop_readable(_: u32);
        #[link_name = "[async-lower][future-read-1][method]tcp-socket.send"]
        fn start_read(_: u32, _: *mut u8) -> u32;
        #[link_name = "[async-lower][future-write-1][method]tcp-socket.send"]
        fn start_write(_: u32, _: *const u8) -> u32;
    }
    unsafe fn lift(ptr: *mut u8) -> Result<(), super::exports::wasi::sockets::types::ErrorCode> {
        unsafe {
            let l0 = i32::from(*ptr.add(0).cast::<u8>());
            match l0 {
                0 => {
                    let e = ();
                    Ok(e)
                }
                1 => {
                    let e = {
                        let l1 =
                            i32::from(*ptr.add(::core::mem::size_of::<*const u8>()).cast::<u8>());
                        use super::exports::wasi::sockets::types::ErrorCode as V6;
                        let v6 = match l1 {
                            0 => V6::AccessDenied,
                            1 => V6::NotSupported,
                            2 => V6::InvalidArgument,
                            3 => V6::OutOfMemory,
                            4 => V6::Timeout,
                            5 => V6::InvalidState,
                            6 => V6::AddressNotBindable,
                            7 => V6::AddressInUse,
                            8 => V6::RemoteUnreachable,
                            9 => V6::ConnectionRefused,
                            10 => V6::ConnectionBroken,
                            11 => V6::ConnectionReset,
                            12 => V6::ConnectionAborted,
                            13 => V6::DatagramTooLarge,
                            n => {
                                debug_assert_eq!(n, 14, "invalid enum discriminant");
                                let e6 = {
                                    let l2 = i32::from(
                                        *ptr.add(2 * ::core::mem::size_of::<*const u8>())
                                            .cast::<u8>(),
                                    );
                                    match l2 {
                                        0 => None,
                                        1 => {
                                            let e = {
                                                let l3 = *ptr
                                                    .add(3 * ::core::mem::size_of::<*const u8>())
                                                    .cast::<*mut u8>();
                                                let l4 = *ptr
                                                    .add(4 * ::core::mem::size_of::<*const u8>())
                                                    .cast::<usize>();
                                                let len5 = l4;
                                                let bytes5 = super::_rt::Vec::from_raw_parts(
                                                    l3.cast(),
                                                    len5,
                                                    len5,
                                                );
                                                super::_rt::string_lift(bytes5)
                                            };
                                            Some(e)
                                        }
                                        _ => super::_rt::invalid_enum_discriminant(),
                                    }
                                };
                                V6::Other(e6)
                            }
                        };
                        v6
                    };
                    Err(e)
                }
                _ => super::_rt::invalid_enum_discriminant(),
            }
        }
    }
    unsafe fn lower(
        value: Result<(), super::exports::wasi::sockets::types::ErrorCode>,
        ptr: *mut u8,
    ) {
        unsafe {
            match value {
                Ok(_) => {
                    *ptr.add(0).cast::<u8>() = (0i32) as u8;
                }
                Err(e) => {
                    *ptr.add(0).cast::<u8>() = (1i32) as u8;
                    use super::exports::wasi::sockets::types::ErrorCode as V1;
                    match e {
                        V1::AccessDenied => {
                            *ptr.add(::core::mem::size_of::<*const u8>()).cast::<u8>() =
                                (0i32) as u8;
                        }
                        V1::NotSupported => {
                            *ptr.add(::core::mem::size_of::<*const u8>()).cast::<u8>() =
                                (1i32) as u8;
                        }
                        V1::InvalidArgument => {
                            *ptr.add(::core::mem::size_of::<*const u8>()).cast::<u8>() =
                                (2i32) as u8;
                        }
                        V1::OutOfMemory => {
                            *ptr.add(::core::mem::size_of::<*const u8>()).cast::<u8>() =
                                (3i32) as u8;
                        }
                        V1::Timeout => {
                            *ptr.add(::core::mem::size_of::<*const u8>()).cast::<u8>() =
                                (4i32) as u8;
                        }
                        V1::InvalidState => {
                            *ptr.add(::core::mem::size_of::<*const u8>()).cast::<u8>() =
                                (5i32) as u8;
                        }
                        V1::AddressNotBindable => {
                            *ptr.add(::core::mem::size_of::<*const u8>()).cast::<u8>() =
                                (6i32) as u8;
                        }
                        V1::AddressInUse => {
                            *ptr.add(::core::mem::size_of::<*const u8>()).cast::<u8>() =
                                (7i32) as u8;
                        }
                        V1::RemoteUnreachable => {
                            *ptr.add(::core::mem::size_of::<*const u8>()).cast::<u8>() =
                                (8i32) as u8;
                        }
                        V1::ConnectionRefused => {
                            *ptr.add(::core::mem::size_of::<*const u8>()).cast::<u8>() =
                                (9i32) as u8;
                        }
                        V1::ConnectionBroken => {
                            *ptr.add(::core::mem::size_of::<*const u8>()).cast::<u8>() =
                                (10i32) as u8;
                        }
                        V1::ConnectionReset => {
                            *ptr.add(::core::mem::size_of::<*const u8>()).cast::<u8>() =
                                (11i32) as u8;
                        }
                        V1::ConnectionAborted => {
                            *ptr.add(::core::mem::size_of::<*const u8>()).cast::<u8>() =
                                (12i32) as u8;
                        }
                        V1::DatagramTooLarge => {
                            *ptr.add(::core::mem::size_of::<*const u8>()).cast::<u8>() =
                                (13i32) as u8;
                        }
                        V1::Other(e) => {
                            *ptr.add(::core::mem::size_of::<*const u8>()).cast::<u8>() =
                                (14i32) as u8;
                            match e {
                                Some(e) => {
                                    *ptr.add(2 * ::core::mem::size_of::<*const u8>())
                                        .cast::<u8>() = (1i32) as u8;
                                    let vec0 = (e.into_bytes()).into_boxed_slice();
                                    let ptr0 = vec0.as_ptr().cast::<u8>();
                                    let len0 = vec0.len();
                                    ::core::mem::forget(vec0);
                                    *ptr.add(4 * ::core::mem::size_of::<*const u8>())
                                        .cast::<usize>() = len0;
                                    *ptr.add(3 * ::core::mem::size_of::<*const u8>())
                                        .cast::<*mut u8>() = ptr0.cast_mut();
                                }
                                None => {
                                    *ptr.add(2 * ::core::mem::size_of::<*const u8>())
                                        .cast::<u8>() = (0i32) as u8;
                                }
                            };
                        }
                    }
                }
            };
        }
    }
    unsafe fn dealloc_lists(ptr: *mut u8) {
        unsafe {
            let l0 = i32::from(*ptr.add(0).cast::<u8>());
            match l0 {
                0 => {}
                _ => {
                    let l1 = i32::from(*ptr.add(::core::mem::size_of::<*const u8>()).cast::<u8>());
                    match l1 {
                        0 => {}
                        1 => {}
                        2 => {}
                        3 => {}
                        4 => {}
                        5 => {}
                        6 => {}
                        7 => {}
                        8 => {}
                        9 => {}
                        10 => {}
                        11 => {}
                        12 => {}
                        13 => {}
                        _ => {
                            let l2 = i32::from(
                                *ptr.add(2 * ::core::mem::size_of::<*const u8>())
                                    .cast::<u8>(),
                            );
                            match l2 {
                                0 => {}
                                _ => {
                                    let l3 = *ptr
                                        .add(3 * ::core::mem::size_of::<*const u8>())
                                        .cast::<*mut u8>();
                                    let l4 = *ptr
                                        .add(4 * ::core::mem::size_of::<*const u8>())
                                        .cast::<usize>();
                                    super::_rt::cabi_dealloc(l3, l4, 1);
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    pub static VTABLE: wit_bindgen::rt::async_support::FutureVtable<
        Result<(), super::exports::wasi::sockets::types::ErrorCode>,
    > = wit_bindgen::rt::async_support::FutureVtable::<
        Result<(), super::exports::wasi::sockets::types::ErrorCode>,
    > {
        cancel_write,
        cancel_read,
        drop_writable,
        drop_readable,
        dealloc_lists,
        layout: unsafe { ::core::alloc::Layout::from_size_align_unchecked(20, 4) },
        lift,
        lower,
        new,
        start_read,
        start_write,
    };
    impl super::wit_future::FuturePayload
        for Result<(), super::exports::wasi::sockets::types::ErrorCode>
    {
        const VTABLE: &'static wit_bindgen::rt::async_support::FutureVtable<Self> = &VTABLE;
    }
}
