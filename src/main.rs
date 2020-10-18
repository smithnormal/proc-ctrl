use std::env;
use nix::sys::{ptrace, wait};
use nix::sys::signal::Signal;
use nix::sys::wait::WaitPidFlag;
use nix::unistd::Pid;
use std::convert::TryInto;
fn main() {

    let args : Vec<String> = env::args().collect();

    if args.len() < 2 {
	println!("args: {:?}", args);
	panic!("required arg: <target pid>");
    }

    let target_pid : Pid = Pid::from_raw(args[1].parse().unwrap());
    println!("target_pid: {}", target_pid);

    let res = ptrace::attach(target_pid);
    println!("attach: {:?}", res);

    let res = wait::waitpid(target_pid, Some(WaitPidFlag::__WALL));
    println!("waitpid: {:?}", res);

    let regs = ptrace::getregs(target_pid).unwrap();
    println!("regs: {:#?}", regs);

    println!("target pc: {:x}", regs.rip);

    const PAGE_QWORDS : usize = 512;
    let mut saved_code : [std::os::raw::c_long; PAGE_QWORDS] = [0; PAGE_QWORDS];
    let base = regs.rip & !0xfff;

    for i in 0..PAGE_QWORDS {
	let ptr = (base + (i * 8) as u64) as ptrace::AddressType;
	saved_code[i as usize] = ptrace::read(target_pid, ptr).unwrap();
    }

    for i in 0..PAGE_QWORDS {
	println!("{:>016x}", saved_code[i as usize]);
    }

    // first, lets mmap ourselves some memory for code and data.
    //
    // MAP_ANONYMOUS 0x20
    // MAP_PRIVATE 0x2
    // PROT_READ 0x1
    // PROT_WRITE 0x2
    // PROT_EXEC 0x4
    //
    let syscall_code : [u8; 48] = [
	0xb8, libc::SYS_mmap as u8, 0x00, 0x00, 0x00, // mov NR_mmap, %eax
	0xbf, 0x00, 0x00, 0x00, 0x00, // mov 0, %edi
	0xbe, 0x00, 0x00, 0x80, 0x00, // mov 0x800000, %esi
	0xba, 0x07, 0x00, 0x00, 0x00, // mov PROT_READ | PROT_WRITE | PROT_EXEC, %edx
	0x41, 0xba, 0x22, 0x00, 0x00, 0x00, // mov MAP_PRIVATE | MAP_ANONYMOUS, %r10d
	0x41, 0xb8, 0xff, 0xff, 0xff, 0xff, // mov 0x00, %r8d
	0x41, 0xb9, 0x00, 0x00, 0x00, 0x00, // mov 0xffffffff, %r9d
	0x0f, 0x05,			    // syscall
	0xcc, 			    // INT3
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 // padding, todo put return value here
    ];

    for i in 0..6 {
	let start : usize = i * 8;
	let slice : &[u8] = &syscall_code[start..(start + 8)];
	let qword = u64::from_le_bytes(slice.try_into().unwrap());

	unsafe {
	    let res = ptrace::write(target_pid,
				    (base + start as u64) as ptrace::AddressType,
				    qword as * mut libc::c_void);
	    println!("poked data: {:#x?}, {:#?}", slice, res);
	}
    };
    let mut new_regs : libc::user_regs_struct = regs;
    // if we were in a nanosleep, (probably), then the kernel might
    // rewind our pc in order to do restart magic. lets bodge that
    // quickly with a proactive plus 2.
    new_regs.rip = base + 2;
    let res = ptrace::setregs(target_pid, new_regs);
    println!("setregs: {:?}", res);

    let res = ptrace::cont(target_pid, None);
    println!("cont: {:?}", res);

    let res = wait::waitpid(target_pid, Some(WaitPidFlag::__WALL));
    println!("waitpid: {:?}", res);

    let res = ptrace::detach(target_pid, Signal::SIGSTOP);
    println!("detach: {:?}", res);
}
