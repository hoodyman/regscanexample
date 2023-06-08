use core::fmt;
use std::{collections::HashMap, fmt::Debug, fs::File, io::Write};
use windows::core::{HRESULT, PCWSTR, PWSTR};
use windows::Win32::Foundation::{ERROR_NO_DATA, ERROR_NO_MORE_ITEMS, ERROR_SUCCESS};
use windows::Win32::System::Registry::*;

fn hresult_to_string(hr: HRESULT) -> String {
    format!("Error 0x{:x}: {}", hr.0, hr.message().to_string())
}

fn unexpected_error(hr: HRESULT) -> String {
    format!(
        "Unexpected error 0x{:x}: {}",
        hr.0,
        hr.message().to_string()
    )
}

fn open_key(handle: &HKEY, subkey: Option<String>) -> Result<HKEY, String> {
    let mut opened_handle = HKEY::default();
    let opened_handle_ptr: *mut HKEY = &mut opened_handle;
    let err;
    match subkey {
        Some(name) => {
            let mut p0: Vec<u16> = name.encode_utf16().collect();
            p0.push(0);
            let p1 = p0.as_ptr();
            let sub = PCWSTR::from_raw(p1);
            unsafe {
                err = RegOpenKeyExW(*handle, sub, 0, KEY_ALL_ACCESS, opened_handle_ptr);
            }
        }
        None => unsafe {
            err = RegOpenKeyExW(*handle, None, 0, KEY_ALL_ACCESS, opened_handle_ptr);
        },
    };
    if err.is_err() {
        let hresult = err.to_hresult();
        return Err(hresult_to_string(hresult));
    }
    Ok(opened_handle)
}

fn close_key(handle: HKEY) {
    unsafe {
        RegCloseKey(handle);
    }
}

enum TreeOrigin {
    ClassesRoot,
    CurrentConfig,
    CurrentUser,
    LocalMachine,
    Users,
}

#[derive(Debug)]
struct Tree {
    origin: Box<HashMap<String, (HKEY, TreeNode)>>,
}

impl fmt::Display for Tree {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.origin.iter().for_each(|(_, y)| {
            write!(f, "{}", format!("{}", y.1)).unwrap();
        });
        Ok(())
    }
}

impl Tree {
    fn new(origin: &[TreeOrigin]) -> Tree {
        let mut hm = HashMap::new();
        origin.iter().for_each(|x| {
            let (hkey, name) = match x {
                TreeOrigin::ClassesRoot => (HKEY_CLASSES_ROOT, "HKEY_CLASSES_ROOT"),
                TreeOrigin::CurrentConfig => (HKEY_CURRENT_CONFIG, "HKEY_CURRENT_CONFIG"),
                TreeOrigin::CurrentUser => (HKEY_CURRENT_USER, "HKEY_CURRENT_USER"),
                TreeOrigin::LocalMachine => (HKEY_LOCAL_MACHINE, "HKEY_LOCAL_MACHINE"),
                TreeOrigin::Users => (HKEY_USERS, "HKEY_USERS"),
            };
            let tn = TreeNode::new(name.to_owned(), None, 0);
            hm.insert(name.to_owned(), (hkey, tn));
        });
        Tree {
            origin: Box::new(hm),
        }
    }

    fn scan(&mut self, options: &Box<OutputOptions>) {
        let scan_opt = &mut Box::new(ScanOptions::new(options));
        for (_, (hkey, tn)) in self.origin.as_mut() {
            let err = open_key(hkey, None);
            match err {
                Ok(hkey) => {
                    match scan_opt.opt_common.search_keys.as_ref() {
                        Some(v) => {
                            let lowercase_keys = v.iter().map(|k| k.to_lowercase()).collect();
                            scan_opt.opt_common.search_keys = Some(lowercase_keys);
                        }
                        None => (),
                    }
                    tn.scan(hkey, scan_opt);
                    close_key(hkey);

                    match scan_opt.out_file_tree_fd.as_mut() {
                        Some(fd) => {
                            let err = fd.write_all(format!("{}", tn).as_bytes());
                            match err {
                                Err(err) => scan_opt.write_error(err.to_string()),
                                _ => (),
                            }
                        }
                        _ => (),
                    }
                }
                Err(err) => {
                    scan_opt.write_error(err);
                }
            }
        }
    }
}

#[derive(Debug)]
enum RegValue {
    String(String),
    ExpandString(Vec<u8>),
    MultiString(Vec<u8>),
    None(Vec<u8>),
    Binary(Vec<u8>),
    Dword(u32),
    Qword(u64),
    Unknown(u32),
}

type TreeNodeValues = Box<HashMap<String, RegValue>>;

#[derive(Debug)]
struct TreeNode {
    name: String,
    values: TreeNodeValues,
    children: Box<HashMap<String, TreeNode>>,
    parent: Option<*const Self>,
    nested: usize,
}

impl fmt::Display for TreeNode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for _ in (0..self.nested).step_by(1) {
            write!(f, "\t")?;
        }
        write!(f, "\"{}\" {{", self.name)?;

        if self.children.len() != 0 {
            write!(f, "\n")?;
        }

        self.children
            .iter()
            .for_each(|(_, key)| write!(f, "{}", format!("{}", key)).unwrap());

        if self.children.len() != 0 {
            for _ in (0..self.nested).step_by(1) {
                write!(f, "\t")?;
            }
        }
        write!(f, "}}\n")?;
        Ok(())
    }
}

impl TreeNode {
    fn new(name: String, parent: Option<*const Self>, nested: usize) -> TreeNode {
        TreeNode {
            name,
            values: Box::new(HashMap::new()),
            children: Box::new(HashMap::new()),
            parent,
            nested,
        }
    }

    fn scan(&mut self, handle: HKEY, scan_opt: &mut Box<ScanOptions>) {
        let mut err;

        let buffer_size = 32767;

        // common buffer
        let mut buffer = vec![0 as u16; buffer_size];
        let buffer_ptr = buffer.as_mut_ptr();
        let buffer_pwstr = PWSTR::from_raw(buffer_ptr);
        let mut wr_size: u32 = 0;
        let wr_size_ptr: *mut u32 = &mut wr_size;

        // looking for key values and save them as structs        
        for idx in (0..u32::MAX).into_iter() {
            let mut res_type = 0 as u32;
            let res_type_ptr: *mut u32 = &mut res_type;
            let mut value_data_size = 0 as u32;
            let value_data_size_ptr: *mut u32 = &mut value_data_size;
            let mut value_raw_data: Vec<u8> = vec![];
            let mut value_raw_data_ptr: *mut u8 = 0 as *mut u8;
            unsafe {
                wr_size = buffer_size as u32;
                err = RegEnumValueW(
                    handle,
                    idx,
                    buffer_pwstr,
                    wr_size_ptr,
                    None,
                    None,
                    None,
                    Some(value_data_size_ptr),
                );
                if err.is_ok() {
                    value_raw_data = vec![0 as u8; value_data_size as usize];
                    value_raw_data_ptr = value_raw_data.as_mut_ptr();
                    wr_size = buffer_size as u32;
                    err = RegEnumValueW(
                        handle,
                        idx,
                        buffer_pwstr,
                        wr_size_ptr,
                        None,
                        Some(res_type_ptr),
                        Some(value_raw_data_ptr),
                        Some(value_data_size_ptr),
                    );
                }
            }
            match err {
                ERROR_SUCCESS => {
                    let buffer_slice = &buffer[0..wr_size as usize];
                    let value_name = String::from_utf16(buffer_slice).unwrap();
                    let value_data: RegValue;
                    if !value_name.is_empty() {
                        match REG_VALUE_TYPE(res_type) {
                            REG_BINARY => {
                                let x = value_raw_data[0..value_data_size as usize].to_vec();
                                value_data = RegValue::Binary(x);
                            }
                            REG_DWORD => unsafe {
                                value_data = RegValue::Dword(*(value_raw_data_ptr as *const u32));
                            },
                            REG_QWORD => unsafe {
                                value_data = RegValue::Qword(*(value_raw_data_ptr as *const u64));
                            },
                            REG_SZ => {
                                if value_data_size == 0 {
                                    value_data = RegValue::String("".to_owned());
                                } else {
                                    let y: Vec<u16> = value_raw_data
                                        .chunks_exact(2)
                                        .into_iter()
                                        .map(|x| u16::from_ne_bytes([x[0], x[1]]))
                                        .collect();
                                    let z = String::from_utf16(
                                        &y[0..(value_data_size / 2 - 1) as usize],
                                    )
                                    .unwrap();
                                    value_data = RegValue::String(z);
                                }
                            }
                            REG_NONE => {
                                let x = value_raw_data[0..value_data_size as usize].to_vec();
                                value_data = RegValue::None(x);
                            }
                            REG_EXPAND_SZ => {
                                let x = value_raw_data[0..value_data_size as usize].to_vec();
                                value_data = RegValue::ExpandString(x);
                            }
                            REG_MULTI_SZ => {
                                let x = value_raw_data[0..value_data_size as usize].to_vec();
                                value_data = RegValue::MultiString(x);
                            }
                            unknown => {
                                scan_opt.write_error(format!(
                                    "{} -> Unknown value type ({}), name \"{}\"",
                                    self.make_path_string(true),
                                    unknown.0,
                                    value_name
                                ));
                                value_data = RegValue::Unknown(unknown.0);
                            }
                        }
                        self.values.insert(value_name, value_data);
                    }
                }
                ERROR_NO_MORE_ITEMS => break,
                ERROR_NO_DATA => {
                    panic!(
                        "{}: buffer size {}",
                        err.to_hresult().message().to_string(),
                        buffer_size
                    )
                }
                _ => panic!("{}", unexpected_error(err.to_hresult())),
            }
        }

        // function save found keys and its values
        let s = format!("{}", self.make_path_string(true));
        let f = |scan_opt: &mut Box<ScanOptions>, s: String, values: &TreeNodeValues| {
            scan_opt.write_key(s);
            scan_opt.write_key("".to_owned());
            if values.len() != 0 {
                for (value_name, value_type_val) in values.iter() {
                    let second_part = match value_type_val {
                        RegValue::Binary(value) => {
                            let mut s = "hex:".to_owned();
                            for idx in (0..value.len()).step_by(1) {
                                s += format!("{:02x}", value[idx]).as_str();
                                if idx < value.len() - 1 {
                                    s += ",";
                                }
                            }
                            s
                        }
                        RegValue::Dword(value) => format!("dword:{:08x}", value),
                        RegValue::Qword(value) => {
                            let mut s = "hex(b):".to_owned();
                            let x1 = value.to_ne_bytes();
                            for idx in (0..x1.len()).step_by(1) {
                                s += format!("{:02x}", x1[idx]).as_str();
                                if idx < x1.len() - 1 {
                                    s += ",";
                                }
                            }
                            s
                        }
                        RegValue::String(value) => format!("\"{}\"", value),
                        RegValue::None(value) => {
                            let mut s = "hex(0):".to_owned();
                            for idx in (0..value.len()).step_by(1) {
                                s += format!("{:02x}", value[idx]).as_str();
                                if idx < value.len() - 1 {
                                    s += ",";
                                }
                            }
                            s
                        }
                        RegValue::ExpandString(value) => {
                            let mut s = "hex(2):".to_owned();
                            for idx in (0..value.len()).step_by(1) {
                                s += format!("{:02x}", value[idx]).as_str();
                                if idx < value.len() - 1 {
                                    s += ",";
                                }
                            }
                            s
                        }
                        RegValue::MultiString(value) => {
                            let mut s = "hex(7):".to_owned();
                            for idx in (0..value.len()).step_by(1) {
                                s += format!("{:02x}", value[idx]).as_str();
                                if idx < value.len() - 1 {
                                    s += ",";
                                }
                            }
                            s
                        }
                        RegValue::Unknown(id) => format!("Unknown({})", id),
                    };
                    scan_opt.write_key(format!("\"{}\"={}", value_name, second_part));
                }
                scan_opt.write_key("".to_owned());
            }
        };

        // save found keys respectively opt
        match scan_opt.opt_common.search_keys.as_ref() {
            Some(key) => match scan_opt.opt_common.search_op.as_ref() {
                Some(op) => {
                    let lower_s = s.to_lowercase();
                    match op {
                        KeyOp::And => {
                            let mut counter = 0;
                            for k in key {
                                if lower_s.contains(k) {
                                    counter += 1;
                                }
                            }
                            if counter == key.len() {
                                f(scan_opt, s, &self.values);
                            }
                        }
                        KeyOp::Or => {
                            for k in key {
                                if lower_s.contains(k) {
                                    f(scan_opt, s, &self.values);
                                    break;
                                }
                            }
                        }
                    };
                }
                None => (),
            },
            None => f(scan_opt, s, &self.values),
        }

        // looking for new keys
        for idx in (0..u32::MAX).into_iter() {
            wr_size = buffer_size as u32;
            unsafe {
                err = RegEnumKeyExW(
                    handle,
                    idx,
                    buffer_pwstr,
                    wr_size_ptr,
                    None,
                    PWSTR::null(),
                    None,
                    None,
                );
            }
            match err {
                ERROR_SUCCESS => {
                    let buffer_slice = &buffer[0..wr_size as usize];
                    let name = String::from_utf16(buffer_slice).unwrap();
                    let new_key =
                        TreeNode::new(name.to_owned(), Some(self as *const Self), self.nested + 1);
                    self.children.insert(name, new_key);
                }
                ERROR_NO_MORE_ITEMS => break,
                ERROR_NO_DATA => {
                    panic!(
                        "{}: buffer size {}",
                        err.to_hresult().message().to_string(),
                        buffer_size
                    )
                }
                _ => panic!("{}", unexpected_error(err.to_hresult())),
            }
        }

        // repeat recursively for scan
        for (name, key) in self.children.iter_mut() {
            let result = open_key(&handle, Some(name.to_owned()));
            match result {
                Ok(handle) => {
                    key.scan(handle, scan_opt);
                    close_key(handle);
                }
                Err(err) => {
                    scan_opt.write_error(format!("{} -> {}", key.make_path_string(true), err));
                }
            }
        }
    }

    fn make_path_string(&self, leader: bool) -> String {
        let trail = match self.parent {
            Some(raw_ptr) => {
                let r;
                unsafe {
                    r = raw_ptr.as_ref();
                }
                r.unwrap().make_path_string(false)
            }
            None => "".to_owned(),
        };
        let t = match trail.is_empty() {
            true => "[".to_owned() + self.name.as_str(),
            false => trail + "\\" + self.name.as_str(),
        } + match leader {
            true => "]",
            false => "",
        };
        t
    }
}

#[derive(Clone)]
enum KeyOp {
    And,
    Or,
}

#[derive(Clone)]
struct OptCommon {
    output_errors_to_console: bool,
    search_keys: Option<Vec<String>>,
    search_op: Option<KeyOp>,
}

struct OutputOptions {
    out_file_tree_name: Option<String>,
    out_file_keys_name: Option<String>,
    out_file_log_name: Option<String>,
    opt_common: Option<OptCommon>,
}

struct ScanOptions {
    out_file_tree_fd: Option<File>,
    out_file_keys_fd: Option<File>,
    out_file_error_log_fd: Option<File>,
    opt_common: OptCommon,
}

impl ScanOptions {
    fn new(opt: &Box<OutputOptions>) -> ScanOptions {
        let mut so = ScanOptions {
            out_file_tree_fd: None,
            out_file_keys_fd: None,
            out_file_error_log_fd: None,
            opt_common: match opt.opt_common.as_ref() {
                Some(opt) => opt.clone(),
                None => OptCommon {
                    output_errors_to_console: true,
                    search_keys: None,
                    search_op: None,
                },
            },
        };

        match opt.out_file_log_name.as_ref() {
            Some(path) => {
                let err = File::create(path);
                match err {
                    Ok(fd) => so.out_file_error_log_fd = Some(fd),
                    Err(err) => so._log_error_to_console(err.to_string()),
                }
            }
            None => (),
        }
        match opt.out_file_keys_name.as_ref() {
            Some(path) => {
                let err = File::create(path);
                match err {
                    Ok(fd) => so.out_file_keys_fd = Some(fd),
                    Err(err) => so.write_error(err.to_string()),
                }
            }
            None => (),
        }
        match opt.out_file_tree_name.as_ref() {
            Some(path) => {
                let err = File::create(path);
                match err {
                    Ok(fd) => so.out_file_tree_fd = Some(fd),
                    Err(err) => so.write_error(err.to_string()),
                }
            }
            None => (),
        }

        so
    }

    fn _log_error_to_console(&self, text: String) {
        if self.opt_common.output_errors_to_console {
            println!("{}", text);
        }
    }

    fn write_error(&mut self, text: String) {
        match self.out_file_error_log_fd.as_mut() {
            Some(fd) => match fd.write((text.to_owned() + "\n").as_bytes()) {
                Err(err) => self._log_error_to_console(err.to_string()),
                _ => (),
            },
            None => (),
        }
        self._log_error_to_console(text);
    }

    fn write_key(&mut self, key_path: String) {
        let err = self
            .out_file_keys_fd
            .as_mut()
            .unwrap()
            .write((key_path + "\n").as_bytes());
        match err {
            Err(err) => self.write_error(err.to_string()),
            _ => (),
        }
    }
}

fn main() {
    fn print_help() {
        println!("-p Output files prefix");
        println!("Can be one of this:");
        println!("\t-sa Key words search by AND");
        println!("\t-so Key words search by OR");
        println!("-h This help");
    }

    let p = "-p out -sa ubuntu".to_string();

    let mut prefix = String::default();
    let mut op = None;
    let mut words = None;

    let x_args = p.split("-");
    x_args.into_iter().for_each(|x| {
        if x.len() != 0 {
            let x_p = x.split(" ");
            let mut v = vec![];
            x_p.into_iter().for_each(|x| {
                if x.len() != 0 {
                    v.push(x);
                }
            });
            match v[0] {
                "p" => {
                    prefix = match v.get(1) {
                        Some(p) => p.to_string() + ".",
                        None => "".to_owned(),
                    };
                }
                "sa" => {
                    op = Some(KeyOp::And);
                    words = Some(v[1..].into_iter().map(|x| x.to_string()).collect());
                }
                "so" => {
                    op = Some(KeyOp::Or);
                    words = Some(v[1..].into_iter().map(|x| x.to_string()).collect());
                }
                "h" => {
                    print_help();
                }
                _ => {
                    println!("Unknown argument {}", v[0]);
                    print_help();
                    return;
                }
            }
        }
    });

    let opt = &Box::new(OutputOptions {
        out_file_keys_name: Some(prefix.to_owned() + "out.keys.txt"),
        out_file_log_name: Some(prefix.to_owned() + "out.error.txt"),
        out_file_tree_name: Some(prefix.to_owned() + "out.tree.txt"),
        opt_common: Some(OptCommon {
            output_errors_to_console: true,
            search_keys: words,
            search_op: op,
        }),
    });

    println!("BEGIN SCAN REGISTRY");
    let mut tree = Tree::new(&[
        TreeOrigin::ClassesRoot,
        TreeOrigin::CurrentConfig,
        TreeOrigin::CurrentUser,
        TreeOrigin::LocalMachine,
        TreeOrigin::Users,
    ]);
    tree.scan(opt);
    println!("END");
}
