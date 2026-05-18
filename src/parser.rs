use crate::errors::ScanError;
use crate::types::{ClassDetails, ConstantPoolEntry, FieldInfo, MethodCallInfo, MethodInfo};
use byteorder::{BigEndian, ReadBytesExt};
use colored::Colorize;
use encoding_rs::UTF_8;
use std::collections::{HashSet, VecDeque};
use std::io::{Cursor, Seek, SeekFrom};

#[inline]
fn check_bounds(
    cursor: &Cursor<&[u8]>,
    needed: u64,
    path: &str,
    context: &str,
) -> Result<(), ScanError> {
    let current_pos = cursor.position();
    let data_len = cursor.get_ref().len() as u64;
    if current_pos + needed > data_len {
        Err(ScanError::ClassParseError {
            path: path.to_string(),
            msg: format!(
                "EOF Error: Needed {} bytes for '{}' at pos {}, but only {} bytes remain (total len {})",
                needed,
                context,
                current_pos,
                data_len.saturating_sub(current_pos),
                data_len
            ),
        })
    } else {
        Ok(())
    }
}

fn resolve_utf8<'a>(
    pool: &'a [ConstantPoolEntry],
    index: u16,
    path: &str,
) -> Result<&'a str, ScanError> {
    if index == 0 || (index as usize) > pool.len() {
        return Err(ScanError::ClassParseError {
            path: path.to_string(),
            msg: "Invalid CP index".to_string(),
        });
    }

    match &pool[index as usize - 1] {
        ConstantPoolEntry::Utf8(s) => Ok(s),
        _ => Err(ScanError::ClassParseError {
            path: path.to_string(),
            msg: "Expected UTF8".to_string(),
        }),
    }
}

fn resolve_class_name(
    pool: &[ConstantPoolEntry],
    index: u16,
    path: &str,
    context: &str,
) -> Result<String, ScanError> {
    if index == 0 {
        if context == "super_class" {
            return Ok("java/lang/Object".to_string());
        }

        return Err(ScanError::ClassParseError {
            path: path.to_string(),
            msg: format!("Invalid CP index 0 for class reference ('{}')", context),
        });
    }

    if (index as usize) > pool.len() {
        return Err(ScanError::ClassParseError {
            path: path.to_string(),
            msg: format!(
                "Invalid CP index {} (0-based) for Class resolve ('{}'). Pool size: {}.",
                index,
                context,
                pool.len()
            ),
        });
    }

    match &pool[index as usize - 1] {
        ConstantPoolEntry::Class(name_index) => {
            Ok(resolve_utf8(pool, *name_index, path)?.to_string())
        }
        other => Err(ScanError::ClassParseError {
            path: path.to_string(),
            msg: format!(
                "Expected Class info at CP index {} ('{}'), found {:?}",
                index, context, other
            ),
        }),
    }
}

fn parse_members<T, F>(
    cursor: &mut Cursor<&[u8]>,
    count: u16,
    file_path_str: &str,
    verbose: bool,
    member_kind: &str,
    pool: &[ConstantPoolEntry],
    make_member: F,
) -> Result<Vec<T>, ScanError>
where
    F: Fn(String, String, u16) -> T,
{
    let mut members = Vec::with_capacity(count as usize);
    let invalid_name_prefix = match member_kind {
        "field" => "INVALID_FIELD_NAME_INDEX",
        "method" => "INVALID_METHOD_NAME_INDEX",
        _ => "INVALID_MEMBER_NAME_INDEX",
    };

    for index in 0..count {
        check_bounds(
            cursor,
            8,
            file_path_str,
            &format!("{} header {}", member_kind, index),
        )?;
        let access_flags = cursor.read_u16::<BigEndian>()?;
        let name_index = cursor.read_u16::<BigEndian>()?;
        let descriptor_index = cursor.read_u16::<BigEndian>()?;
        let attributes_count = cursor.read_u16::<BigEndian>()?;

        let name = resolve_utf8(pool, name_index, file_path_str)
            .map(str::to_string)
            .unwrap_or_else(|e| {
                if verbose {
                    eprintln!("(!) {} name resolution error: {}", member_kind, e);
                }
                format!("<{}_{}>", invalid_name_prefix, name_index)
            });

        let descriptor = resolve_utf8(pool, descriptor_index, file_path_str)
            .map(str::to_string)
            .unwrap_or_else(|e| {
                if verbose {
                    eprintln!("(!) {} descriptor resolution error: {}", member_kind, e);
                }
                format!("<INVALID_DESCRIPTOR_INDEX_{}>", descriptor_index)
            });

        skip_attributes(cursor, attributes_count, file_path_str)?;
        members.push(make_member(name, descriptor, access_flags));
    }

    Ok(members)
}

fn resolve_name_and_type(
    pool: &[ConstantPoolEntry],
    index: u16,
    path: &str,
) -> Result<(String, String), ScanError> {
    if index == 0 || (index as usize) > pool.len() {
        return Err(ScanError::ClassParseError {
            path: path.to_string(),
            msg: format!("Invalid NameAndType index {}", index),
        });
    }

    match &pool[index as usize - 1] {
        ConstantPoolEntry::NameAndType(name_index, descriptor_index) => Ok((
            resolve_utf8(pool, *name_index, path)?.to_string(),
            resolve_utf8(pool, *descriptor_index, path)?.to_string(),
        )),
        other => Err(ScanError::ClassParseError {
            path: path.to_string(),
            msg: format!(
                "Expected NameAndType at CP index {}, found {:?}",
                index, other
            ),
        }),
    }
}

fn resolve_method_ref(
    pool: &[ConstantPoolEntry],
    index: u16,
    path: &str,
) -> Result<(String, String, String), ScanError> {
    if index == 0 || (index as usize) > pool.len() {
        return Err(ScanError::ClassParseError {
            path: path.to_string(),
            msg: format!("Invalid method reference index {}", index),
        });
    }

    match &pool[index as usize - 1] {
        ConstantPoolEntry::Methodref(class_index, name_type_index)
        | ConstantPoolEntry::InterfaceMethodref(class_index, name_type_index) => {
            let owner = resolve_class_name(pool, *class_index, path, "method_ref_owner")?;
            let (name, descriptor) = resolve_name_and_type(pool, *name_type_index, path)?;
            Ok((owner, name, descriptor))
        }
        other => Err(ScanError::ClassParseError {
            path: path.to_string(),
            msg: format!(
                "Expected Methodref at CP index {}, found {:?}",
                index, other
            ),
        }),
    }
}

fn resolve_ldc_string(
    pool: &[ConstantPoolEntry],
    index: u16,
    path: &str,
) -> Result<Option<String>, ScanError> {
    if index == 0 || (index as usize) > pool.len() {
        return Err(ScanError::ClassParseError {
            path: path.to_string(),
            msg: format!("Invalid LDC index {}", index),
        });
    }

    match &pool[index as usize - 1] {
        ConstantPoolEntry::String(utf8_index) => {
            Ok(Some(resolve_utf8(pool, *utf8_index, path)?.to_string()))
        }
        _ => Ok(None),
    }
}

fn read_u32_at(code: &[u8], offset: usize) -> Result<u32, ScanError> {
    if offset + 4 > code.len() {
        return Err(ScanError::ClassParseError {
            path: "<bytecode>".to_string(),
            msg: format!("Unexpected EOF while reading bytecode at offset {}", offset),
        });
    }

    Ok(u32::from_be_bytes([
        code[offset],
        code[offset + 1],
        code[offset + 2],
        code[offset + 3],
    ]))
}

fn bytecode_instruction_length(code: &[u8], pc: usize) -> Result<usize, ScanError> {
    let opcode = code[pc];
    Ok(match opcode {
        0x10 | 0x12 => 2,
        0x11 | 0x13 | 0x14 => 3,
        0x15..=0x19 | 0x36..=0x3A => 2,
        0x84 => 3,
        0x99..=0xA8 => 3,
        0xA9 => 2,
        0xAA => {
            let pad = (4 - ((pc + 1) % 4)) % 4;
            let base = pc + 1 + pad;
            let low = read_u32_at(code, base + 4)?;
            let high = read_u32_at(code, base + 8)?;
            let entries = high.saturating_sub(low).saturating_add(1) as usize;
            1 + pad + 12 + entries * 4
        }
        0xAB => {
            let pad = (4 - ((pc + 1) % 4)) % 4;
            let base = pc + 1 + pad;
            let pairs = read_u32_at(code, base + 4)? as usize;
            1 + pad + 8 + pairs * 8
        }
        0xAC..=0xB1 => 1,
        0xB2..=0xB8 => 3,
        0xB9 | 0xBA => 5,
        0xBB => 3,
        0xBC => 2,
        0xBD => 3,
        0xBE..=0xC3 => 1,
        0xC4 => {
            if pc + 1 >= code.len() {
                return Err(ScanError::ClassParseError {
                    path: "<bytecode>".to_string(),
                    msg: format!("Unexpected EOF while reading wide opcode at offset {}", pc),
                });
            }

            match code[pc + 1] {
                0x15..=0x19 | 0x36..=0x3A | 0xA9 => 4,
                0x84 => 6,
                other => {
                    return Err(ScanError::ClassParseError {
                        path: "<bytecode>".to_string(),
                        msg: format!("Unsupported wide opcode {:02X} at offset {}", other, pc),
                    })
                }
            }
        }
        0xC5 => 4,
        0xC6 | 0xC7 => 3,
        0xC8 | 0xC9 => 5,
        0xCA => 1,
        0x00..=0x0F | 0x1A..=0x35 | 0x3B..=0x83 | 0x85..=0x98 => 1,
        other => {
            return Err(ScanError::ClassParseError {
                path: "<bytecode>".to_string(),
                msg: format!("Unsupported opcode {:02X} at offset {}", other, pc),
            })
        }
    })
}

fn push_recent_string(recent_strings: &mut VecDeque<String>, value: String) {
    recent_strings.push_back(value);
    while recent_strings.len() > 6 {
        recent_strings.pop_front();
    }
}

fn parse_method_invocations(
    code: &[u8],
    pool: &[ConstantPoolEntry],
    file_path_str: &str,
) -> Result<Vec<MethodCallInfo>, ScanError> {
    let mut invocations = Vec::new();
    let mut recent_strings = VecDeque::new();
    let mut pc = 0usize;

    while pc < code.len() {
        let opcode = code[pc];
        match opcode {
            0x12 => {
                if pc + 1 >= code.len() {
                    return Err(ScanError::ClassParseError {
                        path: file_path_str.to_string(),
                        msg: format!("Unexpected EOF while reading ldc at offset {}", pc),
                    });
                }

                let index = code[pc + 1] as u16;
                if let Some(value) = resolve_ldc_string(pool, index, file_path_str)? {
                    push_recent_string(&mut recent_strings, value);
                }
            }
            0x13 => {
                if pc + 2 >= code.len() {
                    return Err(ScanError::ClassParseError {
                        path: file_path_str.to_string(),
                        msg: format!("Unexpected EOF while reading ldc_w at offset {}", pc),
                    });
                }

                let index = u16::from_be_bytes([code[pc + 1], code[pc + 2]]);
                if let Some(value) = resolve_ldc_string(pool, index, file_path_str)? {
                    push_recent_string(&mut recent_strings, value);
                }
            }
            0xB6..=0xB9 => {
                let index = if opcode == 0xB9 {
                    if pc + 4 >= code.len() {
                        return Err(ScanError::ClassParseError {
                            path: file_path_str.to_string(),
                            msg: format!(
                                "Unexpected EOF while reading invokeinterface at offset {}",
                                pc
                            ),
                        });
                    }

                    u16::from_be_bytes([code[pc + 1], code[pc + 2]])
                } else {
                    if pc + 2 >= code.len() {
                        return Err(ScanError::ClassParseError {
                            path: file_path_str.to_string(),
                            msg: format!("Unexpected EOF while reading invoke at offset {}", pc),
                        });
                    }

                    u16::from_be_bytes([code[pc + 1], code[pc + 2]])
                };

                if let Ok((owner, name, descriptor)) =
                    resolve_method_ref(pool, index, file_path_str)
                {
                    invocations.push(MethodCallInfo {
                        owner,
                        name,
                        descriptor,
                        arguments: recent_strings.iter().cloned().collect(),
                    });
                }
            }
            0xBA if pc + 4 >= code.len() => {
                return Err(ScanError::ClassParseError {
                    path: file_path_str.to_string(),
                    msg: format!(
                        "Unexpected EOF while reading invokedynamic at offset {}",
                        pc
                    ),
                });
            }
            0xBA => {}
            _ => {}
        }

        let length = bytecode_instruction_length(code, pc)?;
        pc += length;
    }

    Ok(invocations)
}

fn parse_methods(
    cursor: &mut Cursor<&[u8]>,
    count: u16,
    file_path_str: &str,
    verbose: bool,
    pool: &[ConstantPoolEntry],
) -> Result<(Vec<MethodInfo>, Vec<MethodCallInfo>), ScanError> {
    let mut members = Vec::with_capacity(count as usize);
    let mut method_calls = Vec::new();

    for index in 0..count {
        check_bounds(
            cursor,
            8,
            file_path_str,
            &format!("method header {}", index),
        )?;
        let access_flags = cursor.read_u16::<BigEndian>()?;
        let name_index = cursor.read_u16::<BigEndian>()?;
        let descriptor_index = cursor.read_u16::<BigEndian>()?;
        let attributes_count = cursor.read_u16::<BigEndian>()?;

        let name = resolve_utf8(pool, name_index, file_path_str)
            .map(str::to_string)
            .unwrap_or_else(|e| {
                if verbose {
                    eprintln!("(!) method name resolution error: {}", e);
                }
                format!("<INVALID_METHOD_NAME_INDEX_{}>", name_index)
            });

        let descriptor = resolve_utf8(pool, descriptor_index, file_path_str)
            .map(str::to_string)
            .unwrap_or_else(|e| {
                if verbose {
                    eprintln!("(!) method descriptor resolution error: {}", e);
                }
                format!("<INVALID_DESCRIPTOR_INDEX_{}>", descriptor_index)
            });

        for _ in 0..attributes_count {
            check_bounds(cursor, 6, file_path_str, "method attribute header")?;
            let attribute_name_index = cursor.read_u16::<BigEndian>()?;
            let attribute_length = cursor.read_u32::<BigEndian>()? as u64;
            let attribute_name = resolve_utf8(pool, attribute_name_index, file_path_str)
                .map(str::to_string)
                .unwrap_or_default();

            if attribute_name == "Code" {
                check_bounds(
                    cursor,
                    attribute_length,
                    file_path_str,
                    "Code attribute body",
                )?;
                let code_start = cursor.position() as usize;
                let code_slice = cursor.get_ref();
                if code_start + attribute_length as usize > code_slice.len() {
                    return Err(ScanError::ClassParseError {
                        path: file_path_str.to_string(),
                        msg: format!("Code attribute overruns buffer at offset {}", code_start),
                    });
                }

                let mut code_cursor =
                    Cursor::new(&code_slice[code_start..code_start + attribute_length as usize]);
                check_bounds(&code_cursor, 8, file_path_str, "Code attribute header")?;
                let _max_stack = code_cursor.read_u16::<BigEndian>()?;
                let _max_locals = code_cursor.read_u16::<BigEndian>()?;
                let code_length = code_cursor.read_u32::<BigEndian>()? as usize;
                check_bounds(
                    &code_cursor,
                    code_length as u64,
                    file_path_str,
                    "bytecode body",
                )?;
                let bytecode_start = code_cursor.position() as usize;
                let bytecode_end = bytecode_start + code_length;
                let bytecode = &code_cursor.get_ref()[bytecode_start..bytecode_end];

                let calls = parse_method_invocations(bytecode, pool, file_path_str)?;
                method_calls.extend(calls);

                code_cursor.seek(SeekFrom::Current(code_length as i64))?;
                check_bounds(
                    &code_cursor,
                    8,
                    file_path_str,
                    "Code exception table header",
                )?;
                let exception_table_length = code_cursor.read_u16::<BigEndian>()?;
                code_cursor.seek(SeekFrom::Current((exception_table_length as i64) * 8))?;
                check_bounds(
                    &code_cursor,
                    2,
                    file_path_str,
                    "Code nested attributes count",
                )?;
                let nested_attributes_count = code_cursor.read_u16::<BigEndian>()?;
                skip_attributes(&mut code_cursor, nested_attributes_count, file_path_str)?;

                cursor.seek(SeekFrom::Current(attribute_length as i64))?;
            } else {
                check_bounds(
                    cursor,
                    attribute_length,
                    file_path_str,
                    "method attribute body",
                )?;
                cursor.seek(SeekFrom::Current(attribute_length as i64))?;
            }
        }

        members.push(MethodInfo {
            name,
            descriptor,
            access_flags,
        });
    }

    Ok((members, method_calls))
}

fn parse_constant_pool(
    cursor: &mut Cursor<&[u8]>,
    cp_count: u16,
    file_path_str: &str,
) -> Result<Vec<ConstantPoolEntry>, ScanError> {
    if cp_count == 0 {
        return Err(ScanError::ClassParseError {
            path: file_path_str.to_string(),
            msg: format!("Invalid constant pool count: {}", cp_count),
        });
    }
    if cp_count == 1 {
        return Ok(Vec::new());
    }

    let capacity = cp_count as usize - 1;
    let mut constant_pool = Vec::with_capacity(capacity);
    let mut i = 1;

    while i < cp_count {
        check_bounds(cursor, 1, file_path_str, "CP tag read")?;
        let tag = cursor.read_u8()?;

        let entry_slots: u16 = match tag {
            1 => {
                check_bounds(cursor, 2, file_path_str, "UTF8 length")?;
                let length = cursor.read_u16::<BigEndian>()? as usize;
                let current_pos = cursor.position() as usize;
                let end_pos = current_pos + length;
                let data = cursor.get_ref();

                if end_pos > data.len() {
                    return Err(ScanError::ClassParseError {
                        path: file_path_str.to_string(),
                        msg: format!(
                            "EOF reading UTF8 data: index {}, length {}, pos {}, data len {}",
                            i,
                            length,
                            current_pos,
                            data.len()
                        ),
                    });
                }

                let utf8_bytes = &data[current_pos..end_pos];
                let (cow, _encoding_used, _) = UTF_8.decode(utf8_bytes);

                constant_pool.push(ConstantPoolEntry::Utf8(cow.into()));
                cursor.seek(SeekFrom::Current(length as i64))?;
                1
            }

            3 | 4 => {
                check_bounds(cursor, 4, file_path_str, "Integer/Float data")?;
                constant_pool.push(if tag == 3 {
                    ConstantPoolEntry::Integer
                } else {
                    ConstantPoolEntry::Float
                });
                cursor.seek(SeekFrom::Current(4))?;
                1
            }

            5 | 6 => {
                check_bounds(cursor, 8, file_path_str, "Long/Double data")?;

                constant_pool.push(if tag == 5 {
                    ConstantPoolEntry::Long
                } else {
                    ConstantPoolEntry::Double
                });
                cursor.seek(SeekFrom::Current(8))?;
                constant_pool.push(ConstantPoolEntry::Placeholder);
                2
            }

            7 => {
                check_bounds(cursor, 2, file_path_str, "Class index")?;
                constant_pool.push(ConstantPoolEntry::Class(cursor.read_u16::<BigEndian>()?));
                1
            }

            8 => {
                check_bounds(cursor, 2, file_path_str, "String index")?;
                constant_pool.push(ConstantPoolEntry::String(cursor.read_u16::<BigEndian>()?));
                1
            }

            9..=11 => {
                check_bounds(
                    cursor,
                    4,
                    file_path_str,
                    "Field/Method/Interface ref indices",
                )?;
                let index1 = cursor.read_u16::<BigEndian>()?;
                let index2 = cursor.read_u16::<BigEndian>()?;
                constant_pool.push(match tag {
                    9 => ConstantPoolEntry::Fieldref(index1, index2),
                    10 => ConstantPoolEntry::Methodref(index1, index2),
                    11 => ConstantPoolEntry::InterfaceMethodref(index1, index2),
                    _ => unreachable!(),
                });
                1
            }

            12 => {
                check_bounds(cursor, 4, file_path_str, "NameAndType indices")?;
                let index1 = cursor.read_u16::<BigEndian>()?;
                let index2 = cursor.read_u16::<BigEndian>()?;
                constant_pool.push(ConstantPoolEntry::NameAndType(index1, index2));
                1
            }

            15 => {
                check_bounds(cursor, 3, file_path_str, "MethodHandle data")?;
                constant_pool.push(ConstantPoolEntry::MethodHandle);
                cursor.seek(SeekFrom::Current(3))?;
                1
            }

            16 => {
                check_bounds(cursor, 2, file_path_str, "MethodType index")?;
                constant_pool.push(ConstantPoolEntry::MethodType);
                cursor.seek(SeekFrom::Current(2))?;
                1
            }

            17 | 18 => {
                check_bounds(cursor, 4, file_path_str, "Dynamic/InvokeDynamic data")?;
                constant_pool.push(if tag == 17 {
                    ConstantPoolEntry::Dynamic
                } else {
                    ConstantPoolEntry::InvokeDynamic
                });
                cursor.seek(SeekFrom::Current(4))?;
                1
            }

            19 | 20 => {
                check_bounds(cursor, 2, file_path_str, "Module/Package index")?;
                constant_pool.push(if tag == 19 {
                    ConstantPoolEntry::Module
                } else {
                    ConstantPoolEntry::Package
                });
                cursor.seek(SeekFrom::Current(2))?;
                1
            }
            _ => {
                return Err(ScanError::ClassParseError {
                    path: file_path_str.to_string(),
                    msg: format!("Unknown or unsupported CP tag {} at index {}", tag, i),
                });
            }
        };

        i += entry_slots;
    }

    if constant_pool.len() != capacity {
        eprintln!(
            "{} Warning: Constant pool size mismatch for '{}'. Parsed {} entries, expected capacity {}. File might be corrupt or parser logic error.",
            "!".yellow(),
            file_path_str,
            constant_pool.len(),
            capacity
        );
    }

    Ok(constant_pool)
}

fn skip_attributes(
    cursor: &mut Cursor<&[u8]>,
    attributes_count: u16,
    file_path_str: &str,
) -> Result<(), ScanError> {
    for _ in 0..attributes_count {
        check_bounds(cursor, 6, file_path_str, "attribute header")?;
        let _attribute_name_index = cursor.read_u16::<BigEndian>()?;
        let attribute_length = cursor.read_u32::<BigEndian>()? as u64;

        check_bounds(
            cursor,
            attribute_length,
            file_path_str,
            &format!("attribute data (len {})", attribute_length),
        )?;

        cursor.seek(SeekFrom::Current(attribute_length as i64))?;
    }
    Ok(())
}

pub fn parse_class_structure(
    data: &[u8],
    original_path_str: &str,
    verbose: bool,
) -> Result<ClassDetails, ScanError> {
    let mut cursor = Cursor::new(data);

    if data.len() < 10 {
        return Err(ScanError::ClassParseError {
            path: original_path_str.to_string(),
            msg: "File too small for valid class header".to_string(),
        });
    }

    let magic = cursor.read_u32::<BigEndian>()?;
    if magic != 0xCAFEBABE {
        return Err(ScanError::ClassParseError {
            path: original_path_str.to_string(),
            msg: format!(
                "Invalid magic number: Expected 0xCAFEBABE, found {:#X}",
                magic
            ),
        });
    }
    let _minor_version = cursor.read_u16::<BigEndian>()?;
    let _major_version = cursor.read_u16::<BigEndian>()?;
    let cp_count = cursor.read_u16::<BigEndian>()?;
    if cp_count == 0 {
        return Err(ScanError::ClassParseError {
            path: original_path_str.to_string(),
            msg: "Invalid constant pool count: 0".to_string(),
        });
    }

    let constant_pool = parse_constant_pool(&mut cursor, cp_count, original_path_str)?;

    check_bounds(
        &cursor,
        6,
        original_path_str,
        "access_flags, this_class, super_class",
    )?;
    let access_flags = cursor.read_u16::<BigEndian>()?;
    let this_class_index = cursor.read_u16::<BigEndian>()?;
    let super_class_index = cursor.read_u16::<BigEndian>()?;

    let class_name = resolve_class_name(
        &constant_pool,
        this_class_index,
        original_path_str,
        "this_class",
    )?;
    let superclass_name = resolve_class_name(
        &constant_pool,
        super_class_index,
        original_path_str,
        "super_class",
    )?;

    check_bounds(&cursor, 2, original_path_str, "interfaces_count")?;
    let interfaces_count = cursor.read_u16::<BigEndian>()?;
    let mut interfaces = Vec::with_capacity(interfaces_count as usize);
    for i in 0..interfaces_count {
        check_bounds(
            &cursor,
            2,
            original_path_str,
            &format!("interface index {}", i),
        )?;
        let interface_index = cursor.read_u16::<BigEndian>()?;

        interfaces.push(resolve_class_name(
            &constant_pool,
            interface_index,
            original_path_str,
            &format!("interface {}", i),
        )?);
    }

    check_bounds(&cursor, 2, original_path_str, "fields_count")?;
    let fields_count = cursor.read_u16::<BigEndian>()?;
    let fields = parse_members(
        &mut cursor,
        fields_count,
        original_path_str,
        verbose,
        "field",
        &constant_pool,
        |name, descriptor, access_flags| FieldInfo {
            name,
            descriptor,
            access_flags,
        },
    )?;

    check_bounds(&cursor, 2, original_path_str, "methods_count")?;
    let methods_count = cursor.read_u16::<BigEndian>()?;
    let (methods, method_calls) = parse_methods(
        &mut cursor,
        methods_count,
        original_path_str,
        verbose,
        &constant_pool,
    )?;

    let mut string_set: HashSet<String> = constant_pool
        .iter()
        .filter_map(|entry| match entry {
            ConstantPoolEntry::Utf8(s) => Some(s.to_string()),
            _ => None,
        })
        .collect();

    for utf8_index in constant_pool.iter().filter_map(|entry| match entry {
        ConstantPoolEntry::String(index) => Some(*index),
        _ => None,
    }) {
        match resolve_utf8(&constant_pool, utf8_index, original_path_str) {
            Ok(s) => {
                string_set.insert(s.to_string());
            }
            Err(e) => {
                if verbose {
                    eprintln!("(!) String constant data resolution error: {}", e);
                }
            }
        }
    }
    let mut strings: Vec<String> = string_set.into_iter().collect();
    strings.sort_unstable();

    Ok(ClassDetails {
        class_name,
        superclass_name,
        interfaces,
        methods,
        method_calls,
        fields,
        strings,
        access_flags,
    })
}
