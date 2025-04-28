use crate::errors::ScanError;
use crate::types::{ClassDetails, ConstantPoolEntry, FieldInfo, MethodInfo};
use byteorder::{BigEndian, ReadBytesExt};
use encoding_rs::UTF_8;
use std::collections::HashSet;
use std::io::{Cursor, Read, Seek, SeekFrom};

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

    let constant_pool = parse_constant_pool(&mut cursor, cp_count, original_path_str, verbose)?;

    let resolve_utf8 = |index: u16, context: &str| -> Result<String, ScanError> {
        if index == 0 || (index as usize) > constant_pool.len() {
            return Err(ScanError::ClassParseError {
                path: original_path_str.to_string(),
                msg: format!(
                    "Invalid CP index {} for UTF8 ({}) (pool size {})",
                    index,
                    context,
                    constant_pool.len()
                ),
            });
        }
        match constant_pool.get(index as usize - 1) {
            Some(ConstantPoolEntry::Utf8(s)) => Ok(s.clone()),
            Some(other) => Err(ScanError::ClassParseError {
                path: original_path_str.to_string(),
                msg: format!(
                    "Expected UTF8 at CP index {} ({}), found {:?}",
                    index, context, other
                ),
            }),
            None => Err(ScanError::ClassParseError {
                path: original_path_str.to_string(),
                msg: format!("CP index {} out of bounds ({})", index, context),
            }),
        }
    };

    let resolve_class_name = |index: u16, context: &str| -> Result<String, ScanError> {
        if index == 0 {
            if context == "super_class" {
                if verbose {
                    println!(
                        "{} Warning: Superclass index is 0 in '{}', assuming java/lang/Object.",
                        "⚠️".yellow(),
                        original_path_str
                    );
                }
                return Ok("java/lang/Object".to_string());
            } else if context == "this_class" {
                return Err(ScanError::ClassParseError {
                    path: original_path_str.to_string(),
                    msg: "Invalid CP index 0 for this_class".to_string(),
                });
            } else {
                if verbose {
                    println!(
                        "{} Warning: Class index is 0 for {} in '{}'. Using placeholder.",
                        "⚠️".yellow(),
                        context,
                        original_path_str
                    );
                }
                return Ok("<INVALID_CLASS_INDEX_0>".to_string());
            }
        }
        if (index as usize) > constant_pool.len() {
            return Err(ScanError::ClassParseError {
                path: original_path_str.to_string(),
                msg: format!(
                    "Invalid CP index {} for Class ({}) (pool size {})",
                    index,
                    context,
                    constant_pool.len()
                ),
            });
        }
        match constant_pool.get(index as usize - 1) {
            Some(ConstantPoolEntry::Class(name_index)) => resolve_utf8(
                *name_index,
                &format!("name for Class at {} ({})", index, context),
            ),
            Some(other) => Err(ScanError::ClassParseError {
                path: original_path_str.to_string(),
                msg: format!(
                    "Expected Class info at CP index {} ({}), found {:?}",
                    index, context, other
                ),
            }),
            None => Err(ScanError::ClassParseError {
                path: original_path_str.to_string(),
                msg: format!("CP index {} out of bounds ({})", index, context),
            }),
        }
    };

    if cursor.position() + 6 > data.len() as u64 {
        return Err(ScanError::ClassParseError {
            path: original_path_str.to_string(),
            msg: "EOF before class flags/indices".to_string(),
        });
    }
    let access_flags = cursor.read_u16::<BigEndian>()?;
    let this_class_index = cursor.read_u16::<BigEndian>()?;
    let super_class_index = cursor.read_u16::<BigEndian>()?;

    let class_name = resolve_class_name(this_class_index, "this_class")?;
    let superclass_name = resolve_class_name(super_class_index, "super_class")?;

    if cursor.position() + 2 > data.len() as u64 {
        return Err(ScanError::ClassParseError {
            path: original_path_str.to_string(),
            msg: "EOF before interfaces_count".to_string(),
        });
    }
    let interfaces_count = cursor.read_u16::<BigEndian>()?;
    let mut interfaces = Vec::with_capacity(interfaces_count as usize);
    for i in 0..interfaces_count {
        if cursor.position() + 2 > data.len() as u64 {
            return Err(ScanError::ClassParseError {
                path: original_path_str.to_string(),
                msg: format!("EOF reading interface index {}", i),
            });
        }
        let interface_index = cursor.read_u16::<BigEndian>()?;
        interfaces.push(resolve_class_name(
            interface_index,
            &format!("interface {}", i),
        )?);
    }

    if cursor.position() + 2 > data.len() as u64 {
        return Err(ScanError::ClassParseError {
            path: original_path_str.to_string(),
            msg: "EOF before fields_count".to_string(),
        });
    }
    let fields_count = cursor.read_u16::<BigEndian>()?;
    let mut fields = Vec::with_capacity(fields_count as usize);
    for f_idx in 0..fields_count {
        if cursor.position() + 8 > data.len() as u64 {
            return Err(ScanError::ClassParseError {
                path: original_path_str.to_string(),
                msg: format!("EOF reading field header {}", f_idx),
            });
        }
        let field_access_flags = cursor.read_u16::<BigEndian>()?;
        let name_index = cursor.read_u16::<BigEndian>()?;
        let descriptor_index = cursor.read_u16::<BigEndian>()?;
        let attributes_count = cursor.read_u16::<BigEndian>()?;

        let field_name = match resolve_utf8(name_index, &format!("field {} name", f_idx)) {
            Ok(n) => n,
            Err(e) => {
                if verbose {
                    println!("{} Field name resolution error: {}", "⚠️".yellow(), e);
                }
                format!("<INVALID_FIELD_NAME_{}>", f_idx)
            }
        };
        let field_descriptor =
            match resolve_utf8(descriptor_index, &format!("field {} descriptor", f_idx)) {
                Ok(d) => d,
                Err(e) => {
                    if verbose {
                        println!("{} Field descriptor resolution error: {}", "⚠️".yellow(), e);
                    }
                    "<INVALID_DESCRIPTOR>".to_string()
                }
            };

        skip_attributes(
            &mut cursor,
            attributes_count,
            original_path_str,
            "field",
            f_idx,
        )?;
        fields.push(FieldInfo {
            name: field_name,
            descriptor: field_descriptor,
            access_flags: field_access_flags,
        });
    }

    if cursor.position() + 2 > data.len() as u64 {
        return Err(ScanError::ClassParseError {
            path: original_path_str.to_string(),
            msg: "EOF before methods_count".to_string(),
        });
    }
    let methods_count = cursor.read_u16::<BigEndian>()?;
    let mut methods = Vec::with_capacity(methods_count as usize);
    for m_idx in 0..methods_count {
        if cursor.position() + 8 > data.len() as u64 {
            return Err(ScanError::ClassParseError {
                path: original_path_str.to_string(),
                msg: format!("EOF reading method header {}", m_idx),
            });
        }
        let method_access_flags = cursor.read_u16::<BigEndian>()?;
        let name_index = cursor.read_u16::<BigEndian>()?;
        let descriptor_index = cursor.read_u16::<BigEndian>()?;
        let attributes_count = cursor.read_u16::<BigEndian>()?;

        let method_name = match resolve_utf8(name_index, &format!("method {} name", m_idx)) {
            Ok(n) => n,
            Err(e) => {
                if verbose {
                    println!("{} Method name resolution error: {}", "⚠️".yellow(), e);
                }
                format!("<INVALID_METHOD_NAME_{}>", m_idx)
            }
        };
        let method_descriptor =
            match resolve_utf8(descriptor_index, &format!("method {} descriptor", m_idx)) {
                Ok(d) => d,
                Err(e) => {
                    if verbose {
                        println!(
                            "{} Method descriptor resolution error: {}",
                            "⚠️".yellow(),
                            e
                        );
                    }
                    "<INVALID_DESCRIPTOR>".to_string()
                }
            };

        skip_attributes(
            &mut cursor,
            attributes_count,
            original_path_str,
            "method",
            m_idx,
        )?;
        methods.push(MethodInfo {
            name: method_name,
            descriptor: method_descriptor,
            access_flags: method_access_flags,
        });
    }

    let strings = constant_pool
        .iter()
        .filter_map(|entry| match entry {
            ConstantPoolEntry::String(utf8_index) => {
                match resolve_utf8(*utf8_index, "String constant") {
                    Ok(s) => Some(s),
                    Err(e) => {
                        if verbose {
                            println!("{} String constant resolution error: {}", "⚠️".yellow(), e);
                        }
                        None
                    }
                }
            }
            ConstantPoolEntry::Utf8(s) => Some(s.clone()),
            _ => None,
        })
        .collect::<HashSet<_>>()
        .into_iter()
        .collect();

    Ok(ClassDetails {
        class_name,
        superclass_name,
        interfaces,
        methods,
        fields,
        strings,
        access_flags,
    })
}

fn parse_constant_pool(
    cursor: &mut Cursor<&[u8]>,
    cp_count: u16,
    file_path_str: &str,
    verbose: bool,
) -> Result<Vec<ConstantPoolEntry>, ScanError> {
    if cp_count <= 1 {
        return Ok(Vec::new());
    }
    let capacity = cp_count as usize - 1;

    let mut constant_pool = Vec::with_capacity(capacity);
    let mut i = 1;
    let data_len = cursor.get_ref().len() as u64;

    fn check_needed_bytes(
        cur_pos: u64,
        needed: u64,
        data_len: u64,
        tag: u8,
        index: u16,
        path: &str,
        cp_count: u16,
    ) -> Result<(), ScanError> {
        if index >= cp_count {
            return Err(ScanError::ClassParseError {
                path: path.to_string(),
                msg: format!(
                    "Attempted to read CP entry at index {}, but cp_count is only {}",
                    index, cp_count
                ),
            });
        }
        if cur_pos.saturating_add(needed) > data_len {
            Err(ScanError::ClassParseError {
                path: path.to_string(),
                msg: format!(
                    "EOF before reading data for CP tag {} at index {} (pos {}, needed {}, total len {})",
                    tag, index, cur_pos, needed, data_len
                ),
            })
        } else {
            Ok(())
        }
    }

    while i < cp_count {
        let start_pos = cursor.position();
        check_needed_bytes(start_pos, 1, data_len, 0, i, file_path_str, cp_count)?;
        let tag = cursor.read_u8()?;

        let (needed_data_bytes, entry_slots) = match tag {
            1 => (2u64, 1u16),
            7 | 8 | 16 | 19 | 20 => (2, 1),
            3 | 4 => (4, 1),
            9 | 10 | 11 | 12 | 17 | 18 => (4, 1),
            5 | 6 => (8, 2),
            15 => (3, 1),
            _ => {
                return Err(ScanError::ClassParseError {
                    path: file_path_str.to_string(),
                    msg: format!("Unknown CP tag {} at index {}", tag, i),
                });
            }
        };

        if tag != 1 {
            check_needed_bytes(
                start_pos + 1,
                needed_data_bytes,
                data_len,
                tag,
                i,
                file_path_str,
                cp_count,
            )?;
        }

        let entry = match tag {
            1 => {
                check_needed_bytes(
                    cursor.position(),
                    2,
                    data_len,
                    tag,
                    i,
                    file_path_str,
                    cp_count,
                )?;
                let length = cursor.read_u16::<BigEndian>()? as usize;
                check_needed_bytes(
                    cursor.position(),
                    length as u64,
                    data_len,
                    tag,
                    i,
                    file_path_str,
                    cp_count,
                )?;
                let mut buf = vec![0; length];
                cursor.read_exact(&mut buf)?;
                let (cow, _, had_errors) = UTF_8.decode(&buf);
                if had_errors && verbose {
                    eprintln!(
                        "{} Warning: UTF-8 decoding errors in CP index {} ('{}')",
                        "⚠️".yellow(),
                        i,
                        file_path_str
                    );
                }
                ConstantPoolEntry::Utf8(cow.into_owned())
            }
            7 => ConstantPoolEntry::Class(cursor.read_u16::<BigEndian>()?),
            8 => ConstantPoolEntry::String(cursor.read_u16::<BigEndian>()?),
            3 => {
                cursor.seek(SeekFrom::Current(4))?;
                ConstantPoolEntry::Integer
            }
            4 => {
                cursor.seek(SeekFrom::Current(4))?;
                ConstantPoolEntry::Float
            }
            9 => {
                let c = cursor.read_u16::<BigEndian>()?;
                let n = cursor.read_u16::<BigEndian>()?;
                ConstantPoolEntry::Fieldref(c, n)
            }
            10 => {
                let c = cursor.read_u16::<BigEndian>()?;
                let n = cursor.read_u16::<BigEndian>()?;
                ConstantPoolEntry::Methodref(c, n)
            }
            11 => {
                let c = cursor.read_u16::<BigEndian>()?;
                let n = cursor.read_u16::<BigEndian>()?;
                ConstantPoolEntry::InterfaceMethodref(c, n)
            }
            12 => {
                let n = cursor.read_u16::<BigEndian>()?;
                let d = cursor.read_u16::<BigEndian>()?;
                ConstantPoolEntry::NameAndType(n, d)
            }
            5 => {
                cursor.seek(SeekFrom::Current(8))?;
                ConstantPoolEntry::Long
            }
            6 => {
                cursor.seek(SeekFrom::Current(8))?;
                ConstantPoolEntry::Double
            }
            15 => {
                cursor.seek(SeekFrom::Current(3))?;
                ConstantPoolEntry::MethodHandle
            }
            16 => {
                cursor.seek(SeekFrom::Current(2))?;
                ConstantPoolEntry::MethodType
            }
            17 => {
                cursor.seek(SeekFrom::Current(4))?;
                ConstantPoolEntry::Dynamic
            }
            18 => {
                cursor.seek(SeekFrom::Current(4))?;
                ConstantPoolEntry::InvokeDynamic
            }
            19 => {
                cursor.seek(SeekFrom::Current(2))?;
                ConstantPoolEntry::Module
            }
            20 => {
                cursor.seek(SeekFrom::Current(2))?;
                ConstantPoolEntry::Package
            }
            _ => unreachable!(),
        };

        constant_pool.push(entry);
        if entry_slots == 2 {
            if i + 1 < cp_count {
                constant_pool.push(ConstantPoolEntry::Placeholder);
            } else {
                return Err(ScanError::ClassParseError {
                    path: file_path_str.to_string(),
                    msg: format!(
                        "Corrupt CP: 2-slot entry (tag {}) at last index {} (cp_count {})",
                        tag, i, cp_count
                    ),
                });
            }
        }
        i += entry_slots;
    }

    if constant_pool.len() != capacity {
        eprintln!(
              "{} Warning: Constant pool size mismatch for '{}'. Parsed {} entries, expected capacity {}. File might be corrupt.",
              "⚠️".yellow(),
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
    member_type: &str,
    member_index: u16,
) -> Result<(), ScanError> {
    let data_len = cursor.get_ref().len() as u64;
    for attr_index in 0..attributes_count {
        let attr_header_pos = cursor.position();
        if attr_header_pos.saturating_add(6) > data_len {
            return Err(ScanError::ClassParseError {
                path: file_path_str.to_string(),
                msg: format!(
                    "EOF reading attribute header {} for {} {} (at pos {})",
                    attr_index, member_type, member_index, attr_header_pos
                ),
            });
        }
        let _attribute_name_index = cursor.read_u16::<BigEndian>()?;
        let attribute_length = cursor.read_u32::<BigEndian>()?;
        let current_pos = cursor.position();
        let end_pos = current_pos.saturating_add(attribute_length as u64);

        if end_pos > data_len {
            return Err(ScanError::ClassParseError { path: file_path_str.to_string(), msg: format!("Attribute {} length {} for {} {} exceeds file bounds (at pos {}, needs end pos {}, total len {})", attr_index, attribute_length, member_type, member_index, current_pos, end_pos, data_len) });
        }

        if attribute_length > 0 {
            if let Err(e) = cursor.seek(SeekFrom::Current(attribute_length as i64)) {
                return Err(ScanError::ClassParseError {
                    path: file_path_str.to_string(),
                    msg: format!(
                        "IO Error seeking attribute {} data for {} {} (len {}, current_pos {}): {}",
                        attr_index, member_type, member_index, attribute_length, current_pos, e
                    ),
                });
            };
        }
    }
    Ok(())
}

use colored::*;
