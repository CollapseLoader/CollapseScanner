use crate::errors::ScanError;
use crate::types::{ClassDetails, ConstantPoolEntry, FieldInfo, MethodInfo};
use byteorder::{BigEndian, ReadBytesExt};
use colored::Colorize;
use encoding_rs::UTF_8;
use std::collections::HashSet;
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
    context: &str,
) -> Result<&'a str, ScanError> {
    if index == 0 || (index as usize) > pool.len() {
        return Err(ScanError::ClassParseError {
            path: path.to_string(),
            msg: format!(
                "Invalid CP index {} (0-based) for UTF8 resolve ('{}'). Pool size: {}.",
                index,
                context,
                pool.len()
            ),
        });
    }

    match &pool[index as usize - 1] {
        ConstantPoolEntry::Utf8(s) => Ok(s),
        other => Err(ScanError::ClassParseError {
            path: path.to_string(),
            msg: format!(
                "Expected UTF8 at CP index {} ('{}'), found {:?}",
                index, context, other
            ),
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
            let class_name_context = format!("name for Class at {} ('{}')", index, context);
            Ok(resolve_utf8(pool, *name_index, path, &class_name_context)?.to_owned())
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

        let name_context = format!("{} {} name", member_kind, index);
        let descriptor_context = format!("{} {} descriptor", member_kind, index);

        let name = resolve_utf8(pool, name_index, file_path_str, &name_context)
            .map(str::to_owned)
            .unwrap_or_else(|e| {
                if verbose {
                    eprintln!(
                        "{} {} name resolution error: {}",
                        "⚠️".yellow(),
                        member_kind,
                        e
                    );
                }
                format!("<{}_{}>", invalid_name_prefix, name_index)
            });

        let descriptor = resolve_utf8(pool, descriptor_index, file_path_str, &descriptor_context)
            .map(str::to_owned)
            .unwrap_or_else(|e| {
                if verbose {
                    eprintln!(
                        "{} {} descriptor resolution error: {}",
                        "⚠️".yellow(),
                        member_kind,
                        e
                    );
                }
                format!("<INVALID_DESCRIPTOR_INDEX_{}>", descriptor_index)
            });

        skip_attributes(cursor, attributes_count, file_path_str)?;
        members.push(make_member(name, descriptor, access_flags));
    }

    Ok(members)
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

                constant_pool.push(ConstantPoolEntry::Utf8(cow.into_owned()));
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
    let methods = parse_members(
        &mut cursor,
        methods_count,
        original_path_str,
        verbose,
        "method",
        &constant_pool,
        |name, descriptor, access_flags| MethodInfo {
            name,
            descriptor,
            access_flags,
        },
    )?;

    let mut string_set: HashSet<String> = constant_pool
        .iter()
        .filter_map(|entry| match entry {
            ConstantPoolEntry::Utf8(s) => Some(s.clone()),
            _ => None,
        })
        .collect();

    for utf8_index in constant_pool.iter().filter_map(|entry| match entry {
        ConstantPoolEntry::String(index) => Some(*index),
        _ => None,
    }) {
        match resolve_utf8(
            &constant_pool,
            utf8_index,
            original_path_str,
            "String constant data",
        ) {
            Ok(s) => {
                string_set.insert(s.to_owned());
            }
            Err(e) => {
                if verbose {
                    eprintln!(
                        "{} String constant data resolution error: {}",
                        "⚠️".yellow(),
                        e
                    );
                }
            }
        }
    }
    let strings: Vec<String> = string_set.into_iter().collect();

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
