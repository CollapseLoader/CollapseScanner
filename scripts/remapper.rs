use indicatif::{ProgressBar, ProgressStyle};
use std::io::{BufReader, BufWriter};
use std::{env, fs::File, io, path::Path};
use tempfile::tempdir;
use zip::result::ZipResult;
use zip::write::FileOptions;
use zip::{ZipArchive, ZipWriter};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        eprintln!("Usage: {} <input_jar> <output_jar>", args[0]);
        std::process::exit(1);
    }
    let input_path = &args[1];
    let output_path = &args[2];

    println!("🔍 Remapper for \"trailing slash\" technique");
    println!("📥 Input JAR:  {}", input_path);
    println!("📤 Output JAR: {}", output_path);

    match process_jar(input_path, output_path) {
        Ok(_) => {
            println!("✅ Successfully fixed JAR -> {}", output_path);
            Ok(())
        }
        Err(e) => {
            eprintln!("❌ Error processing JAR: {}", e);
            Err(e.into())
        }
    }
}

fn process_jar(input_path: &str, output_path: &str) -> ZipResult<()> {
    if !Path::new(input_path).exists() {
        return Err(zip::result::ZipError::Io(io::Error::new(
            io::ErrorKind::NotFound,
            "Input file not found",
        )));
    }

    let input_file = File::open(input_path)?;
    let mut archive = ZipArchive::new(BufReader::new(input_file))?;

    let temp_dir = tempdir().map_err(zip::result::ZipError::Io)?;
    let num_entries = archive.len();

    let mut entries_info = Vec::with_capacity(num_entries);
    for i in 0..num_entries {
        let mut entry = archive.by_index(i)?;
        let original_name = entry.enclosed_name().map_or_else(
            || entry.name().to_string(),
            |path| path.to_string_lossy().into_owned(),
        );

        let new_name = if original_name.ends_with(".class/") {
            original_name[0..original_name.len() - 1].to_string()
        } else {
            original_name
        };

        let compression = entry.compression();
        let unix_mode = entry.unix_mode().unwrap_or(0o644);
        let is_dir = entry.is_dir();

        if entry.size() > 1_000_000 && !is_dir {
            let temp_path = temp_dir.path().join(i.to_string());
            {
                let mut temp_file = File::create(&temp_path).map_err(zip::result::ZipError::Io)?;
                io::copy(&mut entry, &mut BufWriter::new(&mut temp_file))
                    .map_err(zip::result::ZipError::Io)?;
            }
            entries_info.push((new_name, compression, unix_mode, is_dir, Some(temp_path)));
        } else {
            entries_info.push((new_name, compression, unix_mode, is_dir, None));
        }
    }
    let output_file = File::create(output_path)?;
    let output_writer = BufWriter::with_capacity(65536, output_file);
    let mut zip_writer = ZipWriter::new(output_writer);

    let pb = ProgressBar::new(num_entries as u64);
    pb.set_style(
        ProgressStyle::default_bar()
            .template(
                "{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} entries",
            )
            .unwrap()
            .progress_chars("=>-"),
    );

    println!("🔧 Building fixed JAR file...");

    let input_file = File::open(input_path)?;
    let mut archive = ZipArchive::new(BufReader::new(input_file))?;

    for (i, (name, compression, unix_mode, is_dir, temp_path)) in
        entries_info.into_iter().enumerate()
    {
        let options = FileOptions::<()>::default()
            .compression_method(compression)
            .unix_permissions(unix_mode);

        if is_dir {
            zip_writer.add_directory(&name, options)?;
        } else {
            zip_writer.start_file(&name, options)?;

            if let Some(path) = temp_path {
                let temp_file = File::open(path).map_err(zip::result::ZipError::Io)?;
                let mut reader = BufReader::with_capacity(65536, temp_file);
                io::copy(&mut reader, &mut zip_writer).map_err(zip::result::ZipError::Io)?;
            } else {
                let mut entry = archive.by_index(i)?;
                io::copy(&mut entry, &mut zip_writer)?;
            }
        }

        pb.inc(1);
    }

    zip_writer.finish()?;

    Ok(())
}
