use std::{
    env,
    fs::{self, File, Permissions},
    io::Write,
    os::unix::fs::PermissionsExt,
};

use elf_experiments::State;

fn main() {
    let files: Vec<(String, Vec<u8>)> = env::args()
        .skip(1)
        .map(|p| (p.clone(), fs::read(p).unwrap()))
        .collect();

    let mut state = State::new();
    for (path, file) in &files {
        state.process_input_file(path, file);
    }

    let dest = files.last().unwrap().0.strip_suffix(".o").unwrap();
    let mut file = File::create(dest).unwrap();
    file.set_permissions(Permissions::from_mode(0o755)).unwrap();
    file.write_all(&state.emit()).unwrap();
}
