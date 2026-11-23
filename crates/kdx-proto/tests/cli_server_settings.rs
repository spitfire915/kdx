//! Checks against `captures/cli-server-settings.pcapng`: the command-line client reads and renames.

use kdx_proto::msg::chat::ChatRecord;
use kdx_proto::msg::server_info::{
    AddressRule, ServerGreeting, ServerInfo, ServerSettings, TrackerEntry,
};
use kdx_proto::msg::EncodeError;
use kdx_proto::session::{Header, MessageType};
use kdx_proto::AccountKey;

mod common;

fn session() -> Vec<(Header, Vec<u8>)> {
    common::session_with_key(
        include_bytes!("fixtures/cli-server-settings-43622.c2s.bin"),
        include_bytes!("fixtures/cli-server-settings-43622.s2c.bin"),
        &AccountKey::from_password(common::LAB_PASSWORD),
    )
}

fn all(kind: MessageType) -> Vec<Vec<u8>> {
    session()
        .into_iter()
        .filter(|(h, _)| h.kind == kind)
        .map(|(_, p)| p)
        .collect()
}

/// Frames 17 and 19: the typed sections of a fresh server, re-encoded byte for byte.
#[test]
fn settings_171_decode_typed_and_reencode_byte_exact() {
    let infos = all(MessageType::SERVER_SETTINGS_INFO);
    assert!(infos.len() >= 2);
    let settings = ServerSettings::decode(&infos[0]).unwrap();
    assert_eq!(settings.encode().unwrap(), infos[0]);
    assert_eq!(settings.main.name, b"New Server");
    assert_eq!(settings.main.port, 10700);
    assert_eq!(settings.name(), b"New Server");
    assert_eq!(settings.trackers, []);
    assert_eq!(settings.allow_deny, []);
    assert_eq!(settings.greeting, None);
    assert_eq!(settings.icon, None);
    // Server 1.620 sends no chat rooms in 171.
    assert!(settings.chats.is_empty());
    assert!(settings.placeholders[ServerSettings::CHATS]);
    assert_eq!(settings.sections()[ServerSettings::MAIN].offset, 0x70);
    assert_eq!(infos[0].len(), ServerSettings::HEADER_LEN + 0x68);
}

/// Frame 20: the command-line client's 172 echoes the 171 with the new name.
#[test]
fn set_172_reencodes_with_the_new_name() {
    let sets = all(MessageType::SET_SERVER_SETTINGS);
    let settings = ServerSettings::decode(&sets[0]).unwrap();
    assert_eq!(settings.encode().unwrap(), sets[0]);
    assert_eq!(settings.main.name, b"OpenKDX Lab");
}

/// Frames 20 and 38: the 172's name length byte is the length of the name
/// the server reports in the next connection's 105.
#[test]
fn renamed_172_length_byte_matches_the_servers_105() {
    let sets = all(MessageType::SET_SERVER_SETTINGS);
    let set = &sets[0];
    let next = common::session_with_key(
        include_bytes!("fixtures/cli-server-settings-43628.c2s.bin"),
        include_bytes!("fixtures/cli-server-settings-43628.s2c.bin"),
        &AccountKey::from_password(common::LAB_PASSWORD),
    );
    let (_, info) = next
        .iter()
        .find(|(h, _)| h.kind == MessageType::SERVER_INFO)
        .unwrap();
    let info = ServerInfo::decode(info).unwrap();
    assert_eq!(info.name, b"OpenKDX Lab");
    assert_eq!(
        usize::from(set[ServerSettings::HEADER_LEN + 0x52]),
        info.name.len()
    );
}

fn put_table(blob: &mut [u8], index: usize, offset: usize, len: usize) {
    let at = 0x0c + 8 * index;
    blob[at..at + 4].copy_from_slice(&(offset as u32).to_be_bytes());
    blob[at + 4..at + 8].copy_from_slice(&(len as u32).to_be_bytes());
}

fn tracker() -> TrackerEntry {
    TrackerEntry {
        name: b"Tracker".to_vec(),
        address: b"tracker.example".to_vec(),
        groups: b"Lab".to_vec(),
        ..TrackerEntry::default()
    }
}

/// The server reads each section at its table offset, in any order.
#[test]
fn decodes_sections_in_any_table_order() {
    let settings = ServerSettings {
        trackers: vec![tracker()],
        greeting: Some(ServerGreeting {
            text: b"Hello".to_vec(),
            ..ServerGreeting::default()
        }),
        ..ServerSettings::default()
    };
    let canonical = settings.encode().unwrap();
    let main = settings.section(ServerSettings::MAIN);
    let greeting = settings.section(ServerSettings::GREETING);
    let trackers = settings.section(ServerSettings::TRACKERS);
    let mut blob = canonical[..ServerSettings::HEADER_LEN].to_vec();
    for (index, bytes) in [
        (ServerSettings::MAIN, &main),
        (ServerSettings::GREETING, &greeting),
        (ServerSettings::TRACKERS, &trackers),
    ] {
        blob.resize(blob.len().next_multiple_of(4), 0);
        let at = blob.len();
        put_table(&mut blob, index, at, bytes.len());
        blob.extend_from_slice(bytes);
    }
    blob.resize(blob.len().next_multiple_of(4), 0);
    assert_ne!(blob, canonical);
    let decoded = ServerSettings::decode(&blob).unwrap();
    assert_eq!(decoded.trackers, settings.trackers);
    assert_eq!(decoded.greeting, settings.greeting);
    assert_eq!(decoded.encode().unwrap(), blob);
}

/// The server does not pad the icon, so a blob that ends with it can end unpadded.
#[test]
fn unpadded_trailing_icon_round_trips() {
    let settings = ServerSettings {
        icon: Some(vec![1, 2, 3, 4, 5]),
        ..ServerSettings::default()
    };
    let blob = settings.encode().unwrap();
    let icon = settings.sections()[ServerSettings::ICON];
    assert_eq!(blob.len(), icon.offset as usize + 5);
    assert_eq!(blob.len() % 4, 1);
    let decoded = ServerSettings::decode(&blob).unwrap();
    assert_eq!(decoded.icon.as_deref(), Some(&[1, 2, 3, 4, 5][..]));
    assert_eq!(decoded.encode().unwrap(), blob);
}

/// Byte 0x54 of the main section and the allow/deny `u16` are kept as they are.
#[test]
fn ignored_54_and_allow_flag_take_any_value() {
    let settings = ServerSettings {
        allow_deny: vec![AddressRule {
            allow_raw: 7,
            address: b"10.0.0.*".to_vec(),
            ..AddressRule::default()
        }],
        ..ServerSettings::default()
    };
    let mut blob = settings.encode().unwrap();
    blob[ServerSettings::HEADER_LEN + 0x54] = 0x7f;
    let decoded = ServerSettings::decode(&blob).unwrap();
    assert_eq!(decoded.main.ignored_54, 0x7f);
    assert_eq!(decoded.allow_deny[0].allow_raw, 7);
    assert!(!decoded.allow_deny[0].allow());
    assert_eq!(decoded.encode().unwrap(), blob);
}

/// A length byte holds at most 255; a longer string is an error, not cut.
#[test]
fn overlong_strings_fail_to_encode() {
    let long = vec![b'x'; 256];
    let mut settings = ServerSettings::default();
    settings.main.name = long.clone();
    assert!(matches!(settings.encode(), Err(EncodeError::TooLong(_))));
    let settings = ServerSettings {
        trackers: vec![TrackerEntry {
            name: long.clone(),
            ..TrackerEntry::default()
        }],
        ..ServerSettings::default()
    };
    assert!(matches!(settings.encode(), Err(EncodeError::TooLong(_))));
    let settings = ServerSettings {
        chats: vec![ChatRecord {
            name: long,
            ..ChatRecord::default()
        }],
        ..ServerSettings::default()
    };
    assert!(matches!(settings.encode(), Err(EncodeError::TooLong(_))));
}

/// A tracker record has twelve length bytes at 0x14 to 0x1f, and its strings
/// follow in that order.
#[test]
fn tracker_entry_strings_follow_the_twelve_lengths() {
    let mut record = vec![0; TrackerEntry::HEADER_LEN];
    record[0] = 0xaa;
    for i in 0..12u8 {
        record[0x14 + usize::from(i)] = i + 1;
    }
    for i in 0..12u8 {
        record.extend(std::iter::repeat_n(b'a' + i, usize::from(i) + 1));
    }
    record.resize(record.len().next_multiple_of(4), 0);
    let (entry, len) = TrackerEntry::decode(&record).unwrap();
    assert_eq!(len, record.len());
    assert_eq!(entry.name, b"a");
    assert_eq!(entry.comments, b"bb");
    assert_eq!(entry.address, b"ccc");
    assert_eq!(entry.login, b"dddd");
    assert_eq!(entry.str_18, b"eeeee");
    assert_eq!(entry.str_19, b"ffffff");
    assert_eq!(entry.groups, b"ggggggg");
    assert_eq!(entry.str_1f, b"llllllllllll");
    assert_eq!(entry.encode().unwrap(), record);
}
