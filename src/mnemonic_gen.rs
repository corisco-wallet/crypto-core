//! Mnemonic generation, split from its entropy source so `the firmware`
//! can supply hardware-TRNG bytes (`esp_fill_random`) instead of pulling
//! `getrandom`'s OS-backed source onto the device just for this.

use bip39::{Language, Mnemonic};

/// Caller-supplied entropy -> a BIP39 mnemonic. `Mnemonic::from_entropy_in`
/// itself validates the length (16/20/24/28/32 bytes -> 12/15/18/21/24
/// words) -- this project only ever passes 16 or 32 bytes (12- or 24-word
/// wallets), but the function stays general rather than hardcoding that.
pub fn generate_mnemonic_from_entropy(entropy: &[u8]) -> Mnemonic {
    Mnemonic::from_entropy_in(Language::English, entropy)
        .expect("entropy length should be valid for BIP39")
}

/// The full, static English BIP39 wordlist -- used on-device by the
/// recovery flow's adaptive keyboard (prefix-filtering/suggestions), so
/// consumers never need their own direct `bip39` dependency just for this.
pub fn wordlist() -> &'static [&'static str; 2048] {
    Language::English.word_list()
}

/// Parses a user-entered recovery phrase (already-validated-against-
/// `wordlist()` words, joined with spaces) into a `Mnemonic`, checking the
/// BIP39 checksum. Since the on-device keyboard only ever lets the user
/// pick real wordlist words, this is the *only* possible failure mode
/// here -- never "not a word," only "this exact combination doesn't
/// checksum," exactly matching how every BIP39 hardware wallet already
/// behaves (you only find out a phrase was misremembered once the full
/// checksum is checked).
pub fn parse_mnemonic(words: &[String]) -> Result<Mnemonic, String> {
    let phrase = words.join(" ");
    Mnemonic::parse_in_normalized(Language::English, &phrase).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_entropy_produces_same_mnemonic() {
        let entropy = [0x42u8; 16];
        let a = generate_mnemonic_from_entropy(&entropy);
        let b = generate_mnemonic_from_entropy(&entropy);
        assert_eq!(a.to_string(), b.to_string());
        assert_eq!(a.word_count(), 12);
    }

    #[test]
    fn different_entropy_produces_different_mnemonics() {
        let a = generate_mnemonic_from_entropy(&[0x00u8; 16]);
        let b = generate_mnemonic_from_entropy(&[0xFFu8; 16]);
        assert_ne!(a.to_string(), b.to_string());
    }

    #[test]
    fn thirty_two_bytes_of_entropy_produces_a_24_word_mnemonic() {
        let mnemonic = generate_mnemonic_from_entropy(&[0x7au8; 32]);
        assert_eq!(mnemonic.word_count(), 24);
    }

    #[test]
    fn wordlist_has_2048_entries_and_matches_generated_words() {
        let list = wordlist();
        assert_eq!(list.len(), 2048);
        let mnemonic = generate_mnemonic_from_entropy(&[0x11u8; 16]);
        for word in mnemonic.to_string().split_whitespace() {
            assert!(
                list.contains(&word),
                "generated word {word:?} missing from wordlist()"
            );
        }
    }

    #[test]
    fn parse_mnemonic_round_trips_through_words() {
        let mnemonic = generate_mnemonic_from_entropy(&[0x22u8; 16]);
        let words: Vec<String> = mnemonic
            .to_string()
            .split_whitespace()
            .map(String::from)
            .collect();
        let parsed = parse_mnemonic(&words).expect("valid phrase should parse");
        assert_eq!(parsed.to_string(), mnemonic.to_string());
    }

    #[test]
    fn parse_mnemonic_rejects_bad_checksum() {
        let mnemonic = generate_mnemonic_from_entropy(&[0x33u8; 16]);
        let mut words: Vec<String> = mnemonic
            .to_string()
            .split_whitespace()
            .map(String::from)
            .collect();
        // Swap two words -- still 12 real wordlist words, wrong order, so
        // this can only ever be caught by the checksum, not word lookup.
        words.swap(0, 1);
        assert!(parse_mnemonic(&words).is_err());
    }
}
