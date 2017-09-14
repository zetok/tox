/*
    Copyright © 2016 quininer kel <quininer@live.com>
    Copyright © 2016 Zetok Zalbavar <zexavexxe@gmail.com>

    This file is part of Tox.

    Tox is libre software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Tox is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Tox.  If not, see <http://www.gnu.org/licenses/>.
*/


use super::quickcheck::quickcheck;

use toxencryptsave::*;

use sodiumoxide::randombytes::randombytes;

// PassKey::

// PassKey::encrypt()

#[test]
fn pass_key_encrypt_test() {
    let plaintext = randombytes(16);
    let passphrase = randombytes(16);
    let pk = PassKey::new(&passphrase).expect("Failed to unwrap PassKey!");
    // test for empty data is done in docs test
    let encrypted = pk.encrypt(&plaintext).expect("Encrypting failed!");
    assert_eq!(plaintext.len() + EXTRA_LENGTH, encrypted.len());
    assert!(plaintext.as_slice() != &encrypted[EXTRA_LENGTH..]);
    assert_eq!(plaintext, pk.decrypt(&encrypted).expect("Decrypting failed"));
}

// PassKey::decrypt()

#[test]
fn pass_key_decrypt_test() {
    let plaintext = randombytes(16);
    let passphrase = randombytes(16);
    let pk = PassKey::new(&passphrase).expect("Failed to unwrap PassKey!");

    let encrypted = pk.encrypt(&plaintext).expect("Encrypting failed!");

    // decrypting should just work™
    assert_eq!(&plaintext, &pk.decrypt(&encrypted).expect("Decrypting failed!"));

    // check if fails if one of `MAGIC_NUMBER` bytes is wrong
    for pos in 0..MAGIC_LENGTH {
        let mut ec = encrypted.clone();
        if ec[pos] == 0 { ec[pos] = 1; } else { ec[pos] = 0; }
        assert_eq!(Err(DecryptionError::BadFormat), pk.decrypt(&ec));
    }

    // check if fails if a data byte is wrong
    for pos in EXTRA_LENGTH..encrypted.len() {
        let mut ec = encrypted.clone();
        if ec[pos] == 0 { ec[pos] = 1; } else { ec[pos] = 0; }
        assert_eq!(Err(DecryptionError::Failed), pk.decrypt(&ec));
    }

    // fails if not enough bytes?
    for n in 1..EXTRA_LENGTH {
        assert_eq!(Err(DecryptionError::InvalidLength),
                pk.decrypt(&encrypted[..EXTRA_LENGTH - n]));
    }
}


// is_encrypted()

#[test]
fn is_encrypted_test() {
    fn with_bytes(bytes: Vec<u8>) {
        assert_eq!(false, is_encrypted(&bytes));
    }
    quickcheck(with_bytes as fn(Vec<u8>));

    with_bytes(b"Hello world.\n".to_vec());
    assert!(is_encrypted(MAGIC_NUMBER));
    assert!(is_encrypted(include_bytes!("ciphertext")));
}


// pass_encrypt()

#[test]
fn pass_encrypt_test() {
    let plaintext = randombytes(16);
    let passphrase = randombytes(16);

    let encrypted = pass_encrypt(&plaintext, &passphrase)
        .expect("Failed to unwrap pass_encrypt!");
    assert!(is_encrypted(&encrypted));

    assert_eq!(plaintext.len() + EXTRA_LENGTH, encrypted.len());
    assert_eq!(plaintext, pass_decrypt(&encrypted, &passphrase)
                        .expect("Failed to pass_decrypt!"));

    let encrypted2 = pass_encrypt(&plaintext, &passphrase)
        .expect("Failed to unwrap pass_encrypt 2!");
    assert!(encrypted != encrypted2);
}


// pass_decrypt()

#[test]
fn pass_decrypt_test() {
    let passphrase = b"encryptsave";
    let plaintext = b"Hello world.\n";
    let ciphertext = include_bytes!("ciphertext");

    assert_eq!(
        pass_decrypt(ciphertext, passphrase).unwrap(),
        plaintext
    );
}

#[test]
fn get_salt_test() {
    fn with_bytes(bytes: Vec<u8>) {
        let mut res = Vec::with_capacity(MAGIC_LENGTH + bytes.len());
        res.extend_from_slice(MAGIC_NUMBER);
        res.extend_from_slice(&bytes);

        if bytes.len() < SALT_LENGTH {
            assert_eq!(None, get_salt(&res));
            return
        }

        // check if will work with any bytes
        assert_eq!(&bytes[..SALT_LENGTH], get_salt(&res)
            .expect("Failed to get Salt!").0);

        // check if will fail with any malformed magic byte
        for pos in 0..MAGIC_LENGTH {
            let mut v = res.clone();
            if v[pos] == 0 { v[pos] = 1; } else { v[pos] = 0; }
            assert_eq!(None, get_salt(&v));
        }
    }
    quickcheck(with_bytes as fn(Vec<u8>));

    assert_eq!(
        get_salt(include_bytes!("ciphertext")).unwrap().0,
        [208, 154, 232, 3, 210, 251, 220, 103, 10, 139, 111, 145, 165, 238, 157, 170, 62, 76, 91, 231, 46, 254, 215, 174, 12, 195, 128, 5, 171, 229, 237, 60]
    );
}
