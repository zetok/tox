(function() {var implementors = {};
implementors["byteorder"] = ["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/hash/trait.Hash.html\" title=\"trait core::hash::Hash\">Hash</a> for <a class=\"enum\" href=\"byteorder/enum.BigEndian.html\" title=\"enum byteorder::BigEndian\">BigEndian</a>","impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/hash/trait.Hash.html\" title=\"trait core::hash::Hash\">Hash</a> for <a class=\"enum\" href=\"byteorder/enum.LittleEndian.html\" title=\"enum byteorder::LittleEndian\">LittleEndian</a>",];
implementors["bytes"] = ["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/hash/trait.Hash.html\" title=\"trait core::hash::Hash\">Hash</a> for <a class=\"struct\" href=\"bytes/struct.Bytes.html\" title=\"struct bytes::Bytes\">Bytes</a>","impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/hash/trait.Hash.html\" title=\"trait core::hash::Hash\">Hash</a> for <a class=\"struct\" href=\"bytes/struct.BytesMut.html\" title=\"struct bytes::BytesMut\">BytesMut</a>",];
implementors["log"] = ["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/hash/trait.Hash.html\" title=\"trait core::hash::Hash\">Hash</a> for <a class=\"enum\" href=\"log/enum.Level.html\" title=\"enum log::Level\">Level</a>","impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/hash/trait.Hash.html\" title=\"trait core::hash::Hash\">Hash</a> for <a class=\"enum\" href=\"log/enum.LevelFilter.html\" title=\"enum log::LevelFilter\">LevelFilter</a>","impl&lt;'a&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/hash/trait.Hash.html\" title=\"trait core::hash::Hash\">Hash</a> for <a class=\"struct\" href=\"log/struct.Metadata.html\" title=\"struct log::Metadata\">Metadata</a>&lt;'a&gt;","impl&lt;'a&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/hash/trait.Hash.html\" title=\"trait core::hash::Hash\">Hash</a> for <a class=\"struct\" href=\"log/struct.MetadataBuilder.html\" title=\"struct log::MetadataBuilder\">MetadataBuilder</a>&lt;'a&gt;",];
implementors["mio"] = ["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/hash/trait.Hash.html\" title=\"trait core::hash::Hash\">Hash</a> for <a class=\"struct\" href=\"mio/struct.Token.html\" title=\"struct mio::Token\">Token</a>",];
implementors["nom"] = ["impl&lt;E:&nbsp;<a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/hash/trait.Hash.html\" title=\"trait core::hash::Hash\">Hash</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/hash/trait.Hash.html\" title=\"trait core::hash::Hash\">Hash</a> for <a class=\"enum\" href=\"nom/enum.ErrorKind.html\" title=\"enum nom::ErrorKind\">ErrorKind</a>&lt;E&gt;",];
implementors["smallvec"] = ["impl&lt;A:&nbsp;<a class=\"trait\" href=\"smallvec/trait.Array.html\" title=\"trait smallvec::Array\">Array</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/hash/trait.Hash.html\" title=\"trait core::hash::Hash\">Hash</a> for <a class=\"struct\" href=\"smallvec/struct.SmallVec.html\" title=\"struct smallvec::SmallVec\">SmallVec</a>&lt;A&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;A::<a class=\"type\" href=\"smallvec/trait.Array.html#associatedtype.Item\" title=\"type smallvec::Array::Item\">Item</a>: <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/hash/trait.Hash.html\" title=\"trait core::hash::Hash\">Hash</a>,&nbsp;</span>",];
implementors["sodiumoxide"] = ["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/hash/trait.Hash.html\" title=\"trait core::hash::Hash\">Hash</a> for <a class=\"struct\" href=\"sodiumoxide/crypto/aead/chacha20poly1305/struct.Nonce.html\" title=\"struct sodiumoxide::crypto::aead::chacha20poly1305::Nonce\">Nonce</a>","impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/hash/trait.Hash.html\" title=\"trait core::hash::Hash\">Hash</a> for <a class=\"struct\" href=\"sodiumoxide/crypto/aead/chacha20poly1305/struct.Tag.html\" title=\"struct sodiumoxide::crypto::aead::chacha20poly1305::Tag\">Tag</a>","impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/hash/trait.Hash.html\" title=\"trait core::hash::Hash\">Hash</a> for <a class=\"struct\" href=\"sodiumoxide/crypto/aead/chacha20poly1305_ietf/struct.Nonce.html\" title=\"struct sodiumoxide::crypto::aead::chacha20poly1305_ietf::Nonce\">Nonce</a>","impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/hash/trait.Hash.html\" title=\"trait core::hash::Hash\">Hash</a> for <a class=\"struct\" href=\"sodiumoxide/crypto/aead/chacha20poly1305_ietf/struct.Tag.html\" title=\"struct sodiumoxide::crypto::aead::chacha20poly1305_ietf::Tag\">Tag</a>","impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/hash/trait.Hash.html\" title=\"trait core::hash::Hash\">Hash</a> for <a class=\"struct\" href=\"sodiumoxide/crypto/box_/curve25519xsalsa20poly1305/struct.PublicKey.html\" title=\"struct sodiumoxide::crypto::box_::curve25519xsalsa20poly1305::PublicKey\">PublicKey</a>","impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/hash/trait.Hash.html\" title=\"trait core::hash::Hash\">Hash</a> for <a class=\"struct\" href=\"sodiumoxide/crypto/box_/curve25519xsalsa20poly1305/struct.Tag.html\" title=\"struct sodiumoxide::crypto::box_::curve25519xsalsa20poly1305::Tag\">Tag</a>","impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/hash/trait.Hash.html\" title=\"trait core::hash::Hash\">Hash</a> for <a class=\"struct\" href=\"sodiumoxide/crypto/box_/curve25519xsalsa20poly1305/struct.Nonce.html\" title=\"struct sodiumoxide::crypto::box_::curve25519xsalsa20poly1305::Nonce\">Nonce</a>","impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/hash/trait.Hash.html\" title=\"trait core::hash::Hash\">Hash</a> for <a class=\"struct\" href=\"sodiumoxide/crypto/sign/ed25519/struct.PublicKey.html\" title=\"struct sodiumoxide::crypto::sign::ed25519::PublicKey\">PublicKey</a>","impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/hash/trait.Hash.html\" title=\"trait core::hash::Hash\">Hash</a> for <a class=\"struct\" href=\"sodiumoxide/crypto/sign/ed25519/struct.Signature.html\" title=\"struct sodiumoxide::crypto::sign::ed25519::Signature\">Signature</a>","impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/hash/trait.Hash.html\" title=\"trait core::hash::Hash\">Hash</a> for <a class=\"struct\" href=\"sodiumoxide/crypto/auth/hmacsha512/struct.Tag.html\" title=\"struct sodiumoxide::crypto::auth::hmacsha512::Tag\">Tag</a>","impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/hash/trait.Hash.html\" title=\"trait core::hash::Hash\">Hash</a> for <a class=\"struct\" href=\"sodiumoxide/crypto/auth/hmacsha512256/struct.Tag.html\" title=\"struct sodiumoxide::crypto::auth::hmacsha512256::Tag\">Tag</a>","impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/hash/trait.Hash.html\" title=\"trait core::hash::Hash\">Hash</a> for <a class=\"struct\" href=\"sodiumoxide/crypto/auth/hmacsha256/struct.Tag.html\" title=\"struct sodiumoxide::crypto::auth::hmacsha256::Tag\">Tag</a>","impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/hash/trait.Hash.html\" title=\"trait core::hash::Hash\">Hash</a> for <a class=\"struct\" href=\"sodiumoxide/crypto/hash/sha512/struct.Digest.html\" title=\"struct sodiumoxide::crypto::hash::sha512::Digest\">Digest</a>","impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/hash/trait.Hash.html\" title=\"trait core::hash::Hash\">Hash</a> for <a class=\"struct\" href=\"sodiumoxide/crypto/hash/sha256/struct.Digest.html\" title=\"struct sodiumoxide::crypto::hash::sha256::Digest\">Digest</a>","impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/hash/trait.Hash.html\" title=\"trait core::hash::Hash\">Hash</a> for <a class=\"struct\" href=\"sodiumoxide/crypto/secretbox/xsalsa20poly1305/struct.Tag.html\" title=\"struct sodiumoxide::crypto::secretbox::xsalsa20poly1305::Tag\">Tag</a>","impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/hash/trait.Hash.html\" title=\"trait core::hash::Hash\">Hash</a> for <a class=\"struct\" href=\"sodiumoxide/crypto/secretbox/xsalsa20poly1305/struct.Nonce.html\" title=\"struct sodiumoxide::crypto::secretbox::xsalsa20poly1305::Nonce\">Nonce</a>","impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/hash/trait.Hash.html\" title=\"trait core::hash::Hash\">Hash</a> for <a class=\"struct\" href=\"sodiumoxide/crypto/onetimeauth/poly1305/struct.Tag.html\" title=\"struct sodiumoxide::crypto::onetimeauth::poly1305::Tag\">Tag</a>","impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/hash/trait.Hash.html\" title=\"trait core::hash::Hash\">Hash</a> for <a class=\"struct\" href=\"sodiumoxide/crypto/pwhash/scryptsalsa208sha256/struct.Salt.html\" title=\"struct sodiumoxide::crypto::pwhash::scryptsalsa208sha256::Salt\">Salt</a>","impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/hash/trait.Hash.html\" title=\"trait core::hash::Hash\">Hash</a> for <a class=\"struct\" href=\"sodiumoxide/crypto/pwhash/scryptsalsa208sha256/struct.HashedPassword.html\" title=\"struct sodiumoxide::crypto::pwhash::scryptsalsa208sha256::HashedPassword\">HashedPassword</a>","impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/hash/trait.Hash.html\" title=\"trait core::hash::Hash\">Hash</a> for <a class=\"struct\" href=\"sodiumoxide/crypto/stream/xsalsa20/struct.Nonce.html\" title=\"struct sodiumoxide::crypto::stream::xsalsa20::Nonce\">Nonce</a>","impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/hash/trait.Hash.html\" title=\"trait core::hash::Hash\">Hash</a> for <a class=\"struct\" href=\"sodiumoxide/crypto/stream/xchacha20/struct.Nonce.html\" title=\"struct sodiumoxide::crypto::stream::xchacha20::Nonce\">Nonce</a>","impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/hash/trait.Hash.html\" title=\"trait core::hash::Hash\">Hash</a> for <a class=\"struct\" href=\"sodiumoxide/crypto/stream/salsa20/struct.Nonce.html\" title=\"struct sodiumoxide::crypto::stream::salsa20::Nonce\">Nonce</a>","impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/hash/trait.Hash.html\" title=\"trait core::hash::Hash\">Hash</a> for <a class=\"struct\" href=\"sodiumoxide/crypto/stream/chacha20/struct.Nonce.html\" title=\"struct sodiumoxide::crypto::stream::chacha20::Nonce\">Nonce</a>","impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/hash/trait.Hash.html\" title=\"trait core::hash::Hash\">Hash</a> for <a class=\"struct\" href=\"sodiumoxide/crypto/shorthash/siphash24/struct.Digest.html\" title=\"struct sodiumoxide::crypto::shorthash::siphash24::Digest\">Digest</a>",];
implementors["tokio_core"] = ["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/hash/trait.Hash.html\" title=\"trait core::hash::Hash\">Hash</a> for <a class=\"struct\" href=\"tokio_core/reactor/struct.CoreId.html\" title=\"struct tokio_core::reactor::CoreId\">CoreId</a>",];
implementors["tokio_io"] = ["impl&lt;T:&nbsp;<a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/hash/trait.Hash.html\" title=\"trait core::hash::Hash\">Hash</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/hash/trait.Hash.html\" title=\"trait core::hash::Hash\">Hash</a> for <a class=\"struct\" href=\"tokio_io/io/struct.AllowStdIo.html\" title=\"struct tokio_io::io::AllowStdIo\">AllowStdIo</a>&lt;T&gt;","impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/hash/trait.Hash.html\" title=\"trait core::hash::Hash\">Hash</a> for <a class=\"struct\" href=\"tokio_io/codec/struct.BytesCodec.html\" title=\"struct tokio_io::codec::BytesCodec\">BytesCodec</a>","impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/hash/trait.Hash.html\" title=\"trait core::hash::Hash\">Hash</a> for <a class=\"struct\" href=\"tokio_io/codec/struct.LinesCodec.html\" title=\"struct tokio_io::codec::LinesCodec\">LinesCodec</a>",];

            if (window.register_implementors) {
                window.register_implementors(implementors);
            } else {
                window.pending_implementors = implementors;
            }
        
})()
