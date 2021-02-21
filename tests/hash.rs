use common_crypto::hash::Hash;

#[test]
fn sha1() {
    assert_eq!(
        &Hash::sha1(b"data")[..],
        hex::decode("a17c9aaa61e80a1bf71d0d850af4e5baa9800bbd").unwrap()
    );
}

#[test]
fn sha224() {
    assert_eq!(
        &Hash::sha224(b"data")[..],
        hex::decode("f4739673acc03c424343b452787ee23dd62999a8a9f14f4250995769").unwrap()
    );
}

#[test]
fn sha256() {
    assert_eq!(
        &Hash::sha256(b"data")[..],
        hex::decode("3a6eb0790f39ac87c94f3856b2dd2c5d110e6811602261a9a923d3bb23adc8b7").unwrap()
    );
}

#[test]
fn sha384() {
    assert_eq!(
        &Hash::sha384(b"data")[..],
        hex::decode("2039e0f0b92728499fb88e23ebc3cfd0554b28400b0ed7b753055c88b5865c3c2aa72c6a1a9ae0a755d87900a4a6ff41").unwrap()
    );
}

#[test]
fn sha512() {
    assert_eq!(
        &Hash::sha512(b"data")[..],
        hex::decode("77c7ce9a5d86bb386d443bb96390faa120633158699c8844c30b13ab0bf92760b7e4416aea397db91b4ac0e5dd56b8ef7e4b066162ab1fdc088319ce6defc876").unwrap()
    );
}
