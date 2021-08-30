//
//  CommonCryptoKitTests.swift
//  CommonCryptoKit
//
//  Created by Adam Kopeć on 03/08/2021.
//  Copyright © 2021 Adam Kopeć.
//
//  Licensed under the MIT License
//

import XCTest
import CommonCrypto
import CryptoKit
@testable import CommonCryptoKit

final class CommonCryptoKitTests: XCTestCase {
    /// Tests P-256 and Curve25519 Private and Public keys as well as their data representations.
    func testECKeys() throws {
        // MARK: P256
        // Verify using rawRepresentation
        
        // Verify CommonCryptoKit -> CryptoKit
        let privateKey = try CommonCryptoKit.P256.Signing.PrivateKey()
        let publicKey = try CryptoKit.P256.Signing.PublicKey(rawRepresentation: privateKey.publicKey.rawRepresentation)
        XCTAssert(publicKey.rawRepresentation == privateKey.publicKey.rawRepresentation)
        XCTAssert(publicKey.x963Representation == privateKey.publicKey.x963Representation)
        // Verify CryptoKit -> CommonCryptoKit
        let privateKey2 = CryptoKit.P256.Signing.PrivateKey()
        let publicKey2 = try CommonCryptoKit.P256.Signing.PublicKey(rawRepresentation: privateKey2.publicKey.rawRepresentation)
        XCTAssert(publicKey2.rawRepresentation == privateKey2.publicKey.rawRepresentation)
        XCTAssert(publicKey2.x963Representation == privateKey2.publicKey.x963Representation)
        
        // Verify using x963Representation
        
        // Verify CommonCryptoKit -> CryptoKit
        let privateKey3 = try CommonCryptoKit.P256.Signing.PrivateKey()
        let publicKey3 = try CryptoKit.P256.Signing.PublicKey(x963Representation: privateKey3.publicKey.x963Representation)
        XCTAssert(publicKey3.x963Representation == privateKey3.publicKey.x963Representation)
        XCTAssert(publicKey3.rawRepresentation == privateKey3.publicKey.rawRepresentation)
        // Verify CryptoKit -> CommonCryptoKit
        let privateKey4 = CryptoKit.P256.Signing.PrivateKey()
        let publicKey4 = try CommonCryptoKit.P256.Signing.PublicKey(x963Representation: privateKey4.publicKey.x963Representation)
        XCTAssert(publicKey4.x963Representation == privateKey4.publicKey.x963Representation)
        XCTAssert(publicKey4.rawRepresentation == privateKey4.publicKey.rawRepresentation)
        
        // MARK: Curve25519
        // Verify using rawRepresentation
        
        // Verify CommonCryptoKit -> CryptoKit
        let privateKey25519 = try CommonCryptoKit.Curve25519.Signing.PrivateKey()
        let publicKey25519 = try CryptoKit.Curve25519.Signing.PublicKey(rawRepresentation: privateKey25519.publicKey.rawRepresentation)
        XCTAssert(publicKey25519.rawRepresentation == privateKey25519.publicKey.rawRepresentation)
        // Verify CryptoKit -> CommonCryptoKit
        let privateKey25519_2 = CryptoKit.Curve25519.Signing.PrivateKey()
        let publicKey25519_2 = try CommonCryptoKit.Curve25519.Signing.PublicKey(rawRepresentation: privateKey25519_2.publicKey.rawRepresentation)
        XCTAssert(publicKey25519_2.rawRepresentation == privateKey25519_2.publicKey.rawRepresentation)
    }
    /// Tests P-256 and Curve25519 signatures.
    func testSigning() throws {
        let dataToSign = "Hello, World!".data(using: .utf8)!
        
        // MARK: P256
        // Test signature creation and verification
        let privateKey = try CommonCryptoKit.P256.Signing.PrivateKey()
        let signature = try privateKey.signature(for: dataToSign)
                
        // Verify derRepresentation
        XCTAssert(try CryptoKit.P256.Signing.ECDSASignature(derRepresentation: signature.derRepresentation).derRepresentation == signature.derRepresentation)
        
        // Verify Signature
        XCTAssert(privateKey.publicKey.isValidSignature(signature, for: dataToSign))
        
        // Make sure the signature validation fails with wrong key
        let newKey = try CommonCryptoKit.P256.Signing.PrivateKey()
        XCTAssert(newKey.publicKey.isValidSignature(signature, for: dataToSign) == false)
        
        // Make sure the signature is verifiable by CryptoKit
        let publicKey = try CryptoKit.P256.Signing.PublicKey(rawRepresentation: privateKey.publicKey.rawRepresentation)
        XCTAssert(publicKey.isValidSignature(try P256.Signing.ECDSASignature(derRepresentation: signature.derRepresentation), for: dataToSign))
        
        // Make sure CryptoKit signature is verifiable by CommonCryptoKit
        let privateKey2 = CryptoKit.P256.Signing.PrivateKey()
        let publicKey2 = try CommonCryptoKit.P256.Signing.PublicKey(rawRepresentation: privateKey2.publicKey.rawRepresentation)
        let signature2 = try privateKey2.signature(for: dataToSign)
        XCTAssert(try publicKey2.isValidSignature(P256.Signing.ECDSASignature(derRepresentation: signature2.derRepresentation), for: dataToSign))
        
        // Make sure the signature is different each time
        XCTAssert(try privateKey.signature(for: dataToSign).derRepresentation != privateKey.signature(for: dataToSign).derRepresentation)
        
        // MARK: Curve25519
        // Test signature creation and verification
        let privateKey25519 = try CommonCryptoKit.Curve25519.Signing.PrivateKey()
        let signature25519 = try privateKey25519.signature(for: dataToSign)
        
        // Verify Signature
        XCTAssert(privateKey25519.publicKey.isValidSignature(signature25519, for: dataToSign))
        
        // Make sure the signature validation fails with wrong key
        let newKey25519 = try CommonCryptoKit.Curve25519.Signing.PrivateKey()
        XCTAssert(newKey25519.publicKey.isValidSignature(signature25519, for: dataToSign) == false)
        
        // Make sure the signature is verifiable by CryptoKit
        let publicKey25519 = try CryptoKit.Curve25519.Signing.PublicKey(rawRepresentation: privateKey25519.publicKey.rawRepresentation)
        XCTAssert(publicKey25519.isValidSignature(signature25519, for: dataToSign))
        
        // Make sure CryptoKit signature is verifiable by CommonCryptoKit
        let privateKey25519_2 = CryptoKit.Curve25519.Signing.PrivateKey()
        let publicKey25519_2 = try CommonCryptoKit.Curve25519.Signing.PublicKey(rawRepresentation: privateKey25519_2.publicKey.rawRepresentation)
        let signature25519_2 = try privateKey25519_2.signature(for: dataToSign)
        XCTAssert(publicKey25519_2.isValidSignature(signature25519_2, for: dataToSign))
        
        // Make sure the signature is different each time
        XCTExpectFailure() // Curve25519 signatures are equal for the same data, this needs to be resolved sometime
        XCTAssert(try privateKey25519.signature(for: dataToSign) != privateKey25519.signature(for: dataToSign))
    }
    /// Tests P-256 and Curve25519 key agreement and shared symmetric key derivation.
    func testKeyAgreement() throws {
        let sharedInfo = "Shared Secret".data(using: .utf8)!

        // MARK: P256
        let alicePrivateKey = try CommonCryptoKit.P256.KeyAgreement.PrivateKey()
        let bobPrivateKey = try CommonCryptoKit.P256.KeyAgreement.PrivateKey()
        let symmetricKey = try alicePrivateKey.sharedSecretFromKeyAgreement(with: bobPrivateKey.publicKey).x963DerivedSymmetricKey(using: SHA256.self, sharedInfo: sharedInfo, outputByteCount: 32)
        
        // Verify the keys are the same
        XCTAssert(try bobPrivateKey.sharedSecretFromKeyAgreement(with: alicePrivateKey.publicKey).x963DerivedSymmetricKey(using: SHA256.self, sharedInfo: sharedInfo, outputByteCount: 32) == symmetricKey)
        
        // Make sure CryptoKit produces the same output
        let samPrivateKey = CryptoKit.P256.KeyAgreement.PrivateKey()
        let alicePublicKey = try CryptoKit.P256.KeyAgreement.PublicKey(rawRepresentation: alicePrivateKey.publicKey.rawRepresentation)
        let samAliceSymmetricKey = try samPrivateKey.sharedSecretFromKeyAgreement(with: alicePublicKey).x963DerivedSymmetricKey(using: SHA256.self, sharedInfo: sharedInfo, outputByteCount: 32)
        let aliceSamSymmetricKey = try alicePrivateKey.sharedSecretFromKeyAgreement(with: CommonCryptoKit.P256.KeyAgreement.PublicKey(rawRepresentation: samPrivateKey.publicKey.rawRepresentation)).x963DerivedSymmetricKey(using: SHA256.self, sharedInfo: sharedInfo, outputByteCount: 32)
        XCTAssert(aliceSamSymmetricKey.asCryptoKitKey == samAliceSymmetricKey)
        
        // MARK: Curve25519
        let alicePrivateKey25519 = try CommonCryptoKit.Curve25519.KeyAgreement.PrivateKey()
        let bobPrivateKey25519 = try CommonCryptoKit.Curve25519.KeyAgreement.PrivateKey()
        let symmetricKey25519 = try alicePrivateKey25519.sharedSecretFromKeyAgreement(with: bobPrivateKey25519.publicKey).x963DerivedSymmetricKey(using: SHA256.self, sharedInfo: sharedInfo, outputByteCount: 32)
        
        // Verify the keys are the same
        XCTAssert(try bobPrivateKey25519.sharedSecretFromKeyAgreement(with: alicePrivateKey25519.publicKey).x963DerivedSymmetricKey(using: SHA256.self, sharedInfo: sharedInfo, outputByteCount: 32) == symmetricKey25519)
        
        // Make sure CryptoKit produces the same output
        let samPrivateKey25519 = CryptoKit.Curve25519.KeyAgreement.PrivateKey()
        let alicePublicKey25519 = try CryptoKit.Curve25519.KeyAgreement.PublicKey(rawRepresentation: alicePrivateKey25519.publicKey.rawRepresentation)
        let samAliceSymmetricKey25519 = try samPrivateKey25519.sharedSecretFromKeyAgreement(with: alicePublicKey25519).x963DerivedSymmetricKey(using: SHA256.self, sharedInfo: sharedInfo, outputByteCount: 32)
        let aliceSamSymmetricKey25519 = try alicePrivateKey25519.sharedSecretFromKeyAgreement(with: CommonCryptoKit.Curve25519.KeyAgreement.PublicKey(rawRepresentation: samPrivateKey25519.publicKey.rawRepresentation)).x963DerivedSymmetricKey(using: SHA256.self, sharedInfo: sharedInfo, outputByteCount: 32)
        XCTAssert(aliceSamSymmetricKey25519.asCryptoKitKey == samAliceSymmetricKey25519)
    }
    /// Tests all implemented hash functions.
    func testHashing() {
        // Verify against CryptoKit
        let plaintextToHash = "Hello, World!".data(using: .utf8)!
        // MD5
        XCTAssert(CommonCryptoKit.Insecure.MD5.hash(data: plaintextToHash).rawRepresentation == CryptoKit.Insecure.MD5.hash(data: plaintextToHash).rawRepresentation)
        // SHA1
        XCTAssert(CommonCryptoKit.Insecure.SHA1.hash(data: plaintextToHash).rawRepresentation == CryptoKit.Insecure.SHA1.hash(data: plaintextToHash).rawRepresentation)
        // SHA256
        XCTAssert(CommonCryptoKit.SHA256.hash(data: plaintextToHash).rawRepresentation == CryptoKit.SHA256.hash(data: plaintextToHash).rawRepresentation)
        // SHA384
        XCTAssert(CommonCryptoKit.SHA384.hash(data: plaintextToHash).rawRepresentation == CryptoKit.SHA384.hash(data: plaintextToHash).rawRepresentation)
        // SHA512
        XCTAssert(CommonCryptoKit.SHA512.hash(data: plaintextToHash).rawRepresentation == CryptoKit.SHA512.hash(data: plaintextToHash).rawRepresentation)
    }
    /// Tests the PBKDF2 key derivation algorithm.
    func testPBKDF2() throws {
        let salt = CommonCryptoKit.SymmetricKey(size: .bits256)
        let plaintextToHash = "Hello, World!".data(using: .utf8)!
        let derivedKey = try PBKDF2.deriveKey(using: SHA256.self, password: plaintextToHash, salt: salt.dataRepresentation, outputByteCount: 32, rounds: 100_000)
        XCTAssert(derivedKey.count == 32)
        XCTAssert(derivedKey != Data(count: 32))
    }
    /// Tests AES encryption in GCM mode.
    func testAES() throws {
        let repetitions = 1
        let string = "Hello, World!".data(using: .utf8)!
        var plaintextToEncrypt = Data(capacity: string.count * repetitions)
        for _ in (0..<repetitions) {
            plaintextToEncrypt.append(string)
        }
        let key = CommonCryptoKit.SymmetricKey(size: .bits256)
        guard let sealed = try CommonCryptoKit.AES.GCM.seal(plaintextToEncrypt, using: key, nonce: nil).combined else { throw CocoaError(.featureUnsupported) }
        XCTAssertNotNil(sealed)
        XCTAssert(try CryptoKit.AES.GCM.open(AES.GCM.SealedBox(combined: sealed), using: key.asCryptoKitKey) == plaintextToEncrypt)
        
        let fileURL = try FileManager.default.url(for: .cachesDirectory, in: .allDomainsMask, appropriateFor: nil, create: true).appendingPathComponent(UUID().uuidString+".xctest")
        defer { try? FileManager.default.removeItem(at: fileURL) }
        try plaintextToEncrypt.write(to: fileURL)
        let nonce = CommonCryptoKit.AES.GCM.Nonce()
        let encURL = try CommonCryptoKit.AES.GCM.seal(fileURL, using: key, nonce: nonce)
        defer { try? FileManager.default.removeItem(at: encURL) }
        let sealedData = try Data(contentsOf: encURL)
        let sealedBox = try CryptoKit.AES.GCM.SealedBox(combined: sealedData)
//        print("CommonCryptoKit encrypted: ")
//        print(sealedBox.nonce.compactMap { String(format: "%02hhx", $0) }.joined())
//        print(sealedBox.ciphertext.compactMap { String(format: "%02hhx", $0) }.joined())
//        let blockCipher = (sealedBox.ciphertext ^ plaintextToEncrypt)
//        print(blockCipher.compactMap { String(format: "%02hhx", $0) }.joined())
//        let counter = try decryptBlock(key: key.dataRepresentation, data: blockCipher.padded)
//        print(counter.compactMap { String(format: "%02hhx", $0) }.joined())
//        print(sealedBox.tag.compactMap { String(format: "%02hhx", $0) }.joined())
        XCTAssert(try CryptoKit.AES.GCM.open(sealedBox, using: key.asCryptoKitKey) == plaintextToEncrypt)
        try CommonCryptoKit.AES.GCM.open(encURL, using: key)
        XCTAssert(try Data(contentsOf: encURL) == plaintextToEncrypt)

        let sealedBoxCrypto = try CryptoKit.AES.GCM.seal(plaintextToEncrypt, using: key.asCryptoKitKey, nonce: AES.GCM.Nonce(data: nonce.dataRepresentation))
//        print("CryptoKit encrypted: ")
//        print(sealedBoxCrypto.nonce.compactMap { String(format: "%02hhx", $0) }.joined())
//        print(sealedBoxCrypto.ciphertext.compactMap { String(format: "%02hhx", $0) }.joined())
//        let blockCipherCrypto = (sealedBoxCrypto.ciphertext ^ plaintextToEncrypt)
//        print(blockCipherCrypto.compactMap { String(format: "%02hhx", $0) }.joined())
//        let counterCrypto = try decryptBlock(key: key.dataRepresentation, data: blockCipherCrypto.padded)
//        print(counterCrypto.compactMap { String(format: "%02hhx", $0) }.joined())
//        print(sealedBoxCrypto.tag.compactMap { String(format: "%02hhx", $0) }.joined())
        try sealedBoxCrypto.combined?.write(to: fileURL)
        try CommonCryptoKit.AES.GCM.open(fileURL, using: key)
        XCTAssert(try Data(contentsOf: fileURL) == plaintextToEncrypt)
    }
    /// Tests AES GCM on running on multiple blocks.
    func testAESMultiBlock() throws {
        var plaintextToEncrypt = "Hello, World!".data(using: .utf8)!
        for _ in (0..<30) {
            plaintextToEncrypt.append("Hello, World!".data(using: .utf8)!)
        }
        let key = CommonCryptoKit.SymmetricKey(size: .bits256)
        guard let sealed = try AES.GCM.seal(plaintextToEncrypt, using: key, nonce: nil).combined else { throw CocoaError(.featureUnsupported) }
        XCTAssertNotNil(sealed)
        XCTAssert(try CryptoKit.AES.GCM.open(AES.GCM.SealedBox(combined: sealed), using: key.asCryptoKitKey) == plaintextToEncrypt)
        
        let fileURL = try FileManager.default.url(for: .cachesDirectory, in: .allDomainsMask, appropriateFor: nil, create: true).appendingPathComponent(UUID().uuidString+".xctest")
        defer { try? FileManager.default.removeItem(at: fileURL) }
        try plaintextToEncrypt.write(to: fileURL)
        let nonce = CommonCryptoKit.AES.GCM.Nonce()
        let encURL = try CommonCryptoKit.AES.GCM.seal(fileURL, using: key, nonce: nonce)
        defer { try? FileManager.default.removeItem(at: encURL) }
        let sealedData = try Data(contentsOf: encURL)
        let sealedBox = try CryptoKit.AES.GCM.SealedBox(combined: sealedData)
        XCTAssert(try CryptoKit.AES.GCM.open(sealedBox, using: key.asCryptoKitKey) == plaintextToEncrypt)
        try CommonCryptoKit.AES.GCM.open(encURL, using: key)
        XCTAssert(try Data(contentsOf: encURL) == plaintextToEncrypt)

        let sealedBoxCrypto = try CryptoKit.AES.GCM.seal(plaintextToEncrypt, using: key.asCryptoKitKey, nonce: AES.GCM.Nonce(data: nonce.dataRepresentation))
        try sealedBoxCrypto.combined?.write(to: fileURL)
        try CommonCryptoKit.AES.GCM.open(fileURL, using: key)
        XCTAssert(try Data(contentsOf: fileURL) == plaintextToEncrypt)
    }
    /// Tests AES GCM encryption with chunking.
    func testAESIncremental() throws {
        let repetitions = 3_000
        let string = "Hello, World!".data(using: .utf8)!
        var plaintextToEncrypt = Data(capacity: string.count * repetitions)
        for _ in (0..<repetitions) {
            plaintextToEncrypt.append(string)
        }
        let key = CommonCryptoKit.SymmetricKey(size: .bits256)
        let fileURL = try FileManager.default.url(for: .cachesDirectory, in: .allDomainsMask, appropriateFor: nil, create: true).appendingPathComponent(UUID().uuidString+".xctest")
        defer { try? FileManager.default.removeItem(at: fileURL) }
        try plaintextToEncrypt.write(to: fileURL)
        var sealedData = Data()
        try CommonCryptoKit.AES.GCM.seal(fileURL, using: key, splittingIntoParts: 1000) { partURL in
            try? sealedData.append(contentsOf: Data(contentsOf: partURL))
            try? FileManager.default.removeItem(at: partURL)
        }
        let sealedBox = try CryptoKit.AES.GCM.SealedBox(combined: sealedData)
        XCTAssert(try CryptoKit.AES.GCM.open(sealedBox, using: key.asCryptoKitKey) == plaintextToEncrypt)
        let encURL = try FileManager.default.url(for: .cachesDirectory, in: .allDomainsMask, appropriateFor: nil, create: true).appendingPathComponent(UUID().uuidString+".xctest")
        defer { try? FileManager.default.removeItem(at: encURL) }
        try sealedData.write(to: encURL)
        try CommonCryptoKit.AES.GCM.open(encURL, using: key)
        XCTAssert(try Data(contentsOf: encURL) == plaintextToEncrypt)
    }
    /// Tests ChaCha20 with Poly1305 encryption.
    func testChaCha() throws {
        let repetitions = 1
        let string = "Hello, World!".data(using: .utf8)!
        var plaintextToEncrypt = Data(capacity: string.count * repetitions)
        for _ in (0..<repetitions) {
            plaintextToEncrypt.append(string)
        }
        let key = CommonCryptoKit.SymmetricKey(size: .bits256)
        let sealed = try ChaChaPoly.seal(plaintextToEncrypt, using: key)
        let nonce = sealed.nonce
//        print("CommonCryptoKit encrypted: ")
//        print(sealed.nonce.compactMap { String(format: "%02hhx", $0) }.joined())
//        print(sealed.ciphertext.compactMap { String(format: "%02hhx", $0) }.joined())
//        print(sealed.tag.compactMap { String(format: "%02hhx", $0) }.joined())
        let cryptoSealed = try CryptoKit.ChaChaPoly.seal(plaintextToEncrypt, using: key.asCryptoKitKey, nonce: CryptoKit.ChaChaPoly.Nonce(data: nonce.dataRepresentation))
//        print("CryptoKit encrypted: ")
//        print(cryptoSealed.nonce.compactMap { String(format: "%02hhx", $0) }.joined())
//        print(cryptoSealed.ciphertext.compactMap { String(format: "%02hhx", $0) }.joined())
//        print(cryptoSealed.tag.compactMap { String(format: "%02hhx", $0) }.joined())
        XCTAssert(try CryptoKit.ChaChaPoly.open(ChaChaPoly.SealedBox(combined: sealed.combined), using: key.asCryptoKitKey) == plaintextToEncrypt)
        XCTAssert(try CommonCryptoKit.ChaChaPoly.open(ChaChaPoly.SealedBox(combined: cryptoSealed.combined), using: key) == plaintextToEncrypt)
    }
}

fileprivate extension Data {
    static func ^(lhs: Data, rhs: Data) -> Data {
        let count = Swift.min(lhs.count, rhs.count)
        var result: Data = Data(count: count)
        
        for i in 0..<count {
            result[i] = lhs[lhs.startIndex + i] ^ rhs[rhs.startIndex + i]
        }
        
        return result
    }
    var padded: Data {
        let count  = 16 - self.count % 16

        if count > 0 {
            return self + Data(count: count)
        }
        
        return self
    }
}

fileprivate func decryptBlock(key: Data, data: Data) throws -> Data {
    if data.count != 16 {
        throw CCKitError.incorrectParameterSize
    }
    
    let operation = CCOperation(kCCDecrypt)
    let algorithm = CCAlgorithm(kCCAlgorithmAES)
    let options   = CCOptions(kCCOptionECBMode)
    
    var ciphertext = Data(count: data.count)
    var num = 0
    
    let status = ciphertext.withUnsafeMutableBytes { ciphertextBuffer in
        data.withUnsafeBytes { dataBuffer in
            key.withUnsafeBytes{ keyBuffer in
                CCCrypt(operation, algorithm, options, keyBuffer.baseAddress, keyBuffer.count, nil, dataBuffer.baseAddress, dataBuffer.count, ciphertextBuffer.baseAddress, ciphertextBuffer.count, &num)
            }
        }
    }
    
    if status != kCCSuccess {
        // TODO: Make it into a more correct error
        throw CCKitError.authenticationFailure
    }
    
    return ciphertext
}
