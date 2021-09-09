//
//  Curve25519.swift
//  CommonCryptoKit
//
//  Created by Adam Kopeć on 29/08/2021.
//  Copyright © 2021 Adam Kopeć.
//
//  Licensed under the MIT License
//

import OpenSSL
import Foundation

/// An elliptic curve that enables X25519 key agreement and ed25519 signatures.
@available(iOS, introduced: 10.0)
@available(tvOS, introduced: 10.0)
@available(watchOS, introduced: 3.0)
@available(macOS, introduced: 10.12)
public enum Curve25519 {
    /// A mechanism used to create or verify a cryptographic signature using Ed25519.
    public enum Signing {
        /// A Curve25519 private key used to create cryptographic signatures.
        public struct PrivateKey {
            /// The OpenSSL `EVP_PKEY_CTX` representation of the current private key.
            fileprivate let pctx: OpenSSLPointer
            /// The OpenSSL `EVP_PKEY` representation of the current private key.
            fileprivate let pkey: OpenSSLPointer
            /// The corresponding public key.
            public var publicKey: PublicKey {
                var publicLength = 0
                EVP_PKEY_get_raw_public_key(pkey.pointer, nil, &publicLength)
                var publicData = Data(count: publicLength)
                publicData.withUnsafeMutableBytes { publicBuffer in
                    let publicPtr = publicBuffer.bindMemory(to: UInt8.self).baseAddress
                    EVP_PKEY_get_raw_public_key(pkey.pointer, publicPtr, &publicLength)
                }
                return try! PublicKey(rawRepresentation: publicData)
            }
            /// A data representation of the private key.
            public var rawRepresentation: Data {
                var privateLength = 0
                EVP_PKEY_get_raw_private_key(pkey.pointer, nil, &privateLength)
                var privateData = Data(count: privateLength)
                privateData.withUnsafeMutableBytes { privateBuffer in
                    let privatePtr = privateBuffer.bindMemory(to: UInt8.self).baseAddress
                    EVP_PKEY_get_raw_private_key(pkey.pointer, privatePtr, &privateLength)
                }
                return privateData.prefix(privateLength)
            }
            /// Creates a random Curve25519 private key for signing.
            public init() {
                pkey = OpenSSLPointer(nil, defer: { pkey in
                    EVP_PKEY_free(pkey)
                })
                pctx = OpenSSLPointer(EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, nil), defer: { pctx in
                    EVP_PKEY_CTX_free(pctx)
                })
                EVP_PKEY_keygen_init(pctx.pointer)
                EVP_PKEY_keygen(pctx.pointer, &pkey.pointer)
                guard pkey.pointer != nil else { fatalError("CCKitError.keyCreationFailure") }
            }
            
            /// Creates a Curve25519 private key for signing from a data representation of the key.
            /// - Parameters:
            ///    - keyData: A raw representation of the key as a collection of contiguous bytes.
            public init<Bytes>(rawRepresentation keyData: Bytes) throws where Bytes: ContiguousBytes {
                let pointer = keyData.withUnsafeBytes { keyBuffer in
                    EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, nil, keyBuffer.bindMemory(to: UInt8.self).baseAddress, keyBuffer.count)
                }
                guard pointer != nil else { throw CCKitError.incorrectKeySize }
                pkey = OpenSSLPointer(pointer, defer: { pkey in
                    EVP_PKEY_free(pkey)
                })
                pctx = OpenSSLPointer(EVP_PKEY_CTX_new(pointer, nil), defer: { pctx in
                    EVP_PKEY_CTX_free(pctx)
                })
            }
        }
        /// A Curve25519 public key used to verify cryptographic signatures.
        public struct PublicKey {
            /// The OpenSSL `EVP_PKEY_CTX` representation of the current private key.
            fileprivate let pctx: OpenSSLPointer
            /// The OpenSSL `EVP_PKEY` representation of the current private key.
            fileprivate let pkey: OpenSSLPointer
            /// A full representation of the public key.
            public var rawRepresentation: Data {
                var publicLength = 0
                EVP_PKEY_get_raw_public_key(pkey.pointer, nil, &publicLength)
                var publicData = Data(count: publicLength)
                publicData.withUnsafeMutableBytes { publicBuffer in
                    let publicPtr = publicBuffer.bindMemory(to: UInt8.self).baseAddress
                    EVP_PKEY_get_raw_public_key(pkey.pointer, publicPtr, &publicLength)
                }
                return publicData
            }
            /// Creates a Curve25519 public key for signing from a collection of bytes.
            /// - Parameters:
            ///    - keyData: A raw representation of the key as a collection of contiguous bytes.
            public init<Bytes>(rawRepresentation keyData: Bytes) throws where Bytes: ContiguousBytes {
                let pointer = keyData.withUnsafeBytes { keyBuffer in
                    EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, nil, keyBuffer.bindMemory(to: UInt8.self).baseAddress, keyBuffer.count)
                }
                guard pointer != nil else { throw CCKitError.incorrectKeySize }
                pkey = OpenSSLPointer(pointer, defer: { pkey in
                    EVP_PKEY_free(pkey)
                })
                pctx = OpenSSLPointer(EVP_PKEY_CTX_new(pointer, nil), defer: { pctx in
                    EVP_PKEY_CTX_free(pctx)
                })
            }
        }
    }
    /// A mechanism used to create a shared secret between two users by performing X25519 key agreement.
    public enum KeyAgreement {
        /// A Curve25519 private key used for key agreement.
        public struct PrivateKey {
            /// The OpenSSL `EVP_PKEY_CTX` representation of the current private key.
            fileprivate let pctx: OpenSSLPointer
            /// The OpenSSL `EVP_PKEY` representation of the current private key.
            fileprivate let pkey: OpenSSLPointer
            /// The corresponding public key.
            public var publicKey: PublicKey {
                var publicLength = 0
                EVP_PKEY_get_raw_public_key(pkey.pointer, nil, &publicLength)
                var publicData = Data(count: publicLength)
                publicData.withUnsafeMutableBytes { publicBuffer in
                    let publicPtr = publicBuffer.bindMemory(to: UInt8.self).baseAddress
                    EVP_PKEY_get_raw_public_key(pkey.pointer, publicPtr, &publicLength)
                }
                return try! PublicKey(rawRepresentation: publicData)
            }
            /// A data representation of the private key.
            public var rawRepresentation: Data {
                var privateLength = 0
                EVP_PKEY_get_raw_private_key(pkey.pointer, nil, &privateLength)
                var privateData = Data(count: privateLength)
                privateData.withUnsafeMutableBytes { privateBuffer in
                    let privatePtr = privateBuffer.bindMemory(to: UInt8.self).baseAddress
                    EVP_PKEY_get_raw_private_key(pkey.pointer, privatePtr, &privateLength)
                }
                return privateData.prefix(privateLength)
            }
            /// Creates a random Curve25519 private key for key agreement.
            public init() {
                pkey = OpenSSLPointer(nil, defer: { pkey in
                    EVP_PKEY_free(pkey)
                })
                pctx = OpenSSLPointer(EVP_PKEY_CTX_new_id(NID_X25519, nil), defer: { pctx in
                    EVP_PKEY_CTX_free(pctx)
                })
                EVP_PKEY_keygen_init(pctx.pointer)
                EVP_PKEY_keygen(pctx.pointer, &pkey.pointer)
                guard pkey.pointer != nil else { fatalError("CCKitError.keyCreationFailure") }
            }
            
            /// Creates a Curve25519 private key for key agreement from a data representation of the key.
            /// - Parameters:
            ///    - keyData: A raw representation of the key as a collection of contiguous bytes.
            public init<Bytes>(rawRepresentation keyData: Bytes) throws where Bytes: ContiguousBytes {
                let pointer = keyData.withUnsafeBytes { keyBuffer in
                    EVP_PKEY_new_raw_private_key(NID_X25519, nil, keyBuffer.bindMemory(to: UInt8.self).baseAddress, keyBuffer.count)
                }
                guard pointer != nil else { throw CCKitError.incorrectKeySize }
                pkey = OpenSSLPointer(pointer, defer: { pkey in
                    EVP_PKEY_free(pkey)
                })
                pctx = OpenSSLPointer(EVP_PKEY_CTX_new(pointer, nil), defer: { pctx in
                    EVP_PKEY_CTX_free(pctx)
                })
            }
        }
        /// A Curve25519 public key used for key agreement.
        public struct PublicKey {
            /// The OpenSSL `EVP_PKEY_CTX` representation of the current private key.
            fileprivate let pctx: OpenSSLPointer
            /// The OpenSSL `EVP_PKEY` representation of the current private key.
            fileprivate let pkey: OpenSSLPointer
            /// A full representation of the public key.
            public var rawRepresentation: Data {
                var publicLength = 0
                EVP_PKEY_get_raw_public_key(pkey.pointer, nil, &publicLength)
                var publicData = Data(count: publicLength)
                publicData.withUnsafeMutableBytes { publicBuffer in
                    let publicPtr = publicBuffer.bindMemory(to: UInt8.self).baseAddress
                    EVP_PKEY_get_raw_public_key(pkey.pointer, publicPtr, &publicLength)
                }
                return publicData
            }
            /// Creates a Curve25519 public key for key agreement from a collection of bytes.
            /// - Parameters:
            ///    - keyData: A raw representation of the key as a collection of contiguous bytes.
            public init<Bytes>(rawRepresentation keyData: Bytes) throws where Bytes: ContiguousBytes {
                let pointer = keyData.withUnsafeBytes { keyBuffer in
                    EVP_PKEY_new_raw_public_key(NID_X25519, nil, keyBuffer.bindMemory(to: UInt8.self).baseAddress, keyBuffer.count)
                }
                guard pointer != nil else { throw CCKitError.incorrectKeySize }
                pkey = OpenSSLPointer(pointer, defer: { pkey in
                    EVP_PKEY_free(pkey)
                })
                pctx = OpenSSLPointer(EVP_PKEY_CTX_new(pointer, nil), defer: { pctx in
                    EVP_PKEY_CTX_free(pctx)
                })
            }
        }
    }
    /// A mechanism used to encrypt ...
    public enum Encryption {
        /// A Curve25519 private key used for encryption.
        public struct PrivateKey {
            /// The OpenSSL `EVP_PKEY_CTX` representation of the current private key.
            fileprivate let pctx: OpenSSLPointer
            /// The OpenSSL `EVP_PKEY` representation of the current private key.
            fileprivate let pkey: OpenSSLPointer
            /// The corresponding public key.
            public var publicKey: PublicKey {
                var publicLength = 0
                EVP_PKEY_get_raw_public_key(pkey.pointer, nil, &publicLength)
                var publicData = Data(count: publicLength)
                publicData.withUnsafeMutableBytes { publicBuffer in
                    let publicPtr = publicBuffer.bindMemory(to: UInt8.self).baseAddress
                    EVP_PKEY_get_raw_public_key(pkey.pointer, publicPtr, &publicLength)
                }
                return try! PublicKey(rawRepresentation: publicData)
            }
            /// A data representation of the private key.
            public var rawRepresentation: Data {
                var privateLength = 0
                EVP_PKEY_get_raw_private_key(pkey.pointer, nil, &privateLength)
                var privateData = Data(count: privateLength)
                privateData.withUnsafeMutableBytes { privateBuffer in
                    let privatePtr = privateBuffer.bindMemory(to: UInt8.self).baseAddress
                    EVP_PKEY_get_raw_private_key(pkey.pointer, privatePtr, &privateLength)
                }
                return privateData.prefix(privateLength)
            }
            /// Creates a random Curve25519 private key for encryption.
            public init() {
                pkey = OpenSSLPointer(nil, defer: { pkey in
                    EVP_PKEY_free(pkey)
                })
                pctx = OpenSSLPointer(EVP_PKEY_CTX_new_id(NID_X25519, nil), defer: { pctx in
                    EVP_PKEY_CTX_free(pctx)
                })
                EVP_PKEY_keygen_init(pctx.pointer)
                EVP_PKEY_keygen(pctx.pointer, &pkey.pointer)
                guard pkey.pointer != nil else { fatalError("CCKitError.keyCreationFailure") }
            }
            
            /// Creates a Curve25519 private key for encryption from a data representation of the key.
            /// - Parameters:
            ///    - keyData: A raw representation of the key as a collection of contiguous bytes.
            public init<Bytes>(rawRepresentation keyData: Bytes) throws where Bytes: ContiguousBytes {
                let pointer = keyData.withUnsafeBytes { keyBuffer in
                    EVP_PKEY_new_raw_private_key(NID_X25519, nil, keyBuffer.bindMemory(to: UInt8.self).baseAddress, keyBuffer.count)
                }
                guard pointer != nil else { throw CCKitError.incorrectKeySize }
                pkey = OpenSSLPointer(pointer, defer: { pkey in
                    EVP_PKEY_free(pkey)
                })
                pctx = OpenSSLPointer(EVP_PKEY_CTX_new(pointer, nil), defer: { pctx in
                    EVP_PKEY_CTX_free(pctx)
                })
            }
        }
        /// A Curve25519 public key used for encryption.
        public struct PublicKey {
            /// The OpenSSL `EVP_PKEY_CTX` representation of the current private key.
            fileprivate let pctx: OpenSSLPointer
            /// The OpenSSL `EVP_PKEY` representation of the current private key.
            fileprivate let pkey: OpenSSLPointer
            /// A full representation of the public key.
            public var rawRepresentation: Data {
                var publicLength = 0
                EVP_PKEY_get_raw_public_key(pkey.pointer, nil, &publicLength)
                var publicData = Data(count: publicLength)
                publicData.withUnsafeMutableBytes { publicBuffer in
                    let publicPtr = publicBuffer.bindMemory(to: UInt8.self).baseAddress
                    EVP_PKEY_get_raw_public_key(pkey.pointer, publicPtr, &publicLength)
                }
                return publicData
            }
            /// Creates a Curve25519 public key for encryption from a collection of bytes.
            /// - Parameters:
            ///    - keyData: A raw representation of the key as a collection of contiguous bytes.
            public init<Bytes>(rawRepresentation keyData: Bytes) throws where Bytes: ContiguousBytes {
                let pointer = keyData.withUnsafeBytes { keyBuffer in
                    EVP_PKEY_new_raw_public_key(NID_X25519, nil, keyBuffer.bindMemory(to: UInt8.self).baseAddress, keyBuffer.count)
                }
                guard pointer != nil else { throw CCKitError.incorrectKeySize }
                pkey = OpenSSLPointer(pointer, defer: { pkey in
                    EVP_PKEY_free(pkey)
                })
                pctx = OpenSSLPointer(EVP_PKEY_CTX_new(pointer, nil), defer: { pctx in
                    EVP_PKEY_CTX_free(pctx)
                })
            }
        }
    }
}

// MARK: - Key Agreement

// Deriving shared symmetric key using ANSI x9.63 method
extension SharedSecret {
    /// Derives a symmetric encryption key from the secret using x9.63 key derivation.
    /// - Parameters:
    ///    - hashFunction: The hash function to use for key derivation.
    ///    - sharedInfo: The shared information to use for key derivation.
    ///    - outputByteCount: The length in bytes of resulting symmetric key.
    ///    - privateKey: The Curve25519 private key.
    ///    - publicKey: The Curve25519 public key.
    /// - Returns: The derived symmetric key.
    static func x963DerivedSymmetricKeyCurve25519<H, SI>(using hashFunction: H.Type, sharedInfo: SI, outputByteCount: Int, privateKey: Curve25519.KeyAgreement.PrivateKey, publicKey: Curve25519.KeyAgreement.PublicKey) throws -> SymmetricKey where H: SHAFunction, SI: DataProtocol {
        // TODO: Implement
        let sharedKey = Data()
        return SymmetricKey(data: sharedKey)
    }
}

// Deriving shared symmetric key using ANSI x9.63 method
@available(iOS, introduced: 10.0)
@available(tvOS, introduced: 10.0)
@available(watchOS, introduced: 3.0)
@available(macOS, introduced: 10.12)
extension Curve25519.KeyAgreement.PrivateKey {
    /// Computes a shared secret with the provided public key from another party.
    /// - Parameters:
    ///    - publicKeyShare: The public key from another party to be combined with the private key from this user to create the shared secret.
    /// - Returns:
    ///     The derived symmetric key.
    public func sharedSecretFromKeyAgreement(with publicKeyShare: Curve25519.KeyAgreement.PublicKey) throws -> SharedSecret {
        return SharedSecret(privateKey: self, publicKey: publicKeyShare)
    }
}

// MARK: - Signing

// Signature Creation
@available(iOS, introduced: 10.0)
@available(tvOS, introduced: 10.0)
@available(watchOS, introduced: 3.0)
@available(macOS, introduced: 10.12)
extension Curve25519.Signing.PrivateKey {
    /// Generates an EdDSA signature over Curve25519.
    /// - Parameters:
    ///    - plaintext: The data to sign.
    /// - Returns: The signature for the data. Although not required by RFC 8032, which describes the Edwards-Curve Digital Signature Algorithm (EdDSA), the CommonCryptoKit implementation (just like the CryptoKit implementation) of the algorithm employs randomization to generate a different signature on every call, even for the same data and key, to guard against side-channel attacks.
    public func signature<D>(for plaintext: D) throws -> Data where D: DataProtocol {
        let ctx = EVP_MD_CTX_new()
        var pctx: OpaquePointer!
        EVP_DigestSignInit(ctx, &pctx, nil, nil, pkey.pointer)
        let result = try Data(plaintext).withUnsafeBytes { plaintextBuffer -> Data in
            let plaintextPtr = plaintextBuffer.bindMemory(to: UInt8.self)
            var signatureLength = 0
            EVP_DigestSign(ctx, nil, &signatureLength, plaintextPtr.baseAddress, plaintextPtr.count)
            var signatureData = Data(count: signatureLength)
            let status = signatureData.withUnsafeMutableBytes { signatureBuffer in
                EVP_DigestSign(ctx, signatureBuffer.bindMemory(to: UInt8.self).baseAddress, &signatureLength, plaintextPtr.baseAddress, plaintextPtr.count)
            }
            guard status != 0 else { throw CCKitError.signatureFailure }
            return signatureData
        }
        EVP_MD_CTX_free(ctx)
        return result
    }
}

// Signature Verification
@available(iOS, introduced: 10.0)
@available(tvOS, introduced: 10.0)
@available(watchOS, introduced: 3.0)
@available(macOS, introduced: 10.12)
extension Curve25519.Signing.PublicKey {
    /// Verifies an EdDSA signature over Curve25519.
    /// - Parameters:
    ///    - signature: The signature to check against the given data.
    ///    - data: The data covered by the signature.
    /// - Returns: A Boolean value that’s true when the signature is valid for the given data.
    public func isValidSignature<S, D>(_ signature: S, for data: D) -> Bool where S: DataProtocol, D: DataProtocol {
        let ctx = EVP_MD_CTX_new()
        var pctx: OpaquePointer!
        EVP_DigestVerifyInit(ctx, &pctx, nil, nil, pkey.pointer)
        let result = Data(data).withUnsafeBytes { plaintextBuffer -> Int32 in
            let plaintextPtr = plaintextBuffer.bindMemory(to: UInt8.self)
            return Data(signature).withUnsafeBytes { signatureBuffer -> Int32 in
                let signaturePtr = signatureBuffer.bindMemory(to: UInt8.self)
                return EVP_DigestVerify(ctx, signaturePtr.baseAddress, signaturePtr.count, plaintextPtr.baseAddress, plaintextPtr.count)
            }
        }
        EVP_MD_CTX_free(ctx)
        return result == 1
    }
}

// MARK: - Encryption
@available(iOS, introduced: 10.0)
@available(tvOS, introduced: 10.0)
@available(watchOS, introduced: 3.0)
@available(macOS, introduced: 10.12)
extension Curve25519.Encryption.PrivateKey {
    // TODO: Implement
}

@available(iOS, introduced: 10.0)
@available(tvOS, introduced: 10.0)
@available(watchOS, introduced: 3.0)
@available(macOS, introduced: 10.12)
extension Curve25519.Encryption.PublicKey {
    // TODO: Implement
}

// MARK: - OpenSSL Helpers

fileprivate class OpenSSLPointer {
    var pointer: OpaquePointer!
    private var dealloc: (OpaquePointer) -> Void
    
    init(_ pointer: OpaquePointer? = nil, defer: @escaping (OpaquePointer) -> Void) {
        self.pointer = pointer
        self.dealloc = `defer`
    }
    
    deinit {
        if let pointer = pointer {
            self.dealloc(pointer)
        }
    }
}
