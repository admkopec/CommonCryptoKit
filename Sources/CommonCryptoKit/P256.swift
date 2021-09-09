//
//  P256.swift
//  CommonCryptoKit
//
//  Created by Adam Kopeć on 03/08/2021.
//  Copyright © 2021 Adam Kopeć.
//
//  Licensed under the MIT License
//

import Security
import Foundation

#if canImport(CryptoKit)
import CryptoKit
#endif

/// An elliptic curve that enables NIST P-256 signatures and key agreement.
@available(iOS, introduced: 10.0)
@available(tvOS, introduced: 10.0)
@available(watchOS, introduced: 3.0)
@available(macOS, introduced: 10.12)
public enum P256 {
    /// A mechanism used to create or verify a cryptographic signature using the NIST P-256 elliptic curve digital signature algorithm (ECDSA).
    @available(iOS, introduced: 10.0/*, deprecated: 14.0, message: "This API is deprecated, please use CryptoKit directly."*/)
    @available(tvOS, introduced: 10.0/*, deprecated: 13.0, message: "This API is deprecated, please use CryptoKit directly."*/)
    @available(watchOS, introduced: 3.0/*, deprecated: 6.0, message: "This API is deprecated, please use CryptoKit directly."*/)
    @available(macOS, introduced: 10.12/*, deprecated: 11.0, message: "This API is deprecated, please use CryptoKit directly."*/)
    public enum Signing {
        /// A P-256 private key used to create cryptographic signatures.
        public struct PrivateKey {
            /// The CommonCrypto `SecKey` representation of the current private key.
            fileprivate let secKey: SecKey
            /// The corresponding public key.
            public var publicKey: PublicKey {
                return PublicKey(secKey: SecKeyCopyPublicKey(secKey)!)
            }
            /// An ANSI x9.63 representation of the private key.
            public var x963Representation: Data {
                var error: Unmanaged<CFError>?
                guard let data = SecKeyCopyExternalRepresentation(secKey, &error) as NSData? else { fatalError("Couldn't get x9.63 representation") }
                return Data(data)
            }
            /// A data representation of the private key.
            public var rawRepresentation: Data {
                let x963 = x963Representation
                guard x963.first == 04, x963.count == 65 else {
                    // Not an x9.63 representation
                    fatalError("Not an x9.63 representation")
                }
                return x963.dropFirst()
            }
            #if canImport(CryptoKit)
            /// A Distinguished Encoding Rules (DER) encoded representation of the private key.
            @available(iOS 14.0, tvOS 14.0, watchOS 7.0, macOS 11.0, *)
            public var derRepresentation: Data {
                try! CryptoKit.P256.Signing.PrivateKey(x963Representation: x963Representation).derRepresentation
            }
            /// A Privacy-Enhanced Mail (PEM) representation of the private key.
            @available(iOS 14.0, tvOS 14.0, watchOS 7.0, macOS 11.0, *)
            public var pemRepresentation: String {
                try! CryptoKit.P256.Signing.PrivateKey(x963Representation: x963Representation).pemRepresentation
            }
            #endif
            /// Creates a random P-256 private key for signing.
            public init() {
                let attributes: [String: Any] = [kSecAttrKeySizeInBits as String: 256,
                                                 kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
                                                 kSecPrivateKeyAttrs as String: [kSecAttrIsPermanent as String: false],
                                                 kSecPublicKeyAttrs as String:[kSecAttrIsPermanent as String: false]]
                var error: Unmanaged<CFError>?

                guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
                    fatalError("CCKitError.keyCreationFailure: \(error?.takeRetainedValue().localizedDescription ?? "Unknonw")")
                }
                secKey = privateKey
            }
            
            /// Creates a P-256 private key for signing from a data representation of the key.
            /// - Parameters:
            ///    - keyData: A raw representation of the key as a collection of contiguous bytes.
            public init<Bytes>(rawRepresentation keyData: Bytes) throws where Bytes: ContiguousBytes {
                let x963 = Data([04])+keyData.dataRepresentation
                guard x963.count == 65 else { throw CCKitError.incorrectKeySize }
                try self.init(x963Representation: x963)
            }
            
            /// Creates a P-256 private key for signing from an ANSI x9.63 representation of the key.
            /// - Parameters:
            ///    - keyData: An ANSI x9.63 representation of the key.
            public init<Bytes>(x963Representation keyData: Bytes) throws where Bytes: ContiguousBytes {
                let data = keyData.dataRepresentation
                guard data.count == 65 else { throw CCKitError.incorrectKeySize }
                var error: Unmanaged<CFError>?
                let attributes: [String:Any] = [kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
                                                kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
                                                kSecAttrKeySizeInBits as String: 256]

                guard let privateKey = SecKeyCreateWithData(Data(data) as CFData , attributes as CFDictionary, &error) else {
                    throw error?.takeRetainedValue() ?? CCKitError.keyCreationFailure
                }
                secKey = privateKey
            }
            #if canImport(CryptoKit)
            /// Creates a P-256 private key for signing from a Distinguished Encoding Rules (DER) encoded representation.
            /// - Parameters:
            ///    - keyData: A DER-encoded representation of the key.
            @available(iOS 14.0, tvOS 14.0, watchOS 7.0, macOS 11.0, *)
            public init<Bytes>(derRepresentation keyData: Bytes) throws where Bytes: RandomAccessCollection, Bytes.Element == UInt8 {
                let privateKey = try CryptoKit.P256.Signing.PrivateKey(derRepresentation: keyData)
                try self.init(x963Representation: privateKey.x963Representation)
            }
            
            /// Creates a P-256 private key for signing from a Privacy-Enhanced Mail (PEM) representation.
            /// - Parameters:
            ///    - keyData: A PEM representation of the key.
            @available(iOS 14.0, tvOS 14.0, watchOS 7.0, macOS 11.0, *)
            public init(pemRepresentation keyData: String) throws {
                let privateKey = try CryptoKit.P256.Signing.PrivateKey(pemRepresentation: keyData)
                try self.init(x963Representation: privateKey.x963Representation)
            }
            #endif
        }
        /// A P-256 public key used to verify cryptographic signatures.
        public struct PublicKey {
            /// The CommonCrypto `SecKey` representation of the current private key.
            fileprivate let secKey: SecKey
            /// An ANSI x9.63 representation of the public key.
            public var x963Representation: Data! {
                var error: Unmanaged<CFError>?
                guard let data = SecKeyCopyExternalRepresentation(secKey, &error) as NSData? else { return nil }
                return Data(data)
            }
            /// A full representation of the public key.
            public var rawRepresentation: Data! {
                let x963 = x963Representation
                guard x963?.first == 04, x963?.count == 65 else {
                    // Not an x9.63 representation
                    return nil
                }
                return x963?.dropFirst()
            }
            #if canImport(CryptoKit)
            /// A Distinguished Encoding Rules (DER) encoded representation of the private key.
            @available(iOS 14.0, tvOS 14.0, watchOS 7.0, macOS 11.0, *)
            public var derRepresentation: Data {
                try! CryptoKit.P256.Signing.PublicKey(x963Representation: x963Representation).derRepresentation
            }
            /// A Privacy-Enhanced Mail (PEM) representation of the private key.
            @available(iOS 14.0, tvOS 14.0, watchOS 7.0, macOS 11.0, *)
            public var pemRepresentation: String {
                try! CryptoKit.P256.Signing.PublicKey(x963Representation: x963Representation).pemRepresentation
            }
            #endif
            /// Create the public key from CommonCrypto's `SecKey`.
            fileprivate init(secKey: SecKey) {
                self.secKey = secKey
            }
            /// Creates a P-256 public key from a collection of bytes.
            /// - Parameters:
            ///    - keyData: A raw representation of the key as a collection of contiguous bytes.
            public init<Bytes>(rawRepresentation keyData: Bytes) throws where Bytes: ContiguousBytes {
                let x963 = Data([04])+keyData.dataRepresentation
                guard x963.count == 65 else { throw CCKitError.incorrectKeySize }
                try self.init(x963Representation: x963)
            }
            /// Creates a P-256 public key from an ANSI x9.63 representation.
            /// - Parameters:
            ///    - keyData: An ANSI x9.63 representation of the key.
            public init<Bytes>(x963Representation keyData: Bytes) throws where Bytes: ContiguousBytes {
                let data = keyData.dataRepresentation
                guard data.count == 65 else { throw CCKitError.incorrectKeySize }
                var error: Unmanaged<CFError>?
                let attributes: [String:Any] = [kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
                                                kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
                                                kSecAttrKeySizeInBits as String: 256]

                guard let publicKey = SecKeyCreateWithData(Data(data) as CFData , attributes as CFDictionary, &error) else {
                    throw error?.takeRetainedValue() ?? CCKitError.keyCreationFailure
                }
                secKey = publicKey
            }
        }
    }
    /// A mechanism used to create a shared secret between two users by performing NIST P-256 elliptic curve Diffie Hellman (ECDH) key exchange.
    @available(iOS, introduced: 10.0/*, deprecated: 14.0, message: "This API is deprecated, please use CryptoKit directly."*/)
    @available(tvOS, introduced: 10.0/*, deprecated: 13.0, message: "This API is deprecated, please use CryptoKit directly."*/)
    @available(watchOS, introduced: 3.0/*, deprecated: 6.0, message: "This API is deprecated, please use CryptoKit directly."*/)
    @available(macOS, introduced: 10.12/*, deprecated: 11.0, message: "This API is deprecated, please use CryptoKit directly."*/)
    public enum KeyAgreement {
        /// A P-256 private key used for key agreement.
        public struct PrivateKey {
            /// The CommonCrypto `SecKey` representation of the current private key.
            fileprivate let secKey: SecKey
            /// The corresponding public key.
            public var publicKey: PublicKey {
                return PublicKey(secKey: SecKeyCopyPublicKey(secKey)!)
            }
            /// An ANSI x9.63 representation of the private key.
            public var x963Representation: Data {
                var error: Unmanaged<CFError>?
                guard let data = SecKeyCopyExternalRepresentation(secKey, &error) as NSData? else { fatalError("Couldn't get x9.63 representation") }
                return Data(data)
            }
            /// A data representation of the private key.
            public var rawRepresentation: Data {
                let x963 = x963Representation
                guard x963.first == 04, x963.count == 65 else {
                    // Not an x9.63 representation
                    fatalError("Not an x9.63 representation")
                }
                return x963.dropFirst()
            }
            #if canImport(CryptoKit)
            /// A Distinguished Encoding Rules (DER) encoded representation of the private key.
            @available(iOS 14.0, tvOS 14.0, watchOS 7.0, macOS 11.0, *)
            public var derRepresentation: Data {
                try! CryptoKit.P256.KeyAgreement.PrivateKey(x963Representation: x963Representation).derRepresentation
            }
            /// A Privacy-Enhanced Mail (PEM) representation of the private key.
            @available(iOS 14.0, tvOS 14.0, watchOS 7.0, macOS 11.0, *)
            public var pemRepresentation: String {
                try! CryptoKit.P256.KeyAgreement.PrivateKey(x963Representation: x963Representation).pemRepresentation
            }
            #endif
            /// Creates a random P-256 private key for key agreement.
            public init() {
                let attributes: [String: Any] = [kSecAttrKeySizeInBits as String: 256,
                                                 kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
                                                 kSecPrivateKeyAttrs as String: [kSecAttrIsPermanent as String: false],
                                                 kSecPublicKeyAttrs as String:[kSecAttrIsPermanent as String: false]]
                var error: Unmanaged<CFError>?

                guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
                    fatalError("CCKitError.keyCreationFailure: \(error?.takeRetainedValue().localizedDescription ?? "Unknonw")")
                }
                secKey = privateKey
            }
            
            /// Creates a P-256 private key for key agreement from a collection of bytes.
            /// - Parameters:
            ///    - keyData: A raw representation of the key as a collection of contiguous bytes.
            public init<Bytes>(rawRepresentation keyData: Bytes) throws where Bytes: ContiguousBytes {
                let x963 = Data([04])+keyData.dataRepresentation
                guard x963.count == 65 else { throw CCKitError.incorrectKeySize }
                try self.init(x963Representation: x963)
            }
            
            /// Creates a P-256 private key for key agreement from an ANSI x9.63 representation.
            /// - Parameters:
            ///    - keyData: An ANSI x9.63 representation of the key.
            public init<Bytes>(x963Representation keyData: Bytes) throws where Bytes: ContiguousBytes {
                let data = keyData.dataRepresentation
                guard data.count == 65 else { throw CCKitError.incorrectKeySize }
                var error: Unmanaged<CFError>?
                let attributes: [String:Any] = [kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
                                                kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
                                                kSecAttrKeySizeInBits as String: 256]

                guard let privateKey = SecKeyCreateWithData(Data(data) as CFData , attributes as CFDictionary, &error) else {
                    throw error?.takeRetainedValue() ?? CCKitError.keyCreationFailure
                }
                secKey = privateKey
            }
            #if canImport(CryptoKit)
            /// Creates a P-256 private key for key agreement from a Distinguished Encoding Rules (DER) encoded representation.
            /// - Parameters:
            ///    - keyData: A DER-encoded representation of the key.
            @available(iOS 14.0, tvOS 14.0, watchOS 7.0, macOS 11.0, *)
            public init<Bytes>(derRepresentation keyData: Bytes) throws where Bytes: RandomAccessCollection, Bytes.Element == UInt8 {
                let privateKey = try CryptoKit.P256.KeyAgreement.PrivateKey(derRepresentation: keyData)
                try self.init(x963Representation: privateKey.x963Representation)
            }
            
            /// Creates a P-256 private key for key agreement from a Privacy-Enhanced Mail (PEM) representation.
            /// - Parameters:
            ///    - keyData: A PEM representation of the key.
            @available(iOS 14.0, tvOS 14.0, watchOS 7.0, macOS 11.0, *)
            public init(pemRepresentation keyData: String) throws {
                let privateKey = try CryptoKit.P256.KeyAgreement.PrivateKey(pemRepresentation: keyData)
                try self.init(x963Representation: privateKey.x963Representation)
            }
            #endif
        }
        /// A P-256 public key used for key agreement.
        public struct PublicKey {
            /// The CommonCrypto `SecKey` representation of the current private key.
            fileprivate let secKey: SecKey
            /// An ANSI x9.63 representation of the public key.
            public var x963Representation: Data! {
                var error: Unmanaged<CFError>?
                guard let data = SecKeyCopyExternalRepresentation(secKey, &error) as NSData? else { return nil }
                return Data(data)
            }
            /// A full representation of the public key.
            public var rawRepresentation: Data! {
                let x963 = x963Representation
                guard x963?.first == 04, x963?.count == 65 else {
                    // Not an x9.63 representation
                    return nil
                }
                return x963?.dropFirst()
            }
            #if canImport(CryptoKit)
            /// A Distinguished Encoding Rules (DER) encoded representation of the private key.
            @available(iOS 14.0, tvOS 14.0, watchOS 7.0, macOS 11.0, *)
            public var derRepresentation: Data {
                try! CryptoKit.P256.KeyAgreement.PublicKey(x963Representation: x963Representation).derRepresentation
            }
            /// A Privacy-Enhanced Mail (PEM) representation of the private key.
            @available(iOS 14.0, tvOS 14.0, watchOS 7.0, macOS 11.0, *)
            public var pemRepresentation: String {
                try! CryptoKit.P256.KeyAgreement.PublicKey(x963Representation: x963Representation).pemRepresentation
            }
            #endif
            /// Create the public key from CommonCrypto's `SecKey`.
            fileprivate init(secKey: SecKey) {
                self.secKey = secKey
            }
            /// Creates a P-256 public key for key agreement from a collection of bytes.
            /// - Parameters:
            ///    - keyData: A raw representation of the key as a collection of contiguous bytes.
            public init<Bytes>(rawRepresentation keyData: Bytes) throws where Bytes: ContiguousBytes {
                let x963 = Data([04])+keyData.dataRepresentation
                guard x963.count == 65 else { throw CCKitError.incorrectKeySize }
                try self.init(x963Representation: x963)
            }
            #if canImport(CryptoKit)
            /// Creates a P-256 public key for key agreement from a compact representation of the key.
            /// - Parameters:
            ///    - keyData: A compact representation of the key as a collection of contiguous bytes.
            @available(iOS 13.0, tvOS 13.0, watchOS 6.0, macOS 10.15, iOSApplicationExtension 14.0, *)
            public init<Bytes>(compactRepresentation keyData: Bytes) throws where Bytes: ContiguousBytes {
                let publicKey = try CryptoKit.P256.KeyAgreement.PublicKey(compactRepresentation: keyData)
                try self.init(x963Representation: publicKey.x963Representation)
            }
            #endif
            /// Creates a P-256 public key for key agreement from an ANSI x9.63 representation.
            /// - Parameters:
            ///    - keyData: An ANSI x9.63 representation of the key.
            public init<Bytes>(x963Representation keyData: Bytes) throws where Bytes: ContiguousBytes {
                let data = keyData.dataRepresentation
                guard data.count == 65 else { throw CCKitError.incorrectKeySize }
                var error: Unmanaged<CFError>?
                let attributes: [String:Any] = [kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
                                                kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
                                                kSecAttrKeySizeInBits as String: 256]

                guard let publicKey = SecKeyCreateWithData(Data(data) as CFData , attributes as CFDictionary, &error) else {
                    throw error?.takeRetainedValue() ?? CCKitError.keyCreationFailure
                }
                secKey = publicKey
            }
            #if canImport(CryptoKit)
            /// Creates a P-256 public key for key agreement from a Distinguished Encoding Rules (DER) encoded representation.
            /// - Parameters:
            ///    - keyData: A DER-encoded representation of the key.
            @available(iOS 14.0, tvOS 14.0, watchOS 7.0, macOS 11.0, *)
            public init<Bytes>(derRepresentation keyData: Bytes) throws where Bytes: RandomAccessCollection, Bytes.Element == UInt8 {
                let publicKey = try CryptoKit.P256.KeyAgreement.PublicKey(derRepresentation: keyData)
                try self.init(x963Representation: publicKey.x963Representation)
            }
            
            /// Creates a P-256 public key for key agreement from a Privacy-Enhanced Mail (PEM) representation.
            /// - Parameters:
            ///    - keyData: A PEM representation of the key.
            @available(iOS 14.0, tvOS 14.0, watchOS 7.0, macOS 11.0, *)
            public init(pemRepresentation keyData: String) throws {
                let publicKey = try CryptoKit.P256.KeyAgreement.PublicKey(pemRepresentation: keyData)
                try self.init(x963Representation: publicKey.x963Representation)
            }
            #endif
        }
    }
    /// A mechanism used to encrypt ...
    public enum Encryption {
        /// A P-256 private key used for encryption.
        public struct PrivateKey {
            /// The CommonCrypto `SecKey` representation of the current private key.
            fileprivate let secKey: SecKey
            /// The corresponding public key.
            public var publicKey: PublicKey {
                return PublicKey(secKey: SecKeyCopyPublicKey(secKey)!)
            }
            /// An ANSI x9.63 representation of the private key.
            public var x963Representation: Data {
                var error: Unmanaged<CFError>?
                guard let data = SecKeyCopyExternalRepresentation(secKey, &error) as NSData? else { fatalError("Couldn't get x9.63 representation") }
                return Data(data)
            }
            /// A data representation of the private key.
            public var rawRepresentation: Data {
                let x963 = x963Representation
                guard x963.first == 04, x963.count == 65 else {
                    // Not an x9.63 representation
                    fatalError("Not an x9.63 representation")
                }
                return x963.dropFirst()
            }
            #if canImport(CryptoKit)
            /// A Distinguished Encoding Rules (DER) encoded representation of the private key.
            @available(iOS 14.0, tvOS 14.0, watchOS 7.0, macOS 11.0, *)
            public var derRepresentation: Data {
                try! CryptoKit.P256.KeyAgreement.PrivateKey(x963Representation: x963Representation).derRepresentation
            }
            /// A Privacy-Enhanced Mail (PEM) representation of the private key.
            @available(iOS 14.0, tvOS 14.0, watchOS 7.0, macOS 11.0, *)
            public var pemRepresentation: String {
                try! CryptoKit.P256.KeyAgreement.PrivateKey(x963Representation: x963Representation).pemRepresentation
            }
            #endif
            /// Creates a random P-256 private key for encryption.
            public init() {
                let attributes: [String: Any] = [kSecAttrKeySizeInBits as String: 256,
                                                 kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
                                                 kSecPrivateKeyAttrs as String: [kSecAttrIsPermanent as String: false],
                                                 kSecPublicKeyAttrs as String:[kSecAttrIsPermanent as String: false]]
                var error: Unmanaged<CFError>?

                guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
                    fatalError("CCKitError.keyCreationFailure: \(error?.takeRetainedValue().localizedDescription ?? "Unknonw")")
                }
                secKey = privateKey
            }
            
            /// Creates a P-256 private key for encryption from a collection of bytes.
            /// - Parameters:
            ///    - keyData: A raw representation of the key as a collection of contiguous bytes.
            public init<Bytes>(rawRepresentation keyData: Bytes) throws where Bytes: ContiguousBytes {
                let x963 = Data([04])+keyData.dataRepresentation
                guard x963.count == 65 else { throw CCKitError.incorrectKeySize }
                try self.init(x963Representation: x963)
            }
            
            /// Creates a P-256 private key for encryption from an ANSI x9.63 representation.
            /// - Parameters:
            ///    - keyData: An ANSI x9.63 representation of the key.
            public init<Bytes>(x963Representation keyData: Bytes) throws where Bytes: ContiguousBytes {
                let data = keyData.dataRepresentation
                guard data.count == 65 else { throw CCKitError.incorrectKeySize }
                var error: Unmanaged<CFError>?
                let attributes: [String:Any] = [kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
                                                kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
                                                kSecAttrKeySizeInBits as String: 256]

                guard let privateKey = SecKeyCreateWithData(Data(data) as CFData , attributes as CFDictionary, &error) else {
                    throw error?.takeRetainedValue() ?? CCKitError.keyCreationFailure
                }
                secKey = privateKey
            }
            #if canImport(CryptoKit)
            /// Creates a P-256 private key for encryption from a Distinguished Encoding Rules (DER) encoded representation.
            /// - Parameters:
            ///    - keyData: A DER-encoded representation of the key.
            @available(iOS 14.0, tvOS 14.0, watchOS 7.0, macOS 11.0, *)
            public init<Bytes>(derRepresentation keyData: Bytes) throws where Bytes: RandomAccessCollection, Bytes.Element == UInt8 {
                let privateKey = try CryptoKit.P256.KeyAgreement.PrivateKey(derRepresentation: keyData)
                try self.init(x963Representation: privateKey.x963Representation)
            }
            
            /// Creates a P-256 private key for encryption from a Privacy-Enhanced Mail (PEM) representation.
            /// - Parameters:
            ///    - keyData: A PEM representation of the key.
            @available(iOS 14.0, tvOS 14.0, watchOS 7.0, macOS 11.0, *)
            public init(pemRepresentation keyData: String) throws {
                let privateKey = try CryptoKit.P256.KeyAgreement.PrivateKey(pemRepresentation: keyData)
                try self.init(x963Representation: privateKey.x963Representation)
            }
            #endif
        }
        /// A P-256 public key used for encryption.
        public struct PublicKey {
            /// The CommonCrypto `SecKey` representation of the current private key.
            fileprivate let secKey: SecKey
            /// An ANSI x9.63 representation of the public key.
            public var x963Representation: Data! {
                var error: Unmanaged<CFError>?
                guard let data = SecKeyCopyExternalRepresentation(secKey, &error) as NSData? else { return nil }
                return Data(data)
            }
            /// A full representation of the public key.
            public var rawRepresentation: Data! {
                let x963 = x963Representation
                guard x963?.first == 04, x963?.count == 65 else {
                    // Not an x9.63 representation
                    return nil
                }
                return x963?.dropFirst()
            }
            #if canImport(CryptoKit)
            /// A Distinguished Encoding Rules (DER) encoded representation of the private key.
            @available(iOS 14.0, tvOS 14.0, watchOS 7.0, macOS 11.0, *)
            public var derRepresentation: Data {
                try! CryptoKit.P256.KeyAgreement.PublicKey(x963Representation: x963Representation).derRepresentation
            }
            /// A Privacy-Enhanced Mail (PEM) representation of the private key.
            @available(iOS 14.0, tvOS 14.0, watchOS 7.0, macOS 11.0, *)
            public var pemRepresentation: String {
                try! CryptoKit.P256.KeyAgreement.PublicKey(x963Representation: x963Representation).pemRepresentation
            }
            #endif
            /// Create the public key from CommonCrypto's `SecKey`.
            fileprivate init(secKey: SecKey) {
                self.secKey = secKey
            }
            /// Creates a P-256 public key for encryption from a collection of bytes.
            /// - Parameters:
            ///    - keyData: A raw representation of the key as a collection of contiguous bytes.
            public init<Bytes>(rawRepresentation keyData: Bytes) throws where Bytes: ContiguousBytes {
                let x963 = Data([04])+keyData.dataRepresentation
                guard x963.count == 65 else { throw CCKitError.incorrectKeySize }
                try self.init(x963Representation: x963)
            }
            #if canImport(CryptoKit)
            /// Creates a P-256 public key for encryption from a compact representation of the key.
            /// - Parameters:
            ///    - keyData: A compact representation of the key as a collection of contiguous bytes.
            @available(iOS 13.0, tvOS 13.0, watchOS 6.0, macOS 10.15, iOSApplicationExtension 14.0, *)
            public init<Bytes>(compactRepresentation keyData: Bytes) throws where Bytes: ContiguousBytes {
                let publicKey = try CryptoKit.P256.KeyAgreement.PublicKey(compactRepresentation: keyData)
                try self.init(x963Representation: publicKey.x963Representation)
            }
            #endif
            /// Creates a P-256 public key for encryption from an ANSI x9.63 representation.
            /// - Parameters:
            ///    - keyData: An ANSI x9.63 representation of the key.
            public init<Bytes>(x963Representation keyData: Bytes) throws where Bytes: ContiguousBytes {
                let data = keyData.dataRepresentation
                guard data.count == 65 else { throw CCKitError.incorrectKeySize }
                var error: Unmanaged<CFError>?
                let attributes: [String:Any] = [kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
                                                kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
                                                kSecAttrKeySizeInBits as String: 256]

                guard let publicKey = SecKeyCreateWithData(Data(data) as CFData , attributes as CFDictionary, &error) else {
                    throw error?.takeRetainedValue() ?? CCKitError.keyCreationFailure
                }
                secKey = publicKey
            }
            #if canImport(CryptoKit)
            /// Creates a P-256 public key for encryption from a Distinguished Encoding Rules (DER) encoded representation.
            /// - Parameters:
            ///    - keyData: A DER-encoded representation of the key.
            @available(iOS 14.0, tvOS 14.0, watchOS 7.0, macOS 11.0, *)
            public init<Bytes>(derRepresentation keyData: Bytes) throws where Bytes: RandomAccessCollection, Bytes.Element == UInt8 {
                let publicKey = try CryptoKit.P256.KeyAgreement.PublicKey(derRepresentation: keyData)
                try self.init(x963Representation: publicKey.x963Representation)
            }
            
            /// Creates a P-256 public key for encryption from a Privacy-Enhanced Mail (PEM) representation.
            /// - Parameters:
            ///    - keyData: A PEM representation of the key.
            @available(iOS 14.0, tvOS 14.0, watchOS 7.0, macOS 11.0, *)
            public init(pemRepresentation keyData: String) throws {
                let publicKey = try CryptoKit.P256.KeyAgreement.PublicKey(pemRepresentation: keyData)
                try self.init(x963Representation: publicKey.x963Representation)
            }
            #endif
        }
    }
}

// MARK: - KeyAgreement

// Deriving shared symmetric key using ANSI x9.63 method
extension SharedSecret {
    /// Derives a symmetric encryption key from the secret using x9.63 key derivation.
    /// - Parameters:
    ///    - hashFunction: The hash function to use for key derivation.
    ///    - sharedInfo: The shared information to use for key derivation.
    ///    - outputByteCount: The length in bytes of resulting symmetric key.
    ///    - privateKey: The P-256 private key.
    ///    - publicKey: The P-256 public key.
    /// - Returns: The derived symmetric key.
    static func x963DerivedSymmetricKeyP256<H, SI>(using hashFunction: H.Type, sharedInfo: SI, outputByteCount: Int, privateKey: P256.KeyAgreement.PrivateKey, publicKey: P256.KeyAgreement.PublicKey) throws -> SymmetricKey where H: SHAFunction, SI: DataProtocol {
        var error: Unmanaged<CFError>?
            
        let keyPairAttr: [String : Any] = [kSecAttrKeySizeInBits as String: 256,
                                           SecKeyKeyExchangeParameter.requestedSize.rawValue as String: outputByteCount,
                                           SecKeyKeyExchangeParameter.sharedInfo.rawValue as String: Data(sharedInfo),
                                           kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
                                           kSecPrivateKeyAttrs as String: [kSecAttrIsPermanent as String: false],
                                           kSecPublicKeyAttrs as String:[kSecAttrIsPermanent as String: false]]
        let algorithm: SecKeyAlgorithm
        if hashFunction == SHA256.self {
            algorithm =  SecKeyAlgorithm.ecdhKeyExchangeStandardX963SHA256
        } else if hashFunction == SHA384.self {
            algorithm =  SecKeyAlgorithm.ecdhKeyExchangeStandardX963SHA384
        } else if hashFunction == SHA512.self {
            algorithm =  SecKeyAlgorithm.ecdhKeyExchangeStandardX963SHA512
        } else {
            throw CCKitError.keyDerivationFailure
        }
        guard let sharedKey = SecKeyCopyKeyExchangeResult(privateKey.secKey, algorithm, publicKey.secKey, keyPairAttr as CFDictionary, &error) as Data? else {
            throw error?.takeRetainedValue() ?? CCKitError.keyDerivationFailure
        }
        return SymmetricKey(data: sharedKey)
    }
}

// Deriving shared symmetric key using ANSI x9.63 method
@available(iOS, introduced: 10.0/*, deprecated: 14.0, message: "This API is deprecated, please use CryptoKit directly."*/)
@available(tvOS, introduced: 10.0/*, deprecated: 13.0, message: "This API is deprecated, please use CryptoKit directly."*/)
@available(watchOS, introduced: 3.0/*, deprecated: 6.0, message: "This API is deprecated, please use CryptoKit directly."*/)
@available(macOS, introduced: 10.12/*, deprecated: 11.0, message: "This API is deprecated, please use CryptoKit directly."*/)
extension P256.KeyAgreement.PrivateKey {
    /// Computes a shared secret with the provided public key from another party.
    /// - Parameters:
    ///    - publicKeyShare: The public key from another party to be combined with the private key from this user to create the shared secret.
    /// - Returns:
    ///     The derived symmetric key.
    public func sharedSecretFromKeyAgreement(with publicKeyShare: P256.KeyAgreement.PublicKey) throws -> SharedSecret {
        return SharedSecret(privateKey: self, publicKey: publicKeyShare)
    }
}

// MARK: - Signing

// ECDSA
@available(iOS, introduced: 10.0/*, deprecated: 14.0, message: "This API is deprecated, please use CryptoKit directly."*/)
@available(tvOS, introduced: 10.0/*, deprecated: 13.0, message: "This API is deprecated, please use CryptoKit directly."*/)
@available(watchOS, introduced: 3.0/*, deprecated: 6.0, message: "This API is deprecated, please use CryptoKit directly."*/)
@available(macOS, introduced: 10.12/*, deprecated: 11.0, message: "This API is deprecated, please use CryptoKit directly."*/)
extension P256.Signing {
    /// A P-256 elliptic curve digital signature algorithm (ECDSA) signature.
    public struct ECDSASignature {
        /// A distinguished encoding rules (DER) encoded representation of a P-256 digital signature.
        public private(set) var derRepresentation: Data
        #if canImport(CryptoKit)
        /// A raw data representation of a P-256 digital signature.
        @available(iOS 13.0, tvOS 13.0, watchOS 6.0, macOS 10.15, *)
        public var rawRepresentation: Data {
            return try! CryptoKit.P256.Signing.ECDSASignature(derRepresentation: derRepresentation).rawRepresentation
        }
        #endif
        /// Creates a P-256 digital signature from a Distinguished Encoding Rules (DER) encoded representation.
        /// - Parameters:
        ///    - derRepresentation: A distinguished encoding rules (DER) encoded representation of a P-256 digital signature.
        public init<D>(derRepresentation: D) throws where D: DataProtocol {
            #if canImport(CryptoKit)
            if #available(iOS 13.0, tvOS 13.0, watchOS 6.0, macOS 10.15, *) {
                self.derRepresentation = try CryptoKit.P256.Signing.ECDSASignature(derRepresentation: derRepresentation).derRepresentation
            } else {
                self.derRepresentation = Data(derRepresentation)
            }
            #else
            self.derRepresentation = Data(derRepresentation)
            #endif
        }
        #if canImport(CryptoKit)
        /// Creates a P-256 digital signature from a raw representation.
        /// - Parameters:
        ///    - rawRepresentation: A raw representation of the key as a collection of contiguous bytes.
        @available(iOS 13.0, tvOS 13.0, watchOS 6.0, macOS 10.15, *)
        public init<D>(rawRepresentation: D) throws where D: DataProtocol {
            self.derRepresentation = try CryptoKit.P256.Signing.ECDSASignature(rawRepresentation: rawRepresentation).derRepresentation
        }
        #endif
    }
}

// Signature Creation
@available(iOS, introduced: 10.0/*, deprecated: 14.0, message: "This API is deprecated, please use CryptoKit directly."*/)
@available(tvOS, introduced: 10.0/*, deprecated: 13.0, message: "This API is deprecated, please use CryptoKit directly."*/)
@available(watchOS, introduced: 3.0/*, deprecated: 6.0, message: "This API is deprecated, please use CryptoKit directly."*/)
@available(macOS, introduced: 10.12/*, deprecated: 11.0, message: "This API is deprecated, please use CryptoKit directly."*/)
extension P256.Signing.PrivateKey {
    /// Generates an elliptic curve digital signature algorithm (ECDSA) signature of the given data over the P-256 elliptic curve, using SHA-256 as a hash function.
    /// - Parameters:
    ///    - plaintext: The data to sign.
    /// - Returns: The signature corresponding to the data. The signing algorithm employs randomization to generate a different signature on every call, even for the same data and key.
    public func signature<D>(for plaintext: D) throws -> P256.Signing.ECDSASignature where D: DataProtocol {
        var error: Unmanaged<CFError>?
        guard let signature = SecKeyCreateSignature(secKey, .ecdsaSignatureMessageX962SHA256, Data(plaintext) as CFData, &error) as Data? else {
            throw error?.takeRetainedValue() ?? CCKitError.signatureFailure
        }
        return try P256.Signing.ECDSASignature(derRepresentation: signature)
    }
    /// Generates an elliptic curve digital signature algorithm (ECDSA) signature of the given digest over the P-256 elliptic curve, using SHA-256 as a hash function.
    /// - Parameters:
    ///    - digest: The digest of the data to sign.
    /// - Returns: The corresponding signature. The signing algorithm employs randomization to generate a different signature on every call, even for the same digest and key.
    public func signature<D>(for digest: D) throws -> P256.Signing.ECDSASignature where D: HashDigest {
        var error: Unmanaged<CFError>?
        guard let signature = SecKeyCreateSignature(secKey, .ecdsaSignatureDigestX962SHA256, digest.rawRepresentation as CFData, &error) as Data? else {
            throw error?.takeRetainedValue() ?? CCKitError.signatureFailure
        }
        return try P256.Signing.ECDSASignature(derRepresentation: signature)
    }
}

// Signature Verification
@available(iOS, introduced: 10.0/*, deprecated: 14.0, message: "This API is deprecated, please use CryptoKit directly."*/)
@available(tvOS, introduced: 10.0/*, deprecated: 13.0, message: "This API is deprecated, please use CryptoKit directly."*/)
@available(watchOS, introduced: 3.0/*, deprecated: 6.0, message: "This API is deprecated, please use CryptoKit directly."*/)
@available(macOS, introduced: 10.12/*, deprecated: 11.0, message: "This API is deprecated, please use CryptoKit directly."*/)
extension P256.Signing.PublicKey {
    /// Verifies an elliptic curve digital signature algorithm (ECDSA) signature on a block of data over the P-256 elliptic curve.
    /// - Parameters:
    ///    - signature: The signature to check against the given data.
    ///    - data: The data covered by the signature.
    /// - Returns: A Boolean value that’s `true` if the signature is valid for the given data.
    public func isValidSignature<D>(_ signature: P256.Signing.ECDSASignature, for data: D) -> Bool where D: DataProtocol {
        var error: Unmanaged<CFError>?
        return SecKeyVerifySignature(secKey, .ecdsaSignatureMessageX962SHA256, Data(data) as CFData, signature.derRepresentation as CFData, &error)
    }
    /// Verifies an elliptic curve digital signature algorithm (ECDSA) signature on a digest over the P-256 elliptic curve.
    /// - Parameters:
    ///    - signature: The signature to check against the given digest.
    ///    - digest: The digest covered by the signature.
    /// - Returns: A Boolean value that’s true if the signature is valid for the given digest.
    public func isValidSignature<D>(_ signature: P256.Signing.ECDSASignature, for digest: D) -> Bool where D: SHADigest {
        var error: Unmanaged<CFError>?
        return SecKeyVerifySignature(secKey, .ecdsaSignatureDigestX962SHA256, digest.rawRepresentation as CFData, signature.derRepresentation as CFData, &error)
    }
}

// MARK: - Encryption

@available(iOS, introduced: 10.0)
@available(tvOS, introduced: 10.0)
@available(watchOS, introduced: 3.0)
@available(macOS, introduced: 10.12)
extension P256.Encryption.PrivateKey {
    // TODO: Implement
}

@available(iOS, introduced: 10.0)
@available(tvOS, introduced: 10.0)
@available(watchOS, introduced: 3.0)
@available(macOS, introduced: 10.12)
extension P256.Encryption.PublicKey {
    // TODO: Implement
}
