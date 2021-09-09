//
//  SecureEncalve.swift
//  CommonCryptoKit
//
//  Created by Adam Kopeć on 26/08/2021.
//  Copyright © 2021 Adam Kopeć.
//
//  Licensed under the MIT License
//

import Foundation

#if canImport(CryptoKit)
import CryptoKit

#if canImport(LocalAuthentication)
import LocalAuthentication
#endif

/// A representation of a device’s hardware-based key manager.
@available(iOS 13.0, tvOS 13.0, watchOS 6.0, macOS 10.15, *)
public enum SecureEnclave {
    /// A Boolean value that’s true if the device supports Secure Enclave access.
    public static var isAvailable: Bool {
        return CryptoKit.SecureEnclave.isAvailable
    }
    
    /// An elliptic curve that enables NIST P-256 signatures and key agreement within the Secure Enclave.
    public enum P256 {
        /// A mechanism used to create a shared secret between two users by performing NIST P-256 elliptic curve Diffie Hellman (ECDH) key exchange within the Secure Enclave.
        public enum KeyAgreement {
            /// A P-256 private key used for key agreement.
            public struct PrivateKey {
                private var cryptoKey: CryptoKit.SecureEnclave.P256.KeyAgreement.PrivateKey
                
                /// A data representation of the private key.
                public var dataRepresentation: Data {
                    return cryptoKey.dataRepresentation
                }
                
                /// The corresponding public key.
                public var publicKey: CommonCryptoKit.P256.KeyAgreement.PublicKey {
                    return try! CommonCryptoKit.P256.KeyAgreement.PublicKey(x963Representation: cryptoKey.publicKey.x963Representation)
                }
                #if canImport(LocalAuthentication)
                /// Creates a P-256 private key for key agreement from a data representation of the key.
                /// - Parameters:
                ///    - dataRepresentation: A raw representation of the key as a collection of contiguous bytes.
                ///    - authenticationContext: A local authentication context.
                @available(iOS 13.0, macOS 10.15, *)
                public init(dataRepresentation: Data, authenticationContext: LAContext? = nil) throws {
                    self.cryptoKey = try CryptoKit.SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: dataRepresentation, authenticationContext: authenticationContext)
                }
                #else
                /// Creates a P-256 private key for key agreement from a data representation of the key.
                /// - Parameters:
                ///    - dataRepresentation: A raw representation of the key as a collection of contiguous bytes.
                @available(tvOS 13.0, watchOS 6.0, *)
                public init(dataRepresentation: Data) throws {
                    self.cryptoKey = try CryptoKit.SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: dataRepresentation)
                }
                #endif
                
                #if canImport(LocalAuthentication)
                /// Creates a P-256 private key for key agreement with access specified by an access control.
                /// - Parameters:
                ///    - compactRepresentable: A Boolean value that indicates whether CryptoKit creates the key with the structure to enable compact point encoding.
                ///    - accessControl: An access control that specifies accessibility of the private key.
                ///    - authenticationContext: A local authentication context.
                @available(iOS 13.0, macOS 10.15, *)
                public init(compactRepresentable: Bool = true, accessControl: SecAccessControl = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly, [], nil)!, authenticationContext: LAContext? = nil) throws {
                    self.cryptoKey = try CryptoKit.SecureEnclave.P256.KeyAgreement.PrivateKey(compactRepresentable: compactRepresentable, accessControl: accessControl, authenticationContext: authenticationContext)
                }
                #else
                /// Creates a P-256 private key for key agreement with access specified by an access control.
                /// - Parameters:
                ///    - compactRepresentable: A Boolean value that indicates whether CryptoKit creates the key with the structure to enable compact point encoding.
                ///    - accessControl: An access control that specifies accessibility of the private key.
                @available(tvOS 13.0, watchOS 6.0, *)
                public init(compactRepresentable: Bool = true, accessControl: SecAccessControl = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly, [], nil)!) throws {
                    self.cryptoKey = try CryptoKit.SecureEnclave.P256.KeyAgreement.PrivateKey(compactRepresentable: compactRepresentable, accessControl: accessControl)
                }
                #endif
            }
        }
        /// A mechanism used to create or verify a cryptographic signature using the NIST P-256 elliptic curve digital signature algorithm (ECDSA) within the Secure Enclave.
        public enum Signing {
            /// A P-256 private key used for signing.
            public struct PrivateKey {
                private var cryptoKey: CryptoKit.SecureEnclave.P256.Signing.PrivateKey
                
                /// A data representation of the private key.
                public var dataRepresentation: Data {
                    return cryptoKey.dataRepresentation
                }
                
                /// The corresponding public key.
                public var publicKey: CommonCryptoKit.P256.Signing.PublicKey {
                    return try! CommonCryptoKit.P256.Signing.PublicKey(x963Representation: cryptoKey.publicKey.x963Representation)
                }
                #if canImport(LocalAuthentication)
                /// Creates a P-256 private key for signing from a data representation of the key.
                /// - Parameters:
                ///    - dataRepresentation: A raw representation of the key as a collection of contiguous bytes.
                ///    - authenticationContext: A local authentication context.
                @available(iOS 13.0, macOS 10.15, *)
                public init(dataRepresentation: Data, authenticationContext: LAContext? = nil) throws {
                    self.cryptoKey = try CryptoKit.SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: dataRepresentation, authenticationContext: authenticationContext)
                }
                #else
                /// Creates a P-256 private key for signing from a data representation of the key.
                /// - Parameters:
                ///    - dataRepresentation: A raw representation of the key as a collection of contiguous bytes.
                @available(tvOS 13.0, watchOS 6.0, *)
                public init(dataRepresentation: Data) throws {
                    self.cryptoKey = try CryptoKit.SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: dataRepresentation)
                }
                #endif
                #if canImport(LocalAuthentication)
                /// Creates a P-256 private key for signing with access specified by an access control.
                /// - Parameters:
                ///    - compactRepresentable: A Boolean value that indicates whether CryptoKit creates the key with the structure to enable compact point encoding.
                ///    - accessControl: An access control that specifies accessibility of the private key.
                ///    - authenticationContext: A local authentication context.
                @available(iOS 13.0, macOS 10.15, *)
                public init(compactRepresentable: Bool = true, accessControl: SecAccessControl = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly, [], nil)!, authenticationContext: LAContext? = nil) throws {
                    self.cryptoKey = try CryptoKit.SecureEnclave.P256.Signing.PrivateKey(compactRepresentable: compactRepresentable, accessControl: accessControl, authenticationContext: authenticationContext)
                }
                #else
                /// Creates a P-256 private key for signing with access specified by an access control.
                /// - Parameters:
                ///    - compactRepresentable: A Boolean value that indicates whether CryptoKit creates the key with the structure to enable compact point encoding.
                ///    - accessControl: An access control that specifies accessibility of the private key.
                @available(tvOS 13.0, watchOS 6.0, *)
                public init(compactRepresentable: Bool = true, accessControl: SecAccessControl = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly, [], nil)!) throws {
                    self.cryptoKey = try CryptoKit.SecureEnclave.P256.Signing.PrivateKey(compactRepresentable: compactRepresentable, accessControl: accessControl)
                }
                #endif
            }
        }
    }
}

// MARK: - KeyAgreement

@available(iOS 13.0, tvOS 13.0, watchOS 6.0, macOS 10.15, *)
extension SecureEnclave.P256.KeyAgreement.PrivateKey {
    /// Computes a shared secret with the provided public key from another party.
    /// - Parameters:
    ///    - publicKeyShare: The public key from another party to be combined with the private key from this user to create the shared secret.
    /// - Returns:
    ///     The computed shared secret.
    public func sharedSecretFromKeyAgreement(with publicKeyShare: P256.KeyAgreement.PublicKey) throws -> SharedSecret {
        let cryptoPublicKeyShare = try CryptoKit.P256.KeyAgreement.PublicKey(x963Representation: publicKeyShare.x963Representation)
        return try SharedSecret(sharedSecret: cryptoKey.sharedSecretFromKeyAgreement(with: cryptoPublicKeyShare))
    }
}

// MARK: - Signing

@available(iOS 13.0, tvOS 13.0, watchOS 6.0, macOS 10.15, *)
extension SecureEnclave.P256.Signing.PrivateKey {
    /// Generates an elliptic curve digital signature algorithm (ECDSA) signature of the given digest over the P-256 elliptic curve, using SHA-256 as a hash function.
    /// - Parameters:
    ///    - data: The data to sign.
    /// - Returns:
    ///     A cryptographic signature. The signing algorithm employs randomization to generate a different signature on every call, even for the same data and key.
    public func signature<D>(for data: D) throws -> P256.Signing.ECDSASignature where D: DataProtocol {
        return try P256.Signing.ECDSASignature(rawRepresentation: cryptoKey.signature(for: data).rawRepresentation)
    }
}

#endif
