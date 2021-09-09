//
//  SHADigest.swift
//  CommonCryptoKit
//
//  Created by Adam Kopeć on 03/08/2021.
//  Copyright © 2021 Adam Kopeć.
//
//  Licensed under the MIT License
//

import Foundation

/// A type that performs cryptographically secure hashing using Secure Hashing Algorithm 2 (SHA-2).
public protocol SHAFunction: HashFunction where Digest: SHADigest {
    /// Computes the digest of the bytes in the given data instance and returns the computed digest.
    static func hash<D>(data: D) -> Digest where D: DataProtocol
}
/// The output of a Secure Hashing Algorithm 2 (SHA-2) hash
public protocol SHADigest: HashDigest {
    /// The representation of the Digest as raw data.
    var rawRepresentation: Data { get }
    /// The representation of the Digest as a hexadecimal number.
    var hexStringRepresentation: String { get }
}
// The extension makes sure to add Hex string representation
public extension SHADigest {
    /// The representation of the Digest as a hexadecimal number.
    var hexStringRepresentation: String {
        return rawRepresentation.compactMap { String(format: "%02hhx", $0) }.joined()
    }
}

#if canImport(CryptoKit)
import CryptoKit

// MARK: - CryptoKit

// Adding SHADigest conformance
@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, *)
extension SHA256Digest: SHADigest {
    /// The representation of the Digest as raw data.
    public var rawRepresentation: Data {
        return Data(self)
    }
    /// The representation of the Digest as a hexadecimal number.
    public var hexStringRepresentation: String {
        return self.compactMap { String(format: "%02hhx", $0) }.joined()
    }
}

// Adding SHADigest conformance
@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, *)
extension SHA384Digest: SHADigest {
    /// The representation of the Digest as raw data.
    public var rawRepresentation: Data {
        return Data(self)
    }
    /// The representation of the Digest as a hexadecimal number.
    public var hexStringRepresentation: String {
        return self.compactMap { String(format: "%02hhx", $0) }.joined()
    }
}

// Adding SHADigest conformance
@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, *)
extension SHA512Digest: SHADigest {
    /// The representation of the Digest as raw data.
    public var rawRepresentation: Data {
        return Data(self)
    }
    /// The representation of the Digest as a hexadecimal number.
    public var hexStringRepresentation: String {
        return self.compactMap { String(format: "%02hhx", $0) }.joined()
    }
}

// Adding HashDigest conformance
@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, *)
extension CryptoKit.Insecure.SHA1Digest: HashDigest {
    /// The representation of the Digest as raw data.
    public var rawRepresentation: Data {
        return Data(self)
    }
    /// The representation of the Digest as a hexadecimal number.
    public var hexStringRepresentation: String {
        return self.compactMap { String(format: "%02hhx", $0) }.joined()
    }
}
#endif
