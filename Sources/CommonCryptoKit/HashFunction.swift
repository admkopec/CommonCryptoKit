//
//  HashFunction.swift
//  CommonCryptoKit
//
//  Created by Adam Kopeć on 18/08/2021.
//  Copyright © 2021 Adam Kopeć.
//
//  Licensed under the MIT License
//

import Foundation

/// The output of a Hashing Algorithm
public protocol HashDigest {
    /// The representation of the Digest as raw data.
    var rawRepresentation: Data { get }
    /// The representation of the Digest as a hexadecimal number.
    var hexStringRepresentation: String { get }
}
// The extension makes sure to add Hex string representation
public extension HashDigest {
    /// The representation of the Digest as a hexadecimal number.
    var hexStringRepresentation: String {
        return rawRepresentation.compactMap { String(format: "%02hhx", $0) }.joined()
    }
}
/// A type that performs cryptographical hashing.
public protocol HashFunction {
    associatedtype Digest: HashDigest
    /// Computes the digest of the bytes in the given data instance and returns the computed digest.
    static func hash<D>(data: D) -> Digest where D: DataProtocol
}
