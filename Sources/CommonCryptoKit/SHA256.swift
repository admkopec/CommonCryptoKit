//
//  SHA256.swift
//  CommonCryptoKit
//
//  Created by Adam Kopeć on 03/08/2021.
//  Copyright © 2021 Adam Kopeć.
//
//  Licensed under the MIT License
//

import Foundation
import CommonCrypto

#if canImport(CryptoKit)
import CryptoKit
#endif

/// An implementation of Secure Hashing Algorithm 2 (SHA-2) hashing with a 256-bit digest.
@available(iOS, introduced: 10.0/*, deprecated: 14.0, message: "This API is deprecated, please use CryptoKit directly."*/)
@available(tvOS, introduced: 10.0/*, deprecated: 13.0, message: "This API is deprecated, please use CryptoKit directly."*/)
@available(watchOS, introduced: 3.0/*, deprecated: 6.0, message: "This API is deprecated, please use CryptoKit directly."*/)
@available(macOS, introduced: 10.12/*, deprecated: 11.0, message: "This API is deprecated, please use CryptoKit directly."*/)
public struct SHA256: SHAFunction {
    /// Computes the SHA256 digest of the bytes in the given data instance and returns the computed digest.
    /// - Parameters:
    ///    - data: The data whose digest the hash function should compute. This can be any type that conforms to `DataProtocol`, like `Data` or an array of `UInt8` instances.
    /// - Returns: The computed digest of the data.
    public static func hash<D>(data: D) -> SHA256.Digest where D: DataProtocol {
        #if canImport(CryptoKit)
        if #available(iOS 13.0, tvOS 13.0, watchOS 6.0, macOS 10.15, *) {
            let digest = CryptoKit.SHA256.hash(data: data)
            return Digest(rawRepresentation: digest.rawRepresentation)
        }
        #endif
        var hashData = Data(count: Int(CC_SHA256_DIGEST_LENGTH))
        _ = hashData.withUnsafeMutableBytes { digestBytes in
            Data(data).withUnsafeBytes { messageBytes in
                CC_SHA256(messageBytes.baseAddress, CC_LONG(data.count), digestBytes.bindMemory(to: UInt8.self).baseAddress)
            }
        }
        return SHA256.Digest(rawRepresentation: hashData)
    }
    /// The output of a Secure Hashing Algorithm 2 (SHA-2) hash with a 256-bit digest.
    public struct Digest: SHADigest {
        public private(set) var rawRepresentation: Data
        fileprivate init<D>(rawRepresentation: D) where D: DataProtocol {
            self.rawRepresentation = Data(rawRepresentation)
        }
    }
}
