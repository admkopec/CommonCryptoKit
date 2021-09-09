//
//  SHA1.swift
//  CommonCryptoKit
//
//  Created by Adam Kopeć on 18/08/2021.
//  Copyright © 2021 Adam Kopeć.
//
//  Licensed under the MIT License
//

import Foundation
import CommonCrypto

#if canImport(CryptoKit)
import CryptoKit
#endif

@available(iOS, introduced: 10.0/*, deprecated: 14.0, message: "This API is deprecated, please use CryptoKit directly."*/)
@available(tvOS, introduced: 10.0/*, deprecated: 13.0, message: "This API is deprecated, please use CryptoKit directly."*/)
@available(watchOS, introduced: 3.0/*, deprecated: 6.0, message: "This API is deprecated, please use CryptoKit directly."*/)
@available(macOS, introduced: 10.12/*, deprecated: 11.0, message: "This API is deprecated, please use CryptoKit directly."*/)
public extension Insecure {
    /// An implementation of SHA1 hashing.
    struct SHA1: HashFunction {
        /// Computes the SHA1 digest of the bytes in the given data instance and returns the computed digest.
        /// - Parameters:
        ///    - data: The data whose digest the hash function should compute. This can be any type that conforms to `DataProtocol`, like `Data` or an array of `UInt8` instances.
        /// - Returns: The computed digest of the data.
        public static func hash<D>(data: D) -> SHA1.Digest where D: DataProtocol {
            if #available(iOS 13.0, tvOS 13.0, watchOS 6.0, macOS 10.15, *) {
                let digest = CryptoKit.Insecure.SHA1.hash(data: data)
                return Digest(rawRepresentation: digest.rawRepresentation)
            }
            var hashData = Data(count: Int(CC_SHA1_DIGEST_LENGTH))
            _ = hashData.withUnsafeMutableBytes { digestBytes in
                Data(data).withUnsafeBytes { messageBytes in
                    CC_SHA1(messageBytes.baseAddress, CC_LONG(data.count), digestBytes.bindMemory(to: UInt8.self).baseAddress)
                }
            }
            return SHA1.Digest(rawRepresentation: hashData)
        }
        /// The output of an SHA1 hash.
        public struct Digest: HashDigest {
            public private(set) var rawRepresentation: Data
            fileprivate init<D>(rawRepresentation: D) where D: DataProtocol {
                self.rawRepresentation = Data(rawRepresentation)
            }
        }
    }
}
