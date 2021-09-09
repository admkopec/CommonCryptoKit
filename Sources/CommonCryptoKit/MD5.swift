//
//  MD5.swift
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
    /// An implementation of MD5 hashing.
    struct MD5: HashFunction {
        /// Computes the MD5 digest of the bytes in the given data instance and returns the computed digest.
        /// - Parameters:
        ///    - data: The data whose digest the hash function should compute. This can be any type that conforms to `DataProtocol`, like `Data` or an array of `UInt8` instances.
        /// - Returns: The computed digest of the data.
        public static func hash<D>(data: D) -> MD5.Digest where D: DataProtocol {
            #if canImport(CryptoKit)
            if #available(iOS 13.0, tvOS 13.0, watchOS 6.0, macOS 10.15, *) {
                let digest = CryptoKit.Insecure.MD5.hash(data: data)
                return Digest(rawRepresentation: digest.rawRepresentation)
            }
            #endif
            var hashData = Data(count: Int(CC_MD5_DIGEST_LENGTH))
            _ = hashData.withUnsafeMutableBytes { digestBytes in
                Data(data).withUnsafeBytes { messageBytes in
                    CC_MD5(messageBytes.baseAddress, CC_LONG(data.count), digestBytes.bindMemory(to: UInt8.self).baseAddress)
                }
            }
            return MD5.Digest(rawRepresentation: hashData)
        }
        /// Computes the MD5 digest of the bytes in the given file and returns the computed digest.
        /// - Parameters:
        ///    - file: The file whose digest the hash function should compute. This should be a `URL` of the desired file.
        /// - Returns: The computed digest of the file.
        public static func hash(file: URL) throws -> MD5.Digest {
            let data = try Data(contentsOf: file, options: .alwaysMapped)
            var hashData = Data(count: Int(CC_MD5_DIGEST_LENGTH))
            _ = hashData.withUnsafeMutableBytes { digestBytes in
                data.withUnsafeBytes { messageBytes in
                    CC_MD5(messageBytes.baseAddress, CC_LONG(data.count), digestBytes.bindMemory(to: UInt8.self).baseAddress)
                }
            }
            return MD5.Digest(rawRepresentation: hashData)
        }
        /// The output of an MD5 hash.
        public struct Digest: HashDigest {
            public private(set) var rawRepresentation: Data
            fileprivate init<D>(rawRepresentation: D) where D: DataProtocol {
                self.rawRepresentation = Data(rawRepresentation)
            }
        }
    }
}

// Adding HashDigest conformance
@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, *)
extension CryptoKit.Insecure.MD5Digest: HashDigest {
    /// The representation of the Digest as raw data.
    public var rawRepresentation: Data {
        return Data(self)
    }
    /// The representation of the Digest as a hexadecimal number.
    public var hexStringRepresentation: String {
        return self.compactMap { String(format: "%02hhx", $0) }.joined()
    }
}
