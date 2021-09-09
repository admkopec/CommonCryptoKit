//
//  Nonce.swift
//  CommonCryptoKit
//
//  Created by Adam Kopeć on 09/08/2021.
//  Copyright © 2021 Adam Kopeć.
//
//  Licensed under the MIT License
//

import Foundation

#if canImport(CryptoKit)
import CryptoKit
#endif

@available(iOS, introduced: 10.0/*, deprecated: 14.0, message: "This API is deprecated, please use CryptoKit directly."*/)
@available(tvOS, introduced: 10.0/*, deprecated: 13.0, message: "This API is deprecated, please use CryptoKit directly."*/)
@available(watchOS, introduced: 3.0/*, deprecated: 6.0, message: "This API is deprecated, please use CryptoKit directly."*/)
@available(macOS, introduced: 10.12/*, deprecated: 11.0, message: "This API is deprecated, please use CryptoKit directly."*/)
public extension AES.GCM {
    /// A value used once during a cryptographic operation and then discarded.
    struct Nonce: ContiguousBytes, Sequence {
        /// A raw representation of the Nonce.
        private var bytes: Data
        /// Creates a new random nonce.
        ///
        ///   The default nonce is a 12-byte random nonce.
        ///
        init() {
            if #available(iOS 13.0, tvOS 13.0, watchOS 6.0, macOS 10.15, *), #available(iOSApplicationExtension 14.0, macOSApplicationExtension 11.0, *) {
                try! self.init(data: CryptoKit.AES.GCM.Nonce().dataRepresentation)
            } else {
                let bytes = 12
                var keyData = Data(count: bytes)
                if keyData.withUnsafeMutableBytes({ SecRandomCopyBytes(kSecRandomDefault, bytes, $0.baseAddress!) }) == errSecSuccess {
                    try! self.init(data: keyData)
                } else {
                    fatalError("There was an error generating secureRandomBytes")
                }
            }
        }
        /// Creates a nonce from the given data.
        ///
        ///   Unless your use case calls for a nonce with a specific value, use the ``init()`` method to instead create a random nonce.
        ///
        /// - Parameters:
        ///    - data: A data representation of the nonce. The initializer throws an error if the data has a length of zero, and otherwise accepts an arrbitrary amount of data.
        ///
        init<D>(data: D) throws where D: DataProtocol {
            guard data.count >= AES.GCM.defaultNonceByteCount else { throw CCKitError.incorrectParameterSize }
            self.bytes = Data(data)
        }
        
        public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
            return try self.bytes.withUnsafeBytes(body)
        }

        public func makeIterator() -> Array<UInt8>.Iterator {
            self.withUnsafeBytes({ (buffPtr) in
                return Array(buffPtr).makeIterator()
            })
        }
    }
}

@available(iOS, introduced: 10.0/*, deprecated: 14.0, message: "This API is deprecated, please use CryptoKit directly."*/)
@available(tvOS, introduced: 10.0/*, deprecated: 13.0, message: "This API is deprecated, please use CryptoKit directly."*/)
@available(watchOS, introduced: 3.0/*, deprecated: 6.0, message: "This API is deprecated, please use CryptoKit directly."*/)
@available(macOS, introduced: 10.12/*, deprecated: 11.0, message: "This API is deprecated, please use CryptoKit directly."*/)
public extension ChaChaPoly {
    /// A value used once during a cryptographic operation and then discarded.
    struct Nonce: ContiguousBytes, Sequence {
        /// A raw representation of the Nonce.
        private var bytes: Data
        /// Creates a new random nonce.
        ///
        ///   The default nonce is a 12-byte random nonce.
        ///
        init() {
            if #available(iOS 13.0, tvOS 13.0, watchOS 6.0, macOS 10.15, *), #available(iOSApplicationExtension 14.0, macOSApplicationExtension 11.0, *) {
                try! self.init(data: CryptoKit.ChaChaPoly.Nonce().dataRepresentation)
            } else {
                let bytes = 12
                var keyData = Data(count: bytes)
                if keyData.withUnsafeMutableBytes({ SecRandomCopyBytes(kSecRandomDefault, bytes, $0.baseAddress!) }) == errSecSuccess {
                    try! self.init(data: keyData)
                } else {
                    fatalError("There was an error generating secureRandomBytes")
                }
            }
        }
        /// Creates a nonce from the given data.
        ///
        ///   Unless your use case calls for a nonce with a specific value, use the ``init()`` method to instead create a random nonce.
        ///
        /// - Parameters:
        ///    - data: A 12-byte data representation of the nonce. The initializer throws an error if the data has a length other than 12 bytes.
        ///
        init<D>(data: D) throws where D: DataProtocol {
            guard data.count == ChaChaPoly.defaultNonceByteCount else { throw CCKitError.incorrectParameterSize }
            self.bytes = Data(data)
        }
        
        public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
            return try self.bytes.withUnsafeBytes(body)
        }

        public func makeIterator() -> Array<UInt8>.Iterator {
            self.withUnsafeBytes({ (buffPtr) in
                return Array(buffPtr).makeIterator()
            })
        }
    }
}
