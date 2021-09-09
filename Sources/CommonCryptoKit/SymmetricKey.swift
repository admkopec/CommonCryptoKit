//
//  SymmetricKey.swift
//  CommonCryptoKit
//
//  Created by Adam Kopeć on 29/08/2021.
//  Copyright © 2021 Adam Kopeć.
//
//  Licensed under the MIT License
//

import Security
import Foundation

#if canImport(CryptoKit)
import CryptoKit
#endif

/// A symmetric cryptographic key.
///
///    You typically derive a symmetric key from an instance of a shared secret (``SharedSecret``)
///    that you obtain through key agreement. You use a symmetric key to compute a message authentication
///    code like HMAC, or to open and close a sealed box (``ChaChaPoly/SealedBox`` or ``AES/GCM/SealedBox``)
///    using a cipher like ``ChaChaPoly`` or ``AES``.
///
@available(iOS, introduced: 10.0)
@available(tvOS, introduced: 10.0)
@available(watchOS, introduced: 3.0)
@available(macOS, introduced: 10.12)
public struct SymmetricKey: ContiguousBytes, Equatable {
    /// The number of bits in the key.
    var bitCount: Int {
        if #available(iOS 13.0, tvOS 13.0, watchOS 6.0, macOS 10.15, *), let key = cryptoKey as? CryptoKit.SymmetricKey {
            return key.bitCount
        } else {
            return dataStorage.count * 8
        }
    }
    // CryptoKit.SymmetricKey
    private var cryptoKey: Any?
    // TODO: Make a SecureBytes storage as a fallback
    private var dataStorage: Data!
    
    /// Creates a key from the given data.
    /// - Parameters:
    ///    - data: The contiguous bytes from which to create the key.
    public init<D>(data: D) where D: ContiguousBytes {
        if #available(iOS 13.0, tvOS 13.0, watchOS 6.0, macOS 10.15, *) {
            self.cryptoKey = CryptoKit.SymmetricKey(data: data)
        } else {
            self.dataStorage = data.withUnsafeBytes { dataBuffer in
                Data(dataBuffer)
            }
        }
    }
    /// Generates a new random key of the given size.
    /// - Parameters:
    ///    - size: The size of the key to generate. You can use one of the standard sizes, like ``SymmetricKeySize/bits256``, or you can create a key of custom length by initializing a ``SymmetricKeySize`` instance with a non-standard value.
    public init(size: SymmetricKeySize) {
        if #available(iOS 13.0, tvOS 13.0, watchOS 6.0, macOS 10.15, *) {
            self.cryptoKey = CryptoKit.SymmetricKey(size: size.asCryptoKitKeySize)
        } else {
            self.dataStorage = SymmetricKey.secureRandom(count: size.bitCount / 8)
        }
    }
    
    @available(iOS 13.0, tvOS 13.0, watchOS 6.0, macOS 10.15, *)
    internal init(_ cryptoKitKey: CryptoKit.SymmetricKey) {
        self.cryptoKey = cryptoKitKey
    }
    
    public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
        if #available(iOS 13.0, tvOS 13.0, watchOS 6.0, macOS 10.15, *), let key = cryptoKey as? CryptoKit.SymmetricKey {
            return try key.withUnsafeBytes(body)
        } else {
            return try dataStorage.withUnsafeBytes(body)
        }
    }
    
    public static func == (lhs: SymmetricKey, rhs: SymmetricKey) -> Bool {
        if #available(iOS 13.0, tvOS 13.0, watchOS 6.0, macOS 10.15, *), let lhsKey = lhs.cryptoKey as? CryptoKit.SymmetricKey, let rhsKey = rhs.cryptoKey as? CryptoKit.SymmetricKey {
            return lhsKey == rhsKey
        } else {
            return lhs.dataStorage == rhs.dataStorage
        }
    }
    
    private static func secureRandom(count bytes: Int) -> Data {
        var keyData = Data(count: bytes)
        if keyData.withUnsafeMutableBytes({ SecRandomCopyBytes(kSecRandomDefault, bytes, $0.baseAddress!) }) == errSecSuccess {
            return keyData
        } else {
            fatalError("There was an error generating secureRandomBytes")
        }
    }
}

// MARK: Key Sizes
@available(iOS, introduced: 10.0)
@available(tvOS, introduced: 10.0)
@available(watchOS, introduced: 3.0)
@available(macOS, introduced: 10.12)
extension SymmetricKey {
    /// The sizes that a symmetric cryptographic key can take.
    ///
    ///    When creating a new ``SymmetricKey`` instance with a call to its ``init(size:)`` initializer,
    ///    you typically use one of the standard key sizes, like ``bits128``, ``bits192``, or ``bits256``.
    ///    When you need a key with a non-standard length, use the ``init(bitCount:)`` initializer to create a ``SymmetricKeySize`` instance with a custom bit count.
    ///
    public struct SymmetricKeySize {
        /// A size of 128 bits.
        public static var bits128 = SymmetricKeySize(bitCount: 128)
        /// A size of 192 bits.
        public static var bits192 = SymmetricKeySize(bitCount: 192)
        /// A size of 256 bits.
        public static var bits256 = SymmetricKeySize(bitCount: 256)
        
        /// The number of bits in the key.
        public let bitCount: Int
        
        /// Creates a new key size of the given length.
        public init(bitCount: Int) {
            self.bitCount = bitCount
        }
    }
}

// MARK: CryptoKit
@available(iOS 13.0, tvOS 13.0, watchOS 6.0, macOS 10.15, *)
extension SymmetricKey.SymmetricKeySize {
    fileprivate var asCryptoKitKeySize: CryptoKit.SymmetricKeySize {
        return CryptoKit.SymmetricKeySize(bitCount: self.bitCount)
    }
}

@available(iOS 13.0, tvOS 13.0, watchOS 6.0, macOS 10.15, *)
extension SymmetricKey {
    internal var asCryptoKitKey: CryptoKit.SymmetricKey {
        return cryptoKey as! CryptoKit.SymmetricKey
    }
}
