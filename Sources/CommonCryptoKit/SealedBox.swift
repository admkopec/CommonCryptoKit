//
//  SealedBox.swift
//  CommonCryptoKit
//
//  Created by Adam Kopeć on 06/08/2021.
//  Copyright © 2021 Adam Kopeć.
//
//  Licensed under the MIT License
//

import Security
import CryptoKit
import Foundation
import CommonCrypto

// MARK: - AES

@available(iOS, introduced: 10.0/*, deprecated: 14.0, message: "This API is deprecated, please use CryptoKit directly."*/)
@available(tvOS, introduced: 10.0/*, deprecated: 13.0, message: "This API is deprecated, please use CryptoKit directly."*/)
@available(watchOS, introduced: 3.0/*, deprecated: 6.0, message: "This API is deprecated, please use CryptoKit directly."*/)
@available(macOS, introduced: 10.12/*, deprecated: 11.0, message: "This API is deprecated, please use CryptoKit directly."*/)
public extension AES.GCM {
    /// A secure container for your data that you access using a cipher.
    ///
    ///    Use a sealed box as a container for data that you want to transmit securely. Seal data into a box with one of the cipher algorithms, like ``seal(_:using:nonce:)-5qdtq``.
    ///
    ///    The box holds an encrypted version of the original data, an authentication tag, and the nonce during encryption.
    ///    The encryption makes the data unintelligible to anyone without the key, while the authentication tag makes it possible for the intended receiver to be sure the data remains intact.
    ///
    ///    The receiver uses another instance of the same cipher, like the ``open(_:using:)-5tjy1`` method, to open the box.
    ///
    struct SealedBox {
        /// The nonce used to encrypt the data.
        public private(set) var nonce: AES.GCM.Nonce
        /// The encrypted data.
        ///
        ///    The length of the ciphertext of a sealed box is the same as the length of the plaintext you encrypt.
        ///
        public private(set) var ciphertext: Data
        /// An authentication tag.
        ///
        ///    The authentication tag has a length of 16 bytes.
        ///
        public private(set) var tag: Data
        /// A combined element composed of the nonce, encrypted data, and authentication tag.
        ///
        ///    The combined representation is only available when the ``AES/GCM/Nonce`` size is the default size of 12 bytes. The data layout of the combined representation is: `nonce`, `ciphertext`, then `tag`.
        ///
        public var combined: Data? {
            guard nonce.dataRepresentation.count == AES.GCM.defaultNonceByteCount else { return nil }
            return nonce.dataRepresentation + ciphertext + tag
        }
        /// Creates a sealed box from the given tag, nonce, and ciphertext.
        /// - Parameters:
        ///    - nonce: The nonce.
        ///    - ciphertext: The encrypted data.
        ///    - tag: The authentication tag.
        public init<C, T>(nonce: AES.GCM.Nonce, ciphertext: C, tag: T) throws where C : DataProtocol, T : DataProtocol {
            guard tag.count == AES.GCM.tagByteCount else { throw CCKitError.incorrectParameterSize }
            self.nonce = nonce
            self.ciphertext = Data(ciphertext)
            self.tag = Data(tag)
        }
        /// Creates a sealed box from the combined bytes of an authentication tag, nonce, and encrypted data.
        /// - Parameters:
        ///    - combined: The combined bytes of the nonce, encrypted data, and authentication tag.
        public init<D>(combined: D) throws where D : DataProtocol {
            if combined.count < AES.GCM.defaultNonceByteCount + AES.GCM.tagByteCount { throw CCKitError.incorrectParameterSize }
            
            self.nonce = try AES.GCM.Nonce(data: combined.prefix(AES.GCM.defaultNonceByteCount))
            self.ciphertext = Data(combined.dropFirst(AES.GCM.defaultNonceByteCount).dropLast(AES.GCM.tagByteCount))
            self.tag = Data(combined.suffix(AES.GCM.tagByteCount))
        }
    }
}

// MARK: - ChaCha20

@available(iOS, introduced: 10.0/*, deprecated: 14.0, message: "This API is deprecated, please use CryptoKit directly."*/)
@available(tvOS, introduced: 10.0/*, deprecated: 13.0, message: "This API is deprecated, please use CryptoKit directly."*/)
@available(watchOS, introduced: 3.0/*, deprecated: 6.0, message: "This API is deprecated, please use CryptoKit directly."*/)
@available(macOS, introduced: 10.12/*, deprecated: 11.0, message: "This API is deprecated, please use CryptoKit directly."*/)
public extension ChaChaPoly {
    /// A secure container for your data that you access using a cipher.
    ///
    ///    Use a sealed box as a container for data that you want to transmit securely. Seal data into a box with one of the cipher algorithms, like ``seal(_:using:nonce:)``.
    ///
    ///    The box holds an encrypted version of the original data, an authentication tag, and the nonce during encryption.
    ///    The encryption makes the data unintelligible to anyone without the key, while the authentication tag makes it possible for the intended receiver to be sure the data remains intact.
    ///
    ///    The receiver uses another instance of the same cipher, like the ``open(_:using:)`` method, to open the box.
    ///
    struct SealedBox {
        /// The nonce used to encrypt the data.
        public private(set) var nonce: ChaChaPoly.Nonce
        /// The encrypted data.
        ///
        ///    The length of the ciphertext of a sealed box is the same as the length of the plaintext you encrypt.
        ///
        public private(set) var ciphertext: Data
        /// An authentication tag.
        ///
        ///    The authentication tag has a length of 16 bytes.
        ///
        public private(set) var tag: Data
        /// A combined element composed of the nonce, encrypted data, and authentication tag.
        ///
        ///    The data layout of the combined representation is: nonce, ciphertext, then tag.
        ///
        public var combined: Data {
            return nonce.dataRepresentation + ciphertext + tag
        }
        /// Creates a sealed box from the given tag, nonce, and ciphertext.
        /// - Parameters:
        ///    - nonce: The nonce.
        ///    - ciphertext: The encrypted data.
        ///    - tag: The authentication tag.
        public init<C, T>(nonce: ChaChaPoly.Nonce, ciphertext: C, tag: T) throws where C : DataProtocol, T : DataProtocol {
            guard tag.count == ChaChaPoly.tagByteCount else { throw CCKitError.incorrectParameterSize }
            self.nonce = nonce
            self.ciphertext = Data(ciphertext)
            self.tag = Data(tag)
        }
        /// Creates a sealed box from the combined bytes of an authentication tag, nonce, and encrypted data.
        /// - Parameters:
        ///    - combined: The combined bytes of the nonce, encrypted data, and authentication tag.
        public init<D>(combined: D) throws where D : DataProtocol {
            if combined.count < ChaChaPoly.defaultNonceByteCount + ChaChaPoly.tagByteCount { throw CCKitError.incorrectParameterSize }
            
            self.nonce = try ChaChaPoly.Nonce(data: combined.prefix(ChaChaPoly.defaultNonceByteCount))
            self.ciphertext = Data(combined.dropFirst(ChaChaPoly.defaultNonceByteCount).dropLast(ChaChaPoly.tagByteCount))
            self.tag = Data(combined.suffix(ChaChaPoly.tagByteCount))
        }
    }
}
