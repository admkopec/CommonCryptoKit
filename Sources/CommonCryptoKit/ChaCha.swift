//
//  ChaCha.swift
//  CommonCryptoKit
//
//  Created by Adam Kopeć on 24/08/2021.
//  Copyright © 2021 Adam Kopeć.
//
//  Licensed under the MIT License
//

import OpenSSL
import Foundation

#if canImport(CryptoKit)
import CryptoKit
#endif

/// An implementation of the ChaCha20-Poly1305 cipher.
@available(iOS, introduced: 10.0)
@available(tvOS, introduced: 10.0)
@available(watchOS, introduced: 3.0)
@available(macOS, introduced: 10.12)
public enum ChaChaPoly {
    internal static let tagByteCount = 16
    internal static let defaultNonceByteCount = 12
    private  static let blockSize: Int = 64
}

// MARK: - Encryption

@available(iOS, introduced: 10.0/*, deprecated: 14.0, message: "This API is deprecated, please use CryptoKit directly."*/)
@available(tvOS, introduced: 10.0/*, deprecated: 13.0, message: "This API is deprecated, please use CryptoKit directly."*/)
@available(watchOS, introduced: 3.0/*, deprecated: 6.0, message: "This API is deprecated, please use CryptoKit directly."*/)
@available(macOS, introduced: 10.12/*, deprecated: 11.0, message: "This API is deprecated, please use CryptoKit directly."*/)
public extension ChaChaPoly {
    /// Secures the given plaintext message with encryption and an authentication tag that covers both the encrypted data and additional data.
    /// - Parameters:
    ///    - message: The plaintext data to seal.
    ///    - key: A cryptographic key used to seal the message.
    ///    - nonce: A nonce used during the sealing process.
    ///    - authenticatedData: Additional data to be authenticated.
    /// - Returns:
    ///    The sealed message.
    static func seal<Plaintext, AuthenticatedData>(_ message: Plaintext, using key: SymmetricKey, nonce: ChaChaPoly.Nonce? = nil, authenticating authenticatedData: AuthenticatedData) throws -> ChaChaPoly.SealedBox where Plaintext : DataProtocol, AuthenticatedData : DataProtocol {
        if #available(iOS 13.0, tvOS 13.0, watchOS 6.0, macOS 10.15, *) {
            let cryptoSealBox = try CryptoKit.ChaChaPoly.seal(message, using: key.asCryptoKitKey, nonce: nonce?.asCryptoKitNonce, authenticating: authenticatedData)
            return try ChaChaPoly.SealedBox(nonce: ChaChaPoly.Nonce(data: cryptoSealBox.nonce.dataRepresentation), ciphertext: cryptoSealBox.ciphertext, tag: cryptoSealBox.tag)
        }
        
        let nonce = nonce ?? ChaChaPoly.Nonce()
        var length: Int32 = 0
        let ctx = EVP_CIPHER_CTX_new()
        if key.bitCount == 256 {
            EVP_EncryptInit_ex(ctx, EVP_chacha20_poly1305(), nil, nil, nil)
        } else {
            EVP_CIPHER_CTX_free(ctx)
            throw CCKitError.incorrectKeySize
        }
        var status = key.withUnsafeBytes { keyBuffer in
            nonce.withUnsafeBytes { nonceBuffer in
                EVP_EncryptInit_ex(ctx, nil, nil, keyBuffer.bindMemory(to: UInt8.self).baseAddress, nonceBuffer.bindMemory(to: UInt8.self).baseAddress)
            }
        }
        if authenticatedData.count > 0 {
            Data(authenticatedData).withUnsafeBytes { authBuffer in
                let authPtr = authBuffer.bindMemory(to: UInt8.self)
                EVP_EncryptUpdate(ctx, nil, &length, authPtr.baseAddress, Int32(authPtr.count))
            }
        }
        var ciphertext = Data(count: message.count)
        Data(message).withUnsafeBytes { plaintextBuffer in
            let plaintextPtr = plaintextBuffer.bindMemory(to: UInt8.self)
            ciphertext.withUnsafeMutableBytes { ciphertextBuffer in
                let ciphertextPtr = ciphertextBuffer.bindMemory(to: UInt8.self)
                EVP_EncryptUpdate(ctx, ciphertextPtr.baseAddress, &length, plaintextPtr.baseAddress, Int32(plaintextPtr.count))
                EVP_EncryptFinal_ex(ctx, ciphertextPtr.baseAddress?.advanced(by: Int(length)), &length)
            }
        }
        var tag = Data(count: ChaChaPoly.tagByteCount)
        status = tag.withUnsafeMutableBytes { tagBuffer in
            EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, Int32(ChaChaPoly.tagByteCount), tagBuffer.bindMemory(to: UInt8.self).baseAddress)
        }
        EVP_CIPHER_CTX_free(ctx)
        guard status != 0 else {
            throw CCKitError.authenticationFailure
        }
        return try ChaChaPoly.SealedBox(nonce: nonce, ciphertext: ciphertext, tag: tag)
    }
    /// Secures the given plaintext message with encryption and an authentication tag.
    /// - Parameters:
    ///    - message: The plaintext data to seal.
    ///    - key: A cryptographic key used to seal the message.
    ///    - nonce: A nonce used during the sealing process.
    /// - Returns:
    ///    The sealed message.
    static func seal<Plaintext>(_ message: Plaintext, using key: SymmetricKey, nonce: ChaChaPoly.Nonce? = nil) throws -> ChaChaPoly.SealedBox where Plaintext : DataProtocol {
        if #available(iOS 13.0, tvOS 13.0, watchOS 6.0, macOS 10.15, *) {
            let cryptoSealBox = try CryptoKit.ChaChaPoly.seal(message, using: key.asCryptoKitKey, nonce: nonce?.asCryptoKitNonce)
            return try ChaChaPoly.SealedBox(nonce: ChaChaPoly.Nonce(data: cryptoSealBox.nonce.dataRepresentation), ciphertext: cryptoSealBox.ciphertext, tag: cryptoSealBox.tag)
        }
        // Fallback using OpenSSL
        return try ChaChaPoly.seal(message, using: key, nonce: nonce, authenticating: Data())
    }
}

// MARK: - Decryption

@available(iOS, introduced: 10.0/*, deprecated: 14.0, message: "This API is deprecated, please use CryptoKit directly."*/)
@available(tvOS, introduced: 10.0/*, deprecated: 13.0, message: "This API is deprecated, please use CryptoKit directly."*/)
@available(watchOS, introduced: 3.0/*, deprecated: 6.0, message: "This API is deprecated, please use CryptoKit directly."*/)
@available(macOS, introduced: 10.12/*, deprecated: 11.0, message: "This API is deprecated, please use CryptoKit directly."*/)
public extension ChaChaPoly {
    /// Decrypts the message and verifies the authenticity of both the encrypted message and additional data.
    /// - Parameters:
    ///    - sealedBox: The sealed box to open.
    ///    - key: The cryptographic key that was used to seal the message.
    ///    - authenticatedData: Additional data that was authenticated.
    /// - Returns:
    ///    The original plaintext message that was sealed in the box, as long as the correct key is used and authentication succeeds. The call throws an error if decryption or authentication fail.
    static func open<AuthenticatedData>(_ sealedBox: ChaChaPoly.SealedBox, using key: SymmetricKey, authenticating authenticatedData: AuthenticatedData) throws -> Data where AuthenticatedData : DataProtocol {
        if #available(iOS 13.0, tvOS 13.0, watchOS 6.0, macOS 10.15, *) {
            let cryptoSealBox = try CryptoKit.ChaChaPoly.SealedBox(nonce: sealedBox.nonce.asCryptoKitNonce, ciphertext: sealedBox.ciphertext, tag: sealedBox.tag)
            return try CryptoKit.ChaChaPoly.open(cryptoSealBox, using: key.asCryptoKitKey, authenticating: authenticatedData)
        }
        let nonce = sealedBox.nonce
        let ciphertext = sealedBox.ciphertext
        var givenTag = sealedBox.tag
        var length: Int32 = 0
        let ctx = EVP_CIPHER_CTX_new()
        if key.bitCount == 256 {
            EVP_DecryptInit_ex(ctx, EVP_chacha20_poly1305(), nil, nil, nil)
        } else {
            EVP_CIPHER_CTX_free(ctx)
            throw CCKitError.incorrectKeySize
        }
        var status = givenTag.withUnsafeMutableBytes { tagBuffer in
            EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, Int32(tagBuffer.count), tagBuffer.baseAddress)
        }
        status = key.withUnsafeBytes { keyBuffer in
            nonce.withUnsafeBytes { nonceBuffer in
                EVP_DecryptInit_ex(ctx, nil, nil, keyBuffer.bindMemory(to: UInt8.self).baseAddress, nonceBuffer.bindMemory(to: UInt8.self).baseAddress)
            }
        }
        if authenticatedData.count > 0 {
            status = Data(authenticatedData).withUnsafeBytes { authBuffer in
                let authPtr = authBuffer.bindMemory(to: UInt8.self)
                return EVP_DecryptUpdate(ctx, nil, &length, authPtr.baseAddress, Int32(authPtr.count))
            }
        }
        var plaintext = Data(count: ciphertext.count)
        status = ciphertext.withUnsafeBytes { ciphertextBuffer in
            let ciphertextPtr = ciphertextBuffer.bindMemory(to: UInt8.self)
            return plaintext.withUnsafeMutableBytes { plaintextBuffer in
                let plaintextPtr = plaintextBuffer.bindMemory(to: UInt8.self)
                EVP_DecryptUpdate(ctx, plaintextPtr.baseAddress, &length, ciphertextPtr.baseAddress, Int32(ciphertextPtr.count))
                return EVP_DecryptFinal_ex(ctx, plaintextPtr.baseAddress?.advanced(by: Int(length)), &length)
            }
        }
        
        EVP_CIPHER_CTX_free(ctx)
        guard status != 0 else {
            throw CCKitError.authenticationFailure
        }
        
        return plaintext
    }
    /// Decrypts the message and verifies its authenticity.
    /// - Parameters:
    ///    - sealedBox: The sealed box to open.
    ///    - key: The cryptographic key that was used to seal the message.
    /// - Returns:
    ///    The original plaintext message that was sealed in the box, as long as the correct key is used and authentication succeeds. The call throws an error if decryption or authentication fail.
    static func open(_ sealedBox: ChaChaPoly.SealedBox, using key: SymmetricKey) throws -> Data {
        if #available(iOS 13.0, tvOS 13.0, watchOS 6.0, macOS 10.15, *) {
            let cryptoSealBox = try CryptoKit.ChaChaPoly.SealedBox(nonce: sealedBox.nonce.asCryptoKitNonce, ciphertext: sealedBox.ciphertext, tag: sealedBox.tag)
            return try CryptoKit.ChaChaPoly.open(cryptoSealBox, using: key.asCryptoKitKey)
        }
        // Fallback using OpenSSL
        return try ChaChaPoly.open(sealedBox, using: key, authenticating: Data())
    }
}

// CryptoKit conversions
@available(iOS 13.0, tvOS 13.0, watchOS 6.0, macOS 10.15, *)
fileprivate extension ChaChaPoly.Nonce {
    var asCryptoKitNonce: CryptoKit.ChaChaPoly.Nonce {
        return try! CryptoKit.ChaChaPoly.Nonce(data: dataRepresentation)
    }
}
