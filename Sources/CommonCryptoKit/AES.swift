//
//  AES.swift
//  CommonCryptoKit
//
//  Created by Adam Kopeć on 06/08/2021.
//  Copyright © 2021 Adam Kopeć.
//
//  Licensed under the MIT License
//

import OpenSSL
import CryptoKit
import Foundation

/// A container for Advanced Encryption Standard (AES) ciphers.
@available(iOS, introduced: 10.0)
@available(tvOS, introduced: 10.0)
@available(watchOS, introduced: 3.0)
@available(macOS, introduced: 10.12)
public enum AES {
    /// The Advanced Encryption Standard (AES) Galois Counter Mode (GCM) cipher suite.
    @available(iOS, introduced: 10.0/*, deprecated: 14.0, message: "This API is deprecated, please use CryptoKit directly."*/)
    @available(tvOS, introduced: 10.0/*, deprecated: 13.0, message: "This API is deprecated, please use CryptoKit directly."*/)
    @available(watchOS, introduced: 3.0/*, deprecated: 6.0, message: "This API is deprecated, please use CryptoKit directly."*/)
    @available(macOS, introduced: 10.12/*, deprecated: 11.0, message: "This API is deprecated, please use CryptoKit directly."*/)
    public enum GCM {
        internal static let tagByteCount = 16
        internal static let defaultNonceByteCount = 12
        private  static let blockSize: Int = 16
        private  static let chunkSize: Int = 1_600_000
    }
}

// MARK: - Encryption

@available(iOS, introduced: 10.0/*, deprecated: 14.0, message: "This API is deprecated, please use CryptoKit directly."*/)
@available(tvOS, introduced: 10.0/*, deprecated: 13.0, message: "This API is deprecated, please use CryptoKit directly."*/)
@available(watchOS, introduced: 3.0/*, deprecated: 6.0, message: "This API is deprecated, please use CryptoKit directly."*/)
@available(macOS, introduced: 10.12/*, deprecated: 11.0, message: "This API is deprecated, please use CryptoKit directly."*/)
public extension AES.GCM {
    /// Secures the given plaintext message with encryption and an authentication tag that covers both the encrypted data and additional data.
    /// - Parameters:
    ///    - message: The plaintext data to seal.
    ///    - key: A cryptographic key used to seal the message.
    ///    - nonce: A nonce used during the sealing process.
    ///    - authenticatedData: Additional data to be authenticated.
    /// - Returns:
    ///    The sealed message.
    static func seal<Plaintext, AuthenticatedData>(_ message: Plaintext, using key: SymmetricKey, nonce: AES.GCM.Nonce? = nil, authenticating authenticatedData: AuthenticatedData) throws -> AES.GCM.SealedBox where Plaintext : DataProtocol, AuthenticatedData : DataProtocol {
        if #available(iOS 13.0, tvOS 13.0, watchOS 6.0, macOS 10.15, *) {
            let cryptoSealBox = try CryptoKit.AES.GCM.seal(message, using: key.asCryptoKitKey, nonce: nonce?.asCryptoKitNonce, authenticating: authenticatedData)
            return try AES.GCM.SealedBox(nonce: AES.GCM.Nonce(data: cryptoSealBox.nonce.dataRepresentation), ciphertext: cryptoSealBox.ciphertext, tag: cryptoSealBox.tag)
        }
        let nonce = nonce ?? AES.GCM.Nonce()
        var length: Int32 = 0
        let ctx = EVP_CIPHER_CTX_new()
        if key.bitCount == 256 {
            EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nil, nil, nil)
        } else if key.bitCount == 192 {
            EVP_EncryptInit_ex(ctx, EVP_aes_192_gcm(), nil, nil, nil)
        } else if key.bitCount == 128 {
            EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), nil, nil, nil)
        } else {
            EVP_CIPHER_CTX_free(ctx)
            throw CCKitError.incorrectKeySize
        }
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, Int32(nonce.dataRepresentation.count), nil)
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
        var tag = Data(count: AES.GCM.tagByteCount)
        status = tag.withUnsafeMutableBytes { tagBuffer in
            EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, Int32(AES.GCM.tagByteCount), tagBuffer.bindMemory(to: UInt8.self).baseAddress)
        }
        EVP_CIPHER_CTX_free(ctx)
        guard status != 0 else {
            throw CCKitError.authenticationFailure
        }
        return try AES.GCM.SealedBox(nonce: nonce, ciphertext: ciphertext, tag: tag)
    }
    /// Secures the given plaintext message with encryption and an authentication tag.
    /// - Parameters:
    ///    - message: The plaintext data to seal.
    ///    - key: A cryptographic key used to seal the message.
    ///    - nonce: A nonce used during the sealing process.
    /// - Returns:
    ///    The sealed message.
    static func seal<Plaintext>(_ message: Plaintext, using key: SymmetricKey, nonce: AES.GCM.Nonce? = nil) throws -> AES.GCM.SealedBox where Plaintext : DataProtocol {
        if #available(iOS 13.0, tvOS 13.0, watchOS 6.0, macOS 10.15, *) {
            let cryptoSealBox = try CryptoKit.AES.GCM.seal(message, using: key.asCryptoKitKey, nonce: nonce?.asCryptoKitNonce)
            return try AES.GCM.SealedBox(nonce: AES.GCM.Nonce(data: cryptoSealBox.nonce.dataRepresentation), ciphertext: cryptoSealBox.ciphertext, tag: cryptoSealBox.tag)
        }
        // Fallback using OpenSSL
        return try AES.GCM.seal(message, using: key, nonce: nonce, authenticating: Data())
    }
    /// Secures the given file with encryption and an authentication tag.
    /// - Parameters:
    ///    - url: The file to seal.
    ///    - key: A cryptographic key used to seal the message.
    ///    - nonce: A nonce used during the sealing process.
    /// - Returns:
    ///    The sealed file.
    static func seal(_ url: URL, using key: SymmetricKey, nonce: AES.GCM.Nonce? = nil) throws -> URL {
        let nonce = nonce ?? AES.GCM.Nonce()
        guard nonce.dataRepresentation.count == AES.GCM.defaultNonceByteCount else {
            throw CCKitError.incorrectParameterSize
        }
        // Seal the whole file
        let message         = try Data(contentsOf: url, options: .alwaysMapped)
        let chunkCount      = (message.count / AES.GCM.chunkSize) + ((message.count % AES.GCM.chunkSize != 0) ? 1 : 0)
        let ciphertextURL   = try FileManager.default.url(for: .itemReplacementDirectory, in: .userDomainMask, appropriateFor: url, create: true).appendingPathComponent(url.lastPathComponent)
        try nonce.dataRepresentation.write(to: ciphertextURL)
        let fileHandle = try FileHandle(forUpdating: ciphertextURL)
        fileHandle.seekToEndOfFile()
        var length: Int32 = 0
        let ctx = EVP_CIPHER_CTX_new()
        if key.bitCount == 256 {
            EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nil, nil, nil)
        } else if key.bitCount == 192 {
            EVP_EncryptInit_ex(ctx, EVP_aes_192_gcm(), nil, nil, nil)
        } else if key.bitCount == 128 {
            EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), nil, nil, nil)
        } else {
            EVP_CIPHER_CTX_free(ctx)
            throw CCKitError.incorrectKeySize
        }
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, Int32(nonce.dataRepresentation.count), nil)
        var status = key.withUnsafeBytes { keyBuffer in
            nonce.withUnsafeBytes { nonceBuffer in
                EVP_EncryptInit_ex(ctx, nil, nil, keyBuffer.bindMemory(to: UInt8.self).baseAddress, nonceBuffer.bindMemory(to: UInt8.self).baseAddress)
            }
        }
        message.withUnsafeBytes { plaintextBuffer in
            let plaintextPtr = plaintextBuffer.bindMemory(to: UInt8.self)
            for i in 0..<chunkCount {
                let plaintextCount = min(plaintextPtr.count - i*AES.GCM.chunkSize, AES.GCM.chunkSize)
                var ciphertext = Data(count: plaintextCount)
                ciphertext.withUnsafeMutableBytes { ciphertextBuffer in
                    let ciphertextPtr = ciphertextBuffer.bindMemory(to: UInt8.self)
                    EVP_EncryptUpdate(ctx, ciphertextPtr.baseAddress, &length, plaintextPtr.baseAddress?.advanced(by: i*AES.GCM.chunkSize), Int32(plaintextCount))
                    if i+1 == chunkCount {
                        EVP_EncryptFinal_ex(ctx, ciphertextPtr.baseAddress?.advanced(by: Int(length)), &length)
                    }
                }
                fileHandle.write(ciphertext)
            }
        }
        var tag = Data(count: AES.GCM.tagByteCount)
        status = tag.withUnsafeMutableBytes { tagBuffer in
            EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, Int32(AES.GCM.tagByteCount), tagBuffer.bindMemory(to: UInt8.self).baseAddress)
        }
        EVP_CIPHER_CTX_free(ctx)
        // Save tag to file
        fileHandle.write(tag)
        // Close the file
        fileHandle.closeFile()
        
        guard status != 0 else {
            throw CCKitError.authenticationFailure
        }
        
        return ciphertextURL
    }
    /// Secures the given file with encryption and an authentication tag.
    /// - Parameters:
    ///    - url: The file to seal.
    ///    - key: A cryptographic key used to seal the message.
    ///    - nonce: A nonce used during the sealing process.
    /// - Returns:
    ///    Throws...
    static func seal(_ url: URL, using key: SymmetricKey, nonce: AES.GCM.Nonce? = nil, splittingIntoParts perPartChunkCount: Int = 10, perPartHandler: @escaping (_ partURL: URL) -> Void) throws -> Void {
        let nonce = nonce ?? AES.GCM.Nonce()
        guard nonce.dataRepresentation.count == AES.GCM.defaultNonceByteCount else {
            throw CCKitError.incorrectParameterSize
        }
        // Seal the whole file
        let message         = try Data(contentsOf: url, options: .alwaysMapped)
        let chunkCount      = (message.count / AES.GCM.chunkSize) + ((message.count % AES.GCM.chunkSize != 0) ? 1 : 0)
        var countedChunks   = 0
        let baseURL         = try FileManager.default.url(for: .itemReplacementDirectory, in: .userDomainMask, appropriateFor: url, create: true)
        var ciphertextURL   = baseURL.appendingPathComponent(UUID().uuidString)
        try nonce.dataRepresentation.write(to: ciphertextURL)
        var fileHandle = try FileHandle(forUpdating: ciphertextURL)
        fileHandle.seekToEndOfFile()
        var length: Int32 = 0
        let ctx = EVP_CIPHER_CTX_new()
        if key.bitCount == 256 {
            EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nil, nil, nil)
        } else if key.bitCount == 192 {
            EVP_EncryptInit_ex(ctx, EVP_aes_192_gcm(), nil, nil, nil)
        } else if key.bitCount == 128 {
            EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), nil, nil, nil)
        } else {
            EVP_CIPHER_CTX_free(ctx)
            throw CCKitError.incorrectKeySize
        }
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, Int32(nonce.dataRepresentation.count), nil)
        var status = key.withUnsafeBytes { keyBuffer in
            nonce.withUnsafeBytes { nonceBuffer in
                EVP_EncryptInit_ex(ctx, nil, nil, keyBuffer.bindMemory(to: UInt8.self).baseAddress, nonceBuffer.bindMemory(to: UInt8.self).baseAddress)
            }
        }
        try message.withUnsafeBytes { plaintextBuffer in
            let plaintextPtr = plaintextBuffer.bindMemory(to: UInt8.self)
            for i in 0..<chunkCount {
                countedChunks += 1
                let plaintextCount = min(plaintextPtr.count - i*AES.GCM.chunkSize, AES.GCM.chunkSize)
                var ciphertext = Data(count: plaintextCount)
                ciphertext.withUnsafeMutableBytes { ciphertextBuffer in
                    let ciphertextPtr = ciphertextBuffer.bindMemory(to: UInt8.self)
                    EVP_EncryptUpdate(ctx, ciphertextPtr.baseAddress, &length, plaintextPtr.baseAddress?.advanced(by: i*AES.GCM.chunkSize), Int32(plaintextCount))
                    if i+1 == chunkCount {
                        EVP_EncryptFinal_ex(ctx, ciphertextPtr.baseAddress?.advanced(by: Int(length)), &length)
                    }
                }
                if countedChunks == perPartChunkCount {
                    fileHandle.closeFile()
                    countedChunks = 0
                    DispatchQueue.global().async {
                        perPartHandler(ciphertextURL)
                    }
                    ciphertextURL = baseURL.appendingPathComponent(UUID().uuidString)
                    try ciphertext.write(to: ciphertextURL)
                    fileHandle = try FileHandle(forUpdating: ciphertextURL)
                    fileHandle.seekToEndOfFile()
                } else {
                    // Save ciphertext to file
                    fileHandle.write(ciphertext)
                }
            }
        }
        var tag = Data(count: AES.GCM.tagByteCount)
        status = tag.withUnsafeMutableBytes { tagBuffer in
            EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, Int32(AES.GCM.tagByteCount), tagBuffer.bindMemory(to: UInt8.self).baseAddress)
        }
        EVP_CIPHER_CTX_free(ctx)
        // Save tag to file
        fileHandle.write(tag)
        // Close the file
        fileHandle.closeFile()
        perPartHandler(ciphertextURL)
        guard status != 0 else {
            throw CCKitError.authenticationFailure
        }
    }
}

// MARK: - Decryption

@available(iOS, introduced: 10.0/*, deprecated: 14.0, message: "This API is deprecated, please use CryptoKit directly."*/)
@available(tvOS, introduced: 10.0/*, deprecated: 13.0, message: "This API is deprecated, please use CryptoKit directly."*/)
@available(watchOS, introduced: 3.0/*, deprecated: 6.0, message: "This API is deprecated, please use CryptoKit directly."*/)
@available(macOS, introduced: 10.12/*, deprecated: 11.0, message: "This API is deprecated, please use CryptoKit directly."*/)
public extension AES.GCM {
    /// Decrypts the message and verifies the authenticity of both the encrypted message and additional data.
    /// - Parameters:
    ///    - sealedBox: The sealed box to open.
    ///    - key: The cryptographic key that was used to seal the message.
    ///    - authenticatedData: Additional data that was authenticated.
    /// - Returns:
    ///    The original plaintext message that was sealed in the box, as long as the correct key is used and authentication succeeds. The call throws an error if decryption or authentication fail.
    static func open<AuthenticatedData>(_ sealedBox: AES.GCM.SealedBox, using key: SymmetricKey, authenticating authenticatedData: AuthenticatedData) throws -> Data where AuthenticatedData : DataProtocol {
        if #available(iOS 13.0, tvOS 13.0, watchOS 6.0, macOS 10.15, *) {
            let cryptoSealBox = try CryptoKit.AES.GCM.SealedBox(nonce: sealedBox.nonce.asCryptoKitNonce, ciphertext: sealedBox.ciphertext, tag: sealedBox.tag)
            return try CryptoKit.AES.GCM.open(cryptoSealBox, using: key.asCryptoKitKey, authenticating: authenticatedData)
        }
        let nonce = sealedBox.nonce
        let ciphertext = sealedBox.ciphertext
        var givenTag = sealedBox.tag
        var length: Int32 = 0
        let ctx = EVP_CIPHER_CTX_new()
        if key.bitCount == 256 {
            EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nil, nil, nil)
        } else if key.bitCount == 192 {
            EVP_DecryptInit_ex(ctx, EVP_aes_192_gcm(), nil, nil, nil)
        } else if key.bitCount == 128 {
            EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), nil, nil, nil)
        } else {
            EVP_CIPHER_CTX_free(ctx)
            throw CCKitError.incorrectKeySize
        }
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, Int32(nonce.dataRepresentation.count), nil)
        var status = givenTag.withUnsafeMutableBytes { tagBuffer in
            EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, Int32(tagBuffer.count), tagBuffer.baseAddress)
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
    static func open(_ sealedBox: AES.GCM.SealedBox, using key: SymmetricKey) throws -> Data {
        if #available(iOS 13.0, tvOS 13.0, watchOS 6.0, macOS 10.15, *) {
            let cryptoSealBox = try CryptoKit.AES.GCM.SealedBox(nonce: sealedBox.nonce.asCryptoKitNonce, ciphertext: sealedBox.ciphertext, tag: sealedBox.tag)
            return try CryptoKit.AES.GCM.open(cryptoSealBox, using: key.asCryptoKitKey)
        }
        // Fallback using OpenSSL
        return try AES.GCM.open(sealedBox, using: key, authenticating: Data())
    }
    /// Decrypts the file **in place** and verifies its authenticity.
    /// - Parameters:
    ///    - ciphertextURL: The url of the encrypted file.
    ///    - key: The cryptographic key that was used to seal the file.
    /// - Note:
    ///    The call throws an error if decryption or authentication fail.
    ///    Make sure the passed url is writable as its contents will be changed.
    static func open(_ ciphertextURL: URL, using key: SymmetricKey) throws -> Void {
        let sealedBoxData = try Data(contentsOf: ciphertextURL, options: .alwaysMapped)
        let nonce = sealedBoxData.prefix(AES.GCM.defaultNonceByteCount)
        
        let ciphertext = sealedBoxData.dropFirst(AES.GCM.defaultNonceByteCount).dropLast(AES.GCM.tagByteCount)
        var givenTag = sealedBoxData.suffix(AES.GCM.tagByteCount)
        
        var length: Int32 = 0
        let ctx = EVP_CIPHER_CTX_new()
        if key.bitCount == 256 {
            EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nil, nil, nil)
        } else if key.bitCount == 192 {
            EVP_DecryptInit_ex(ctx, EVP_aes_192_gcm(), nil, nil, nil)
        } else if key.bitCount == 128 {
            EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), nil, nil, nil)
        } else {
            EVP_CIPHER_CTX_free(ctx)
            throw CCKitError.incorrectKeySize
        }
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, Int32(nonce.dataRepresentation.count), nil)
        var status = givenTag.withUnsafeMutableBytes { tagBuffer in
            EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, Int32(tagBuffer.count), tagBuffer.baseAddress)
        }
        status = key.withUnsafeBytes { keyBuffer in
            nonce.withUnsafeBytes { nonceBuffer in
                EVP_DecryptInit_ex(ctx, nil, nil, keyBuffer.bindMemory(to: UInt8.self).baseAddress, nonceBuffer.bindMemory(to: UInt8.self).baseAddress)
            }
        }
        let chunkCount = (ciphertext.count / AES.GCM.chunkSize) + ((ciphertext.count % AES.GCM.chunkSize != 0) ? 1 : 0)
        
        let fileHandle = try FileHandle(forWritingTo: ciphertextURL)
        fileHandle.seek(toFileOffset: 0)
        
        ciphertext.withUnsafeBytes { ciphertextBuffer in
            let ciphertextPtr = ciphertextBuffer.bindMemory(to: UInt8.self)
            for i in 0..<chunkCount {
                let ciphertextCount = min(ciphertextPtr.count - i*AES.GCM.chunkSize, AES.GCM.chunkSize)
                var plaintext = Data(count: ciphertextCount)
                plaintext.withUnsafeMutableBytes { plaintextBuffer in
                    let plaintextPtr = plaintextBuffer.bindMemory(to: UInt8.self)
                    EVP_DecryptUpdate(ctx, plaintextPtr.baseAddress, &length, ciphertextPtr.baseAddress?.advanced(by: i*AES.GCM.chunkSize), Int32(ciphertextPtr.count))
                    if i+1 == chunkCount {
                        status = EVP_DecryptFinal_ex(ctx, plaintextPtr.baseAddress?.advanced(by: Int(length)), &length)
                    }
                }
                fileHandle.write(plaintext)
            }
        }
        
        EVP_CIPHER_CTX_free(ctx)
        guard status != 0 else {
            throw CCKitError.authenticationFailure
        }
        
        fileHandle.truncateFile(atOffset: fileHandle.offsetInFile)
        fileHandle.closeFile()
    }
}

// CryptoKit conversions
@available(iOS 13.0, tvOS 13.0, watchOS 6.0, macOS 10.15, *)
fileprivate extension AES.GCM.Nonce {
    var asCryptoKitNonce: CryptoKit.AES.GCM.Nonce {
        return try! CryptoKit.AES.GCM.Nonce(data: dataRepresentation)
    }
}
