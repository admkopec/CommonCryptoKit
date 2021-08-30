//
//  PBKDF2.swift
//  CommonCryptoKit
//
//  Created by Adam Kopeć on 11/08/2021.
//  Copyright © 2021 Adam Kopeć.
//
//  Licensed under the MIT License
//

import Foundation
import CommonCrypto

/// An implementation of PBKDF2 key derivation function.
public struct PBKDF2 {
    /// Derives a secure key using the provided hash function, passphrase and salt.
    /// - Parameters:
    ///    - hashFunction: The hash function to use for key derivation.
    ///    - password: The passphrase, which should be used as a basis for the key. This can be any type that conforms to `DataProtocol`, like `Data` or an array of `UInt8` instances.
    ///    - salt: The salt to use for key derivation.
    ///    - outputByteCount: The length in bytes of resulting symmetric key.
    ///    - rounds: The number of rounds which should be used to perform key derivation.
    /// - Returns: The derived symmetric key.
    public static func deriveKey<H, Passphrase, Salt>(using hashFunction: H.Type, password: Passphrase, salt: Salt, outputByteCount: Int, rounds: Int = 300_000_000) throws -> SymmetricKey where H: HashFunction, Passphrase: DataProtocol, Salt: DataProtocol {
        let ccHash: CCPBKDFAlgorithm
        if hashFunction == CommonCryptoKit.SHA256.self {
            ccHash = CCPBKDFAlgorithm(kCCPRFHmacAlgSHA256)
        } else if hashFunction == CommonCryptoKit.SHA384.self {
            ccHash = CCPBKDFAlgorithm(kCCPRFHmacAlgSHA384)
        } else if hashFunction == CommonCryptoKit.SHA512.self {
            ccHash = CCPBKDFAlgorithm(kCCPRFHmacAlgSHA512)
        } else {
            throw CCKitError.incorrectParameterSize
        }
        // TODO: Use SecureBytes for `derivedKeyData`
        var derivedKeyData = Data(repeating: 0, count: outputByteCount)
        let derivedCount = derivedKeyData.count
        let derivationStatus = derivedKeyData.withUnsafeMutableBytes { derivedKeyBytes -> Int32 in
            let keyBuffer: UnsafeMutablePointer<UInt8> =
                derivedKeyBytes.baseAddress!.assumingMemoryBound(to: UInt8.self)
            return Data(salt).withUnsafeBytes { saltBytes -> Int32 in
                let saltBuffer: UnsafePointer<UInt8> = saltBytes.baseAddress!.assumingMemoryBound(to: UInt8.self)
                return Data(password).withUnsafeBytes { passwordBytes -> Int32 in
                    let passwordBuffer: UnsafePointer<Int8> = passwordBytes.baseAddress!.assumingMemoryBound(to: Int8.self)
                    return CCKeyDerivationPBKDF(
                        CCPBKDFAlgorithm(kCCPBKDF2),
                        passwordBuffer,
                        password.count,
                        saltBuffer,
                        salt.count,
                        ccHash,
                        UInt32(rounds),
                        keyBuffer,
                        derivedCount)
                }
            }
        }
        if derivationStatus != kCCSuccess {
            throw CCKitError.keyDerivationFailure
        }
        return SymmetricKey(data: derivedKeyData)
    }
}
