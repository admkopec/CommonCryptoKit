//
//  PBKDF2.swift
//  CommonCryptoKit
//
//  Created by Adam Kopeć on 11/08/2021.
//  Copyright © 2021 Adam Kopeć.
//
//  Licensed under the MIT License
//

import OpenSSL
import Foundation

/// An implementation of scrypt key derivation function.
public struct Scrypt {
    /// Derives a secure key using the provided hash function, passphrase and salt.
    /// - Parameters:
    ///    - password: The passphrase, which should be used as a basis for the key. This can be any type that conforms to `DataProtocol`, like `Data` or an array of `UInt8` instances.
    ///    - salt: The salt to use for key derivation.
    ///    - outputByteCount: The length in bytes of resulting symmetric key.
    ///    - rounds: The number of rounds which should be used to perform key derivation.
    /// - Returns: The derived symmetric key.
    public static func deriveKey<Passphrase, Salt>(from password: Passphrase, salt: Salt, outputByteCount: Int, rounds: Int = 300_000_000) throws -> SymmetricKey where Passphrase: DataProtocol, Salt: DataProtocol {
        // TODO: Implement
        return SymmetricKey(size: SymmetricKey.SymmetricKeySize(bitCount: outputByteCount / 8))
    }
}
