//
//  SharedSecret.swift
//  CommonCryptoKit
//
//  Created by Adam Kopeć on 03/08/2021.
//  Copyright © 2021 Adam Kopeć.
//
//  Licensed under the MIT License
//

import Foundation

#if canImport(CryptoKit)
import CryptoKit
#endif

/// A key agreement result from which you can derive a symmetric cryptographic key.
@available(iOS, introduced: 10.0)
@available(tvOS, introduced: 10.0)
@available(watchOS, introduced: 3.0)
@available(macOS, introduced: 10.12)
public struct SharedSecret {
    private var privateKey: Any!
    private var publicKey: Any!
    
    private var sharedSecret: Any?
    
    /// Derives a symmetric encryption key from the secret using x9.63 key derivation.
    /// - Parameters:
    ///    - hashFunction: The hash function to use for key derivation.
    ///    - sharedInfo: The shared information to use for key derivation.
    ///    - outputByteCount: The length in bytes of resulting symmetric key.
    /// - Returns: The derived symmetric key.
    public func x963DerivedSymmetricKey<H, SI>(using hashFunction: H.Type, sharedInfo: SI, outputByteCount: Int) throws -> SymmetricKey where H: SHAFunction, SI: DataProtocol {
        #if canImport(CryptoKit)
        if #available(iOS 13.0, tvOS 13.0, watchOS 6.0, macOS 10.15, *), let sharedSecret = sharedSecret as? CryptoKit.SharedSecret {
            if hashFunction == SHA256.self {
                return SymmetricKey(sharedSecret.x963DerivedSymmetricKey(using: CryptoKit.SHA256.self, sharedInfo: sharedInfo, outputByteCount: outputByteCount))
            } else if hashFunction == SHA384.self {
                return SymmetricKey(sharedSecret.x963DerivedSymmetricKey(using: CryptoKit.SHA384.self, sharedInfo: sharedInfo, outputByteCount: outputByteCount))
            } else if hashFunction == SHA512.self {
                return SymmetricKey(sharedSecret.x963DerivedSymmetricKey(using: CryptoKit.SHA512.self, sharedInfo: sharedInfo, outputByteCount: outputByteCount))
            } else {
                throw CCKitError.keyDerivationFailure
            }
        }
        #endif
        if let privateKey = privateKey as? P256.KeyAgreement.PrivateKey, let publicKey = publicKey as? P256.KeyAgreement.PublicKey {
            return try SharedSecret.x963DerivedSymmetricKeyP256(using: hashFunction, sharedInfo: sharedInfo, outputByteCount: outputByteCount, privateKey: privateKey, publicKey: publicKey)
        } else if let privateKey = privateKey as? Curve25519.KeyAgreement.PrivateKey, let publicKey = publicKey as? Curve25519.KeyAgreement.PublicKey {
            return try SharedSecret.x963DerivedSymmetricKeyCurve25519(using: hashFunction, sharedInfo: sharedInfo, outputByteCount: outputByteCount, privateKey: privateKey, publicKey: publicKey)
        } else {
            throw CCKitError.keyCreationFailure
        }
    }
    #if canImport(CryptoKit)
    /// Derives a symmetric encryption key from the secret using HKDF key derivation.
    /// - Parameters:
    ///    - hashFunction: The hash function to use for key derivation.
    ///    - salt: The salt to use for key derivation.
    ///    - sharedInfo: The shared information to use for key derivation.
    ///    - outputByteCount: The length in bytes of resulting symmetric key.
    /// - Returns: The derived symmetric key.
    @available(iOS 13.0, tvOS 13.0, watchOS 6.0, macOS 10.15, *)
    public func hkdfDerivedSymmetricKey<H, Salt, SI>(using hashFunction: H.Type, salt: Salt, sharedInfo: SI, outputByteCount: Int) -> SymmetricKey where H : CryptoKit.HashFunction, Salt : DataProtocol, SI : DataProtocol {
        if let sharedSecret = sharedSecret as? CryptoKit.SharedSecret {
            return SymmetricKey(sharedSecret.hkdfDerivedSymmetricKey(using: hashFunction, salt: salt, sharedInfo: sharedInfo, outputByteCount: outputByteCount))
        }
        if let privateKey = privateKey as? P256.KeyAgreement.PrivateKey, let publicKey = publicKey as? P256.KeyAgreement.PublicKey {
            let cryptoKitPrivateKey = try! CryptoKit.P256.KeyAgreement.PrivateKey(x963Representation: privateKey.x963Representation)
            let cryptoKitPublicKey = try! CryptoKit.P256.KeyAgreement.PublicKey(x963Representation: publicKey.x963Representation)
            return try! SymmetricKey(cryptoKitPrivateKey.sharedSecretFromKeyAgreement(with: cryptoKitPublicKey).hkdfDerivedSymmetricKey(using: hashFunction, salt: salt, sharedInfo: sharedInfo, outputByteCount: outputByteCount))
        } else if let privateKey = privateKey as? Curve25519.KeyAgreement.PrivateKey, let publicKey = publicKey as? Curve25519.KeyAgreement.PublicKey {
            let cryptoKitPrivateKey = try! CryptoKit.Curve25519.KeyAgreement.PrivateKey(rawRepresentation: privateKey.rawRepresentation)
            let cryptoKitPublicKey = try! CryptoKit.Curve25519.KeyAgreement.PublicKey(rawRepresentation: publicKey.rawRepresentation)
            return try! SymmetricKey(cryptoKitPrivateKey.sharedSecretFromKeyAgreement(with: cryptoKitPublicKey).hkdfDerivedSymmetricKey(using: hashFunction, salt: salt, sharedInfo: sharedInfo, outputByteCount: outputByteCount))
        } else {
            fatalError("CCKitError.keyCreationFailure")
        }
    }
    #endif
    internal init(privateKey: P256.KeyAgreement.PrivateKey, publicKey: P256.KeyAgreement.PublicKey) {
        self.privateKey = privateKey
        self.publicKey  = publicKey
    }
    
    internal init(privateKey: Curve25519.KeyAgreement.PrivateKey, publicKey: Curve25519.KeyAgreement.PublicKey) {
        self.privateKey = privateKey
        self.publicKey  = publicKey
    }
    
    #if canImport(CryptoKit)
    @available(iOS 13.0, tvOS 13.0, watchOS 6.0, macOS 10.15, *)
    internal init(sharedSecret: CryptoKit.SharedSecret) {
        self.sharedSecret = sharedSecret
    }
    #endif
}
