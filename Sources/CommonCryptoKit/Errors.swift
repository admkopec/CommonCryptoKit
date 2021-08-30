//
//  Errors.swift
//  CommonCryptoKit
//
//  Created by Adam Kopeć on 03/08/2021.
//  Copyright © 2021 Adam Kopeć.
//
//  Licensed under the MIT License
//

import Foundation

/// General CommonCryptoKit errors.
@available(iOS, introduced: 10.0/*, deprecated: 13.0, message: "This API is deprecated, please use CryptoKit when available."*/)
@available(tvOS, introduced: 10.0/*, deprecated: 13.0, message: "This API is deprecated, please use CryptoKit when available."*/)
@available(watchOS, introduced: 3.0/*, deprecated: 6.0, message: "This API is deprecated, please use CryptoKit when available."*/)
@available(macOS, introduced: 10.12/*, deprecated: 10.15, message: "This API is deprecated, please use CryptoKit when available."*/)
public enum CCKitError: Error {
    /// The key size was incorrect.
    case incorrectKeySize
    /// The parameter size was incorrect.
    case incorrectParameterSize
    /// The authentication of the message failed.
    case authenticationFailure
    /// The signature of the message failed.
    case signatureFailure
    /// The key creation failed.
    case keyCreationFailure
    /// The key derivation failed.
    case keyDerivationFailure
}
