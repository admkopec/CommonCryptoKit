//
//  Helpers.swift
//  CommonCryptoKit
//
//  Created by Adam Kopeć on 05/08/2021.
//  Copyright © 2021 Adam Kopeć.
//
//  Licensed under the MIT License
//

import Foundation
import CryptoKit

/// A container for older, cryptographically insecure algorithms.
@available(iOS, introduced: 10.0)
@available(tvOS, introduced: 10.0)
@available(watchOS, introduced: 3.0)
@available(macOS, introduced: 10.12)
public enum Insecure {
    
}

public extension ContiguousBytes {
    /// A Data instance created safely from the contiguous bytes without making any copies.
    var dataRepresentation: Data {
        return self.withUnsafeBytes { bytes in
            let cfdata = CFDataCreateWithBytesNoCopy(nil, bytes.baseAddress?.assumingMemoryBound(to: UInt8.self), bytes.count, kCFAllocatorNull)
            return ((cfdata as NSData?) as Data?) ?? Data()
        }
    }
}

// MARK: Data

internal extension Data {
    @inlinable
    static func ^(lhs: Data, rhs: Data) -> Data {
        let count = Swift.min(lhs.count, rhs.count)
        var result: Data = Data(count: count)
        
        for i in 0..<count {
            result[i] = lhs[lhs.startIndex + i] ^ rhs[rhs.startIndex + i]
        }
        
        return result
    }
}
