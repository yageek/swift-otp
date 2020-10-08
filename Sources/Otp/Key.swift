//
//  File.swift
//  
//
//  Created by eidd5180 on 24/06/2020.
//

import Foundation

/// Simple protocol to abstract input key
public protocol Key {

    /// The bytes representation of the key
    var bytesRepresentation: Data { get }
}

/// :nodoc:
extension String: Key {
    public var bytesRepresentation: Data {
        return Otp.Generator.number(key: self)
    }
}

/// :nodoc:
extension Data: Key {
    public var bytesRepresentation: Data {
        return self
    }
}
