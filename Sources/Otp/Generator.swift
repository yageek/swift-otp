//
//  File.swift
//  
//
//  Created by eidd5180 on 24/06/2020.
//

import Foundation
import CryptoKit

public struct Generator  {
    // Use values presented here
    public enum Algorithm: String {
        case sha1 = "SHA1"
        case sha256 = "SHA256"
        case sha512 = "SHA512s"
    }

    // MARK: - iVar
    public let sharedKey: Data
    public let counter: UInt64
    public let digit: Int
    public let algorithm: Algorithm

    /// Default initializer
    /// - Parameters:
    ///   - sharedKey: The shared key
    ///   - algorithm: The algorithm used
    ///   - counter: The counter value
    ///   - hash: The hash function used
    ///   - digit: The number of digit to use (between 1 and 8)
    public init<K: Key>(sharedKey: K, algorithm: Algorithm, counter: UInt64, digit: Int) {
        self.sharedKey = sharedKey.bytesRepresentation
        self.counter = counter
        self.digit = max(1, min(digit,8))
        self.algorithm = algorithm
    }

    public init<K: Key>(sharedKey: K, algorithm: Algorithm, time: UInt64, stepTime: UInt64, origin: UInt64, digit: Int) {
        let counter = (time - origin)/stepTime
        self.init(sharedKey: sharedKey, algorithm: algorithm, counter: counter, digit: digit)
    }

    /// Process the value
    /// - Throws: Throws a cryptographic error
    /// - Returns: The HOTP code
    public func process() throws -> UInt32 {

        let result: UInt32
        switch self.algorithm {
        case .sha1:
            let mac: HMAC<Insecure.SHA1>.MAC = try Generator.hmac(key: self.sharedKey, count: self.counter)
            result = try otp(from: mac)
        case .sha256:
            let mac: HMAC<SHA256>.MAC = try Generator.hmac(key: self.sharedKey, count: self.counter)
            result = try otp(from: mac)
        case .sha512:
            let mac: HMAC<SHA512>.MAC = try Generator.hmac(key: self.sharedKey, count: self.counter)
            result = try otp(from: mac)
        }

        return result
    }

    private func otp<H: HashFunction>(from hmac: HMAC<H>.MAC) throws -> UInt32 {
        let bytes = hmac.withUnsafeBytes { Data($0) }
        let otp = Generator.dynamicTruncation(mac: bytes, digit: self.digit)
        return otp
    }

    static func number(key: String) -> Data {
        key.compactMap { $0.asciiValue }.reduce(into: Data()) {  $0.append($1) }
    }

    static func hmac<H: HashFunction>(key: Data, count: UInt64) throws -> HMAC<H>.MAC {
        var count = count.bigEndian
        let countBytes = Data(bytes: &count, count: MemoryLayout<UInt64>.size)
        return HMAC<H>.authenticationCode(for: countBytes, using: SymmetricKey(data: key))
    }

    static func dynamicTruncation(mac: Data, digit: Int) -> UInt32 {

        let offset = Int(mac[mac.count - 1] & 0xf)
        let bin_code: UInt32 = (UInt32(mac[offset]) & 0x7f) << 24 | (UInt32(mac[offset + 1]) & 0xff) << 16 | (UInt32(mac[offset + 2]) & 0xff) << 8 | (UInt32(mac[offset + 3]) & 0xff)

        let otp = bin_code % Generator.DigitsPower[digit]
        return otp
    }

    static let DigitsPower: [UInt32] = [1,10,100,1000,10_000,100_000,1_000_000,10_000_000,100_000_000]
}

