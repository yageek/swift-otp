import XCTest
@testable import Otp
import CryptoKit

final class OtpTests: XCTestCase {

    static let Secret = "12345678901234567890"
    static let Secret32 = "12345678901234567890123456789012"
    static let Secret64 = "1234567890123456789012345678901234567890123456789012345678901234"


    // MARK: - Core Tests
    func testStringConversion() {

        let expected = Data([0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30])
        let out = OtpTests.Secret.compactMap { $0.asciiValue }.reduce(into: Data()) {  $0.append($1) }
        XCTAssertEqual(expected, out)
    }

    func testRFC4226HMAC() {
        assertHMAC("cc93cf18508d94934c64b65d8ba7667fb7cde4b0", counter: 0)
        assertHMAC("75a48a19d4cbe100644e8ac1397eea747a2d33ab", counter: 1)
        assertHMAC("0bacb7fa082fef30782211938bc1c5e70416ff44", counter: 2)
        assertHMAC("66c28227d03a2d5529262ff016a1e6ef76557ece", counter: 3)
        assertHMAC("a904c900a64b35909874b33e61c5938a8e15ed1c", counter: 4)
        assertHMAC("a37e783d7b7233c083d4f62926c7a25f238d0316", counter: 5)
        assertHMAC("bc9cd28561042c83f219324d3c607256c03272ae", counter: 6)
        assertHMAC("a4fb960c0bc06e1eabb804e5b397cdc4b45596fa", counter: 7)
        assertHMAC("1b3c89f65e6c9e883012052823443f048b4332db", counter: 8)
        assertHMAC("1637409809a679dc698207310c8c7fc07290d9e5", counter: 9)
    }

    func testTruncation() {
        let buffer = Data([0x1f, 0x86, 0x98, 0x69, 0x0e, 0x02, 0xca, 0x16, 0x61, 0x85, 0x50, 0xef, 0x7f, 0x19, 0xda, 0x8e, 0x94, 0x5b, 0x55, 0x5a])
        let otp = Generator.dynamicTruncation(mac: buffer, digit: 6)
        XCTAssertEqual(872921, otp)
    }

    func testHOTP() {
        assertHOTPSha1With6Digits(755224, counter: 0)
        assertHOTPSha1With6Digits(287082, counter: 1)
        assertHOTPSha1With6Digits(359152, counter: 2)
        assertHOTPSha1With6Digits(969429, counter: 3)
        assertHOTPSha1With6Digits(338314, counter: 4)
        assertHOTPSha1With6Digits(254676, counter: 5)
        assertHOTPSha1With6Digits(287922, counter: 6)
        assertHOTPSha1With6Digits(162583, counter: 7)
        assertHOTPSha1With6Digits(399871, counter: 8)
        assertHOTPSha1With6Digits(520489, counter: 9)
    }

    // MARK: - TOTP
    func testTOTP() {

        let testTimes: [UInt64] = [ 59, 1_111_111_109, 1_111_111_111, 1_234_567_890, 2_000_000_000, 20_000_000_000 ];
        let sha1Expected: [UInt32] = [94287082, 07081804, 14050471, 89005924, 69279037, 65353130]
        let sha256Expected: [UInt32] = [46119246, 68084774, 67062674, 91819424, 90698825, 77737706]
        let sha512Expected: [UInt32] = [90693936, 25091201, 99943326, 93441116, 38618901, 47863826]

        let stepTime: UInt64 = 30
        let origin: UInt64 = 0
        let digit: Int = 8

        for i in 0..<testTimes.count {
            do {

                let time = testTimes[i]
                let sha1 = try Generator(sharedKey: OtpTests.Secret, algorithm: .sha1, time: time, stepTime: stepTime, origin: origin, digit: digit).process()
                XCTAssertEqual(sha1Expected[i], sha1)

                let sha256 = try Generator(sharedKey: OtpTests.Secret32, algorithm: .sha256, time: time, stepTime: stepTime, origin: origin, digit: digit).process()
                XCTAssertEqual(sha256Expected[i], sha256)

                let sha512 = try Generator(sharedKey: OtpTests.Secret64, algorithm: .sha512, time: time, stepTime: stepTime, origin: origin, digit: digit).process()
                XCTAssertEqual(sha512Expected[i], sha512)

            } catch let error {
                XCTFail("Error during TOTP generation for time: \(testTimes[i]) \(error.localizedDescription)")
            }
        }
    }

    // MARK: - Tools
    func assertHOTPSha1With6Digits(_ expected: UInt32, counter: UInt64, message: String = "", file: StaticString = #filePath, line: UInt = #line) {

        do {
            let value = Generator(sharedKey: OtpTests.Secret, algorithm: .sha1, counter: counter, digit: 6)
            let code = try value.process()
            XCTAssertEqual(expected, code, file: file, line: line)
        } catch let error {
            XCTFail("Error: \(error.localizedDescription)", file: file, line: line)
        }
    }

    func assertHMAC(_ value: String, counter: UInt64, message: String = "", file: StaticString = #filePath, line: UInt = #line) {

        let keyData = Generator.number(key: OtpTests.Secret)
        let hmac: HMAC<Insecure.SHA1>.MAC = try! Generator.hmac(key: keyData, count: counter)
        let hmacString = hmac.map { String(format: "%02x", $0) }.joined()
        XCTAssertEqual(value, hmacString, message, file: file, line: line)
    }

    static var allTests = [
        ("testTruncation", testTruncation),
        ("testStringConversion", testStringConversion),
        ("testRFC4226", testRFC4226HMAC),
    ]
}
