import XCTest

import HotpTests

var tests = [XCTestCaseEntry]()
tests += hotpTests.allTests()
XCTMain(tests)
