#if canImport(Testing)
import Testing
import Seccompiler

@Suite("Seccompiler Swift Export Suite")
struct SeccompilerExportTests {
    @Test("Swift module loads cleanly")
    func swiftModuleLoads() {
        #expect(Bool(true), "Seccompiler swift module imported cleanly")
    }
}
#elseif canImport(XCTest)
import XCTest
import Seccompiler

final class SeccompilerExportTests: XCTestCase {
    func testSwiftModuleLoads() throws {
        XCTAssertTrue(true, "Seccompiler swift module imported cleanly")
    }
}
#endif

