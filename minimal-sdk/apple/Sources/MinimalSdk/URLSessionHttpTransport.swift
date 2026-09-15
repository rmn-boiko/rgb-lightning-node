import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

/// `HttpTransport` over `URLSession`.
///
/// The Rust core builds every gateway request (method, URL, headers, JSON
/// body, timeout) and parses every response; this type only moves bytes.
/// It is the Swift twin of the Kotlin OkHttp/`HttpURLConnection` transport:
/// networking stays idiomatic per platform and Rust links no HTTP or TLS
/// stack.
///
/// `send` is synchronous because the FFI trait is; it blocks the calling
/// thread on a semaphore until `URLSession` answers. Call `GatewayClient`
/// off the main thread (a `Task.detached` or a background queue), exactly
/// as you would a blocking socket.
public final class URLSessionHttpTransport: HttpTransport {
    private let session: URLSession

    /// - Parameter session: defaults to an ephemeral session so nothing the
    ///   gateway returns is written to a disk cache.
    public init(session: URLSession = URLSession(configuration: .ephemeral)) {
        self.session = session
    }

    public func send(request: HttpRequest) throws -> HttpResponse {
        guard let url = URL(string: request.url) else {
            throw SdkError.Transport(reason: "invalid URL")
        }
        var urlRequest = URLRequest(url: url)
        urlRequest.timeoutInterval = TimeInterval(request.timeoutMs) / 1000
        switch request.method {
        case .get:
            urlRequest.httpMethod = "GET"
        case .post:
            urlRequest.httpMethod = "POST"
        }
        for (name, value) in request.headers {
            urlRequest.setValue(value, forHTTPHeaderField: name)
        }
        if let body = request.body {
            urlRequest.httpBody = Data(body.utf8)
        }

        let semaphore = DispatchSemaphore(value: 0)
        let outcome = Outcome()
        let task = session.dataTask(with: urlRequest) { data, response, error in
            defer { semaphore.signal() }
            if let error = error {
                // URLError descriptions carry the host but never the
                // request headers, so the bearer token cannot leak here.
                outcome.set(.failure(.Transport(reason: error.localizedDescription)))
                return
            }
            guard let http = response as? HTTPURLResponse else {
                outcome.set(.failure(.Transport(reason: "non-HTTP response")))
                return
            }
            // The contract is "return Ok for any status the server answered":
            // a non-UTF-8 error page still carries its HTTP status, so decode
            // lossily instead of hiding the status behind a Transport error.
            let body = String(decoding: data ?? Data(), as: UTF8.self)
            guard http.statusCode >= 0, http.statusCode <= Int(UInt16.max) else {
                outcome.set(.failure(.Transport(reason: "invalid HTTP status")))
                return
            }
            outcome.set(.success(HttpResponse(status: UInt16(http.statusCode), body: body)))
        }
        task.resume()
        // `timeoutInterval` is URLSession's inactivity timeout; `timeoutMs`
        // is the total budget Rust promised the caller. Bound the wait as
        // well so a slow-drip server cannot hold the thread past it.
        let budget = DispatchTime.now() + .milliseconds(Int(clamping: request.timeoutMs))
        if semaphore.wait(timeout: budget) == .timedOut {
            task.cancel()
            throw SdkError.Transport(reason: "timed out after \(request.timeoutMs) ms")
        }
        return try outcome.get()
    }

    /// Hands the completion handler's result back to the blocked caller.
    /// The lock makes the hand-off well-defined under Swift 6 strict
    /// concurrency; the semaphore already orders the two accesses.
    private final class Outcome: @unchecked Sendable {
        private let lock = NSLock()
        private var value: Result<HttpResponse, SdkError>?

        func set(_ result: Result<HttpResponse, SdkError>) {
            lock.lock()
            value = result
            lock.unlock()
        }

        func get() throws -> HttpResponse {
            lock.lock()
            defer { lock.unlock() }
            guard let value = value else { throw SdkError.Transport(reason: "no response") }
            return try value.get()
        }
    }
}
