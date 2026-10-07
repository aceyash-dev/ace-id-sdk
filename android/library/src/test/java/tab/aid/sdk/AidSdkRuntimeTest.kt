package tab.aid.sdk

import org.junit.Assert.assertEquals
import org.junit.Assert.assertSame
import org.junit.Test
import java.util.concurrent.atomic.AtomicInteger

class AidSdkRuntimeTest {
    @Test
    fun discoveryIsLoadedOnceWhileCached() {
        val calls = AtomicInteger()
        val first = AidSdkRuntime.discovery("https://cache-test.example") {
            calls.incrementAndGet()
            OidcConfiguration(
                issuer = "https://cache-test.example",
                authorizationEndpoint = "https://cache-test.example/authorize",
                tokenEndpoint = "https://cache-test.example/token",
            )
        }
        val second = AidSdkRuntime.discovery("https://cache-test.example") {
            calls.incrementAndGet()
            error("cache miss")
        }

        assertSame(first, second)
        assertEquals(1, calls.get())
    }

    @Test
    fun refreshLockSerializesWorkForSameClient() {
        val key = "https://issuer.example|client"
        var active = 0
        var maxActive = 0

        val first = Thread {
            AidSdkRuntime.withRefreshLock(key) {
                active++
                maxActive = maxOf(maxActive, active)
                Thread.sleep(20)
                active--
            }
        }
        val second = Thread {
            AidSdkRuntime.withRefreshLock(key) {
                active++
                maxActive = maxOf(maxActive, active)
                Thread.sleep(20)
                active--
            }
        }

        first.start()
        second.start()
        first.join()
        second.join()

        assertEquals(1, maxActive)
    }
}
