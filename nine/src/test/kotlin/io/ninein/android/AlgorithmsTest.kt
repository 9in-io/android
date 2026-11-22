package io.ninein.android

import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/**
 * ID tokens signed with every asymmetric algorithm of 9in's key library go through the Java core's
 * checks and complete a sign-in. The core verifies the signatures (and is tested for each check on
 * its own); this is the integration, on the JVM's and on Android's (Conscrypt) security providers.
 */
internal fun signInWithEveryAlgorithm() = runBlocking<Unit> {
    for (alg in TestKey.ALGORITHMS) {
        AuthorizationBroker.reset()
        val fake = FakeNine(key = TestKey(alg))
        val nine = fake.client()
        assertEquals(alg, "usr_alice", nine.signIn(fake.browser()).id)
        // And a refreshed ID token signed with it.
        assertEquals(alg, "usr_alice", nine.refresh().tokenSet.subject())
    }
}

class AlgorithmsTest {
    @Before
    fun reset() = AuthorizationBroker.reset()

    @Test
    fun `every algorithm signs in through the core on the JVM`() = signInWithEveryAlgorithm()
}

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [26, 37])
class AlgorithmsOnAndroidTest {
    @Test
    fun `every algorithm signs in through the core with Android's providers`() = signInWithEveryAlgorithm()
}
