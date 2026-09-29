package dev.attestra.client

import android.content.Context
import com.google.android.play.core.integrity.IntegrityManagerFactory
import com.google.android.play.core.integrity.StandardIntegrityException
import com.google.android.play.core.integrity.StandardIntegrityManager.PrepareIntegrityTokenRequest
import com.google.android.play.core.integrity.StandardIntegrityManager.StandardIntegrityTokenProvider
import com.google.android.play.core.integrity.StandardIntegrityManager.StandardIntegrityTokenRequest
import com.google.android.play.core.integrity.model.StandardIntegrityErrorCode
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.tasks.await

/** Produces Play Integrity tokens; injectable for tests. */
interface IntegrityTokenSource {
    /** Prepares the token provider ahead of time so the first request is fast. */
    suspend fun warmUp()

    /** Requests a token bound to [requestHash]. */
    suspend fun requestToken(requestHash: String): String
}

/**
 * Play Integrity **Standard API** token source.
 *
 * Call [warmUp] early (e.g. at app start); preparing the provider takes a few seconds.
 * An expired provider (`INTEGRITY_TOKEN_PROVIDER_INVALID`) is prepared again transparently.
 *
 * @param cloudProjectNumber The Google Cloud project number linked in Play Console.
 */
class PlayIntegrityTokenSource(
    context: Context,
    private val cloudProjectNumber: Long,
) : IntegrityTokenSource {
    private val manager = IntegrityManagerFactory.createStandard(context.applicationContext)
    private val mutex = Mutex()

    @Volatile
    private var provider: StandardIntegrityTokenProvider? = null

    override suspend fun warmUp() {
        mutex.withLock { provider = prepare() }
    }

    override suspend fun requestToken(requestHash: String): String {
        val request = StandardIntegrityTokenRequest.builder().setRequestHash(requestHash).build()
        return try {
            currentProvider().request(request).await().token()
        } catch (e: StandardIntegrityException) {
            if (e.errorCode != StandardIntegrityErrorCode.INTEGRITY_TOKEN_PROVIDER_INVALID) throw e
            warmUp()
            currentProvider().request(request).await().token()
        }
    }

    private suspend fun currentProvider(): StandardIntegrityTokenProvider =
        provider ?: mutex.withLock { provider ?: prepare().also { provider = it } }

    private suspend fun prepare(): StandardIntegrityTokenProvider =
        manager.prepareIntegrityToken(
            PrepareIntegrityTokenRequest.builder().setCloudProjectNumber(cloudProjectNumber).build(),
        ).await()
}
