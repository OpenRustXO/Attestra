package dev.attestra.client

import android.content.Context
import java.util.UUID

/** Provides the per-install id bound into every Play Integrity request hash. */
fun interface InstallIdStore {
    fun installId(): String
}

/**
 * Persists a random UUID in private [android.content.SharedPreferences]. The id is created on
 * first use and lives until the app is uninstalled or its data cleared, i.e. one Attestra
 * device per install.
 */
class SharedPreferencesInstallIdStore(
    context: Context,
    preferencesName: String = "attestra",
) : InstallIdStore {
    private val preferences = context.applicationContext.getSharedPreferences(preferencesName, Context.MODE_PRIVATE)

    @Synchronized
    override fun installId(): String {
        preferences.getString(KEY, null)?.let { return it }
        // Lowercase canonical form, as the worker requires.
        val id = UUID.randomUUID().toString()
        preferences.edit().putString(KEY, id).apply()
        return id
    }

    private companion object {
        const val KEY = "install_id"
    }
}
