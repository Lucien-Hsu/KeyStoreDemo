package tw.com.example.trykeystore

import android.content.Context


class SharedPreferencesHelper(context: Context) {
    private val PREF_NAME = "MY_PREF"
    private val PREF_AES_KEY = "PREF_AES_KEY"
    private val PREF_AES_IV = "PREF_AES_IV"

    private val pref = context.getSharedPreferences(PREF_NAME, 0)

    fun putAesKey(str: String) = pref.edit().putString(PREF_AES_KEY, str).apply()
    fun putAesIv(str: String) = pref.edit().putString(PREF_AES_IV, str).apply()

    fun getAesKey(): String = pref.getString(PREF_AES_KEY, "")!!
    fun getAesIv(): String = pref.getString(PREF_AES_IV, "")!!
}