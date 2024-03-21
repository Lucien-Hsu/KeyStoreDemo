package tw.com.example.trykeystore

import android.os.Build
import android.os.Bundle
import android.util.Log
import androidx.annotation.RequiresApi
import androidx.appcompat.app.AppCompatActivity


class MainActivity : AppCompatActivity() {
    private val TAG = this.javaClass.canonicalName

    private lateinit var keyStoreHelper: KeyStoreHelper

    val myText = "Hello my text."

    @RequiresApi(Build.VERSION_CODES.O)
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        keyStoreHelper = KeyStoreHelper(this)

        Log.d(TAG, "onCreate: 加密:$myText")
        val encryptedMessage = keyStoreHelper.encryptAES(myText)
        val decryptedMessage = keyStoreHelper.decryptAES(encryptedMessage)
        Log.d(TAG, "onCreate: 解密:$decryptedMessage")
    }

}