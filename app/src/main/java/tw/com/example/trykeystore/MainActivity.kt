package tw.com.example.trykeystore

import android.os.Build
import android.os.Bundle
import android.util.Log
import android.widget.TextView
import androidx.annotation.RequiresApi
import androidx.appcompat.app.AppCompatActivity


class MainActivity : AppCompatActivity() {
    private val TAG = this.javaClass.canonicalName

    private lateinit var sharedPreferencesHelper: SharedPreferencesHelper
    private lateinit var keyStoreHelper: KeyStoreHelper

    private val myText = "Hello my text."

    private lateinit var tvBefore: TextView
    private lateinit var tvAfter: TextView

    @RequiresApi(Build.VERSION_CODES.O)
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        initView()

        sharedPreferencesHelper = SharedPreferencesHelper(this)
        keyStoreHelper = KeyStoreHelper(sharedPreferencesHelper)

        tvBefore.text = myText
        val encryptedMessage = keyStoreHelper.encryptAES(myText)

        val decryptedMessage = keyStoreHelper.decryptAES(encryptedMessage)
        tvAfter.text = decryptedMessage
    }

    private fun initView() {
        tvBefore = findViewById(R.id.tvBefore)
        tvAfter = findViewById(R.id.tvAfter)
    }

}