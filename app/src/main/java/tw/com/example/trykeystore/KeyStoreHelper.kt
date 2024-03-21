package tw.com.example.trykeystore

import android.content.Context
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Log
import androidx.annotation.RequiresApi
import java.nio.charset.StandardCharsets
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.PublicKey
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

@RequiresApi(Build.VERSION_CODES.O)
class KeyStoreHelper(context: Context) {
    private val TAG = this.javaClass.canonicalName

    private val KEYSTORE_PROVIDER = "AndroidKeyStore"
    private val KEYSTORE_ALIAS = "MY_KEYSTORE"
    private val keystore: KeyStore = KeyStore.getInstance(KEYSTORE_PROVIDER)

    private val AES_MODE = "AES/GCM/NoPadding"
    private val RSA_MODE = "RSA/ECB/PKCS1Padding"

    private val pref = SharedPreferencesHelper(context)

    init {
        //加載 KeyStore，參數通常為 null，表示沒有密碼。在 Android 中對於 AndroidKeyStore，通常情況下不需要密碼。
        keystore.load(null)
        //若不存在需要的 Key 則產生，這邊檢查是否包含所需的 KeyPair 的別名
        if (!keystore.containsAlias(KEYSTORE_ALIAS)) {
            Log.d(TAG, "init: 沒有密鑰，重新產生")
            //產生 RSA 密鑰對
            genRSAKeyPair()
            //產生 AES Key
            genAESKey()
        }
    }

    @RequiresApi(Build.VERSION_CODES.O)
    private fun genRSAKeyPair(keySize: Int = 2048): Boolean {
        try {
            // 1.創建 KeyPairGenerator 實例
            // 參數一：指定使用的演算法，這邊用 RSA。
            // 參數二：指定使用 AndroidKeyStore 產生密鑰，只有這樣才會由 Android 系統保存密鑰，所以這是最佳實踐。
            val keyPairGenerator =
                KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, KEYSTORE_PROVIDER)

            // 2.設定密鑰參數
            // 參數一：别名，用於密鑰檢索
            // 參數二：指定密鑰用途
            val spec = KeyGenParameterSpec.Builder(
                KEYSTORE_ALIAS,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
            )
                .setKeySize(keySize) //設定密鑰長度，最小要大於等於2048才安全
                .setDigests(KeyProperties.DIGEST_SHA256) //指定使用 SHA-256 哈希算法加密
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1) //設定填充算法，避免明文攻擊
                .build()

            //3.初始化密鑰
            keyPairGenerator.initialize(spec)

            //4.生成RSA密钥对，并返回包含公钥和私钥的 KeyPair 对象
            val keyPair: KeyPair = keyPairGenerator.generateKeyPair()

            val privateKey: PrivateKey = keyPair.private // 取私鑰
            val publicKey: PublicKey = keyPair.public // 取公鑰
            Log.d(TAG, "generateRSAKeyPair: privateKey:$privateKey")
            Log.d(TAG, "generateRSAKeyPair: publicKey:$publicKey")

            return true
        } catch (e: Exception) {
            Log.d(TAG, "generateRSAKeyPair: catch error:${e.message}")
        }

        return false
    }

    private fun genAESKey() {
        Log.d(TAG, "genAESKey: >>>")

        try {
            //SecureRandom 專門用於產生高度隨機性的隨機數，以用於加密
            val secureRandom = SecureRandom()

            //1.產生 AES-Key
            val aesKey = ByteArray(16).apply {
                secureRandom.nextBytes(this) // 產生 16*8 = 128 隨機數
            }
            val encryptAesKey = encryptRSA(aesKey) // 用 RSA 公鑰加密 AES-Key
            pref.putAesKey(encryptAesKey) // 存起來
            Log.d(TAG, "genAESKey: aesKey:$aesKey, encryptAesKey:$encryptAesKey")

            //2.產生 iv
            val aesIv = secureRandom.generateSeed(12) // 產生 12 bytes iv（初始化向量）
            val encryptAesIv = encryptRSA(aesIv) // 用 RSA 公鑰加密 AES-IV
            pref.putAesIv(encryptAesIv) // 存起來
            Log.d(TAG, "genAESKey: aesIv:$aesIv, encryptAesIv:$encryptAesIv")

        } catch (e: Exception) {
            e.printStackTrace()
        }

        Log.d(TAG, "genAESKey: <<<")
    }

    private fun encryptRSA(messageBytes: ByteArray): String {
        val publicKey = keystore.getCertificate(KEYSTORE_ALIAS).publicKey // 取得公鑰
        val encryptCipher = Cipher.getInstance(RSA_MODE) // 加解密需使用 Cipher 搭配密鑰
        encryptCipher.init(Cipher.ENCRYPT_MODE, publicKey) // 初始化，加密時要搭配 publicKey

        val encryptedMessageBytes = encryptCipher.doFinal(messageBytes) // 用 doFinal 加密字串
        val base64String: String = encryptedMessageBytes.toHexString() // 轉成 base 64 方便使用與傳遞
//        Log.d(TAG, "encryptRSA: base64String:$base64String")

        return base64String
    }

    private fun decryptRSA(encodedMessage: String): ByteArray {
        val privateKey = keystore.getKey(KEYSTORE_ALIAS, null)

        var decryptCipher: Cipher = Cipher.getInstance(RSA_MODE) // 用 Cipher
        decryptCipher.init(Cipher.DECRYPT_MODE, privateKey) // 初始化，解密時要搭配 privateKey

        val encryptedMessageBytes = encodedMessage.hexToByteArray()
        val messageBytes = decryptCipher.doFinal(encryptedMessageBytes) // 用 doFinal 解密
        Log.d(TAG, "decryptRSA: messageBytes:${messageBytes}")

        return messageBytes
    }

    fun encryptAES(messageString: String): String {
        Log.d(TAG, "encryptAES: >>>")

        //先用 RSA 把 AES Key 解密，這樣就能取得 AES Key
        val aesKey = decryptRSA(pref.getAesKey())
        val iv = decryptRSA(pref.getAesIv())

        //加解密需使用 Cipher 搭配密鑰
        val encryptCipher = Cipher.getInstance(AES_MODE)
        //初始化，加密時要搭配 publicKey
        encryptCipher.init(
            Cipher.ENCRYPT_MODE,
            SecretKeySpec(aesKey, AES_MODE),
            IvParameterSpec(iv)
        )

        Log.d(TAG, "encryptAES: messageString:$messageString")
        val messageBytes = messageString.toByteArray(Charsets.UTF_8) // 把字串轉爲 bytes
        val encryptedMessageBytes = encryptCipher.doFinal(messageBytes) // 用 doFinal 加密 bytes
        val base64String: String = encryptedMessageBytes.toHexString() // bytes 轉成 base 64 方便使用與傳遞
        Log.d(TAG, "encryptAES: base64String:$base64String")

        Log.d(TAG, "encryptAES: <<<")
        return base64String
    }

    fun decryptAES(encodedMessage: String): String {
        Log.d(TAG, "decryptAES: >>>")

        val aesKey = decryptRSA(pref.getAesKey())
        val iv = decryptRSA(pref.getAesIv())

        //用 Cipher
        var decryptCipher: Cipher = Cipher.getInstance(AES_MODE) //使用默認算法
        //初始化，解密時要搭配 privateKey
        decryptCipher.init(
            Cipher.DECRYPT_MODE,
            SecretKeySpec(aesKey, AES_MODE),
            IvParameterSpec(iv)
        )

        Log.d(TAG, "decryptAES: encodedMessage(base64String):$encodedMessage")
        val encryptedMessageBytes = encodedMessage.hexToByteArray() // base 64 轉回 bytes
        val messageBytes = decryptCipher.doFinal(encryptedMessageBytes) // 用 doFinal 解密 bytes
        val decryptedMessage = String(messageBytes, StandardCharsets.UTF_8) // bytes 轉字串
        Log.d(TAG, "decryptAES: decryptedMessage:$decryptedMessage")

        Log.d(TAG, "decryptAES: <<<")
        return decryptedMessage
    }

    private fun ByteArray.toHexString(): String =
        joinToString(separator = "") { byte ->
            //"%"：格式化指令的起始符號。
            //"0"：填充字符。在不夠指定寬度時填充的字符。
            //"2"：指定的最小寬度為兩個字元。如果生成的字串長度不足兩個字元，將在左側填充指定的字符（在這裡是0）。
            //因此，"%02x".format(byte) 會將位元組 byte 轉換為一個兩位的十六進制字串。如果位元組的十六進制表示只有一個字元寬度，則會在左側填充一個零。
            "%02x".format(byte)
        }

    private fun String.hexToByteArray(): ByteArray =
        chunked(2)                            // 將字符串按每兩個字符一組拆分
            .map { it.toInt(16).toByte() }    // 對每組字符執行轉換為十進制數字，然後轉換為字節
            .toByteArray()                    // 將結果轉換為字节数组

}