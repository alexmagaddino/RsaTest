package it.alex

import java.io.IOException
import java.nio.charset.StandardCharsets.UTF_8
import java.security.*
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import java.util.*
import javax.crypto.Cipher


/**
 * Created by alexm on 14/05/2019
 */
object RsaUtil : RsaInterface {

    private const val KEY_ALGORITHM = "RSA"
    private const val ENCRYPT_DECRYPT_ALGORITHM = "RSA/ECB/PKCS1Padding"
    private const val SIGNATURE_ALGORITHM = "SHA256withRSA"

    @Throws(Exception::class)
    override fun sign(data: String): ByteArray =
        sign(data, generateKeyPair().private).toByteArray(UTF_8)

    @Throws(Exception::class)
    override fun sign(plainText: String, privateKey: PrivateKey): String {
        val privateSignature = Signature.getInstance(SIGNATURE_ALGORITHM)
        privateSignature.initSign(privateKey)
        privateSignature.update(plainText.toByteArray(UTF_8))

        val signature = privateSignature.sign()

        return Base64.getEncoder().encodeToString(signature)
    }

    @Throws(Exception::class)
    override fun verify(plainText: String, signature: String, publicKey: PublicKey): Boolean {
        val publicSignature = Signature.getInstance(SIGNATURE_ALGORITHM)
        publicSignature.initVerify(publicKey)
        publicSignature.update(plainText.toByteArray(UTF_8))

        val signatureBytes = Base64.getDecoder().decode(signature)

        return publicSignature.verify(signatureBytes)
    }

    @Throws(Exception::class)
    override fun encrypt(plainText: String, publicKey: PublicKey): String {
        val encryptCipher = Cipher.getInstance(ENCRYPT_DECRYPT_ALGORITHM)
        encryptCipher.init(Cipher.ENCRYPT_MODE, publicKey)

        val cipherText = encryptCipher.doFinal(plainText.toByteArray(UTF_8))

        return Base64.getEncoder().encodeToString(cipherText)
    }

    @Throws(Exception::class)
    override fun decrypt(cipherText: String, privateKey: PrivateKey): String =
        Cipher.getInstance(ENCRYPT_DECRYPT_ALGORITHM).let { decryptCipher ->
            decryptCipher.init(Cipher.DECRYPT_MODE, privateKey)
            String(decryptCipher.doFinal(Base64.getDecoder().decode(cipherText)), UTF_8)
        }

    @Throws(GeneralSecurityException::class, IOException::class)
    override fun loadPrivateKey(key64: String): PrivateKey = PKCS8EncodedKeySpec(Base64.getDecoder()
        .decode(key64))
        .let { keySpec ->
            KeyFactory.getInstance(KEY_ALGORITHM).generatePrivate(keySpec)
        }

    @Throws(GeneralSecurityException::class, IOException::class)
    override fun loadPublicKey(key64: String): PublicKey = X509EncodedKeySpec(Base64.getDecoder()
        .decode(key64))
        .let { keySpec ->
            KeyFactory.getInstance(KEY_ALGORITHM).generatePublic(keySpec)
        }

    @Throws(Exception::class)
    override fun generateKeyPair(): KeyPair = KeyPairGenerator
        .getInstance(KEY_ALGORITHM)
        .apply {
            initialize(2048, SecureRandom())
        }
        .generateKeyPair()

    override fun generateKeys(): Pair<String, String> = generateKeyPair()
        .let { keys ->
            Pair(Base64.getEncoder().encodeToString(keys.private.encoded),
                Base64.getEncoder().encodeToString(keys.public.encoded))
        }
}