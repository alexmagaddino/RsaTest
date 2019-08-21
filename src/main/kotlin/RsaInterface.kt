package it.alex

import java.security.KeyPair
import java.security.PrivateKey
import java.security.PublicKey


/**
 * Created by alexm on 16/08/2019
 */
interface RsaInterface {

    fun sign(data: String): ByteArray

    fun sign(plainText: String, privateKey: PrivateKey): String

    fun verify(plainText: String, signature: String, publicKey: PublicKey): Boolean

    /**
     * Prototipo ch espone il contratto di criptazione di un testo grazie ad una chiave publica
     * */
    fun encrypt(plainText: String, publicKey: PublicKey): String

    /**
     * Prototipo ch espone il contratto di decriptazione di un testo grazie ad una chiave privata
     * */
    fun decrypt(cipherText: String, privateKey: PrivateKey): String

    /**
     * Questa prototipo espone il contratto di una funzione che deve generare un KeyPair
     * di chiavi publica e privata con algoritmo Rsa
     * */
    fun generateKeyPair(): KeyPair

    /**
     * Come sopra ma come coppia di stringhe
     * */
    fun generateKeys(): Pair<String, String>

    /**
     * Converte una chiave privata in ciao base 64 in PrivateKey
     * */
    fun loadPrivateKey(key64: String): PrivateKey

    /**
     * Converte una chiave publica in ciao base 64 in PublicKey
     * */
    fun loadPublicKey(key64: String): PublicKey
}
