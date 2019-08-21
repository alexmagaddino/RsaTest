package it.alex


fun test1() {
    val (pvt, pub) = RsaUtil.generateKeys().also { (pvt, pub) ->
        println(pvt)
        println(pub)
    }

    val privateKey = RsaUtil.loadPrivateKey(pvt)
    val publicKey = RsaUtil.loadPublicKey(pub)

    println(RsaUtil.decrypt(RsaUtil.encrypt(ciao, publicKey), privateKey) == ciao)

}

/**
 * prova con classi miste Elia e mie
 */
fun test2() {
    val (pvt, pub) = RsaUtil.generateKeys()

    val ciaoEncrypted = RSAUtils.encryptInBase64WithPublicBase64Key(pub, ciao)

    println(RsaUtil.encrypt(ciao, RsaUtil.loadPublicKey(pub)) == ciaoEncrypted)

    val ciaoDecrypt = RsaUtil.decrypt(ciaoEncrypted, RsaUtil.loadPrivateKey(pvt))

    println(ciaoDecrypt)
    println(ciao)
    println(ciaoDecrypt == ciao)
}


@Throws(Exception::class)
fun test3() {
    val v = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEApvW+tOMuSbndSJQlCDyi" +
            "FMn6GigDiRVVcBmh/AJdAnMWhZu/ZqHJdPgr4Hy/I22V+2mA/hD10sW4OAbmT075" +
            "EgZ7gpxBA009ciw0JGiemqDt8opE4eSq8C89NGaLO4gyBl/lZgJuZBqCb83ya8/o" +
            "RUQQd2UJtdK1ZP19Fpk3fWZPTH4KFTtV/vVPwWt0cTszPxPIX0hRapdf4aQxVId0" +
            "1Itd4nAnJb3FLdDqySjVIo/JeG6L6BTkYY78HrxJttwqvs+6BdREsFNnCXr99dzf" +
            "+Wizf8ZqlPlGsjBBMM61fFKTdF2XVM244gHAqnJBKhM/hMmuF55X6Z+Fk4E557nN" +
            "pwIDAQAB"
    val ciaoEncrypted = RSAUtils.encryptInBase64WithPublicBase64Key(v, ciao)
    val p = "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCm9b604y5Jud1I" +
            "lCUIPKIUyfoaKAOJFVVwGaH8Al0CcxaFm79mocl0+CvgfL8jbZX7aYD+EPXSxbg4" +
            "BuZPTvkSBnuCnEEDTT1yLDQkaJ6aoO3yikTh5KrwLz00Zos7iDIGX+VmAm5kGoJv" +
            "zfJrz+hFRBB3ZQm10rVk/X0WmTd9Zk9MfgoVO1X+9U/Ba3RxOzM/E8hfSFFql1/h" +
            "pDFUh3TUi13icCclvcUt0OrJKNUij8l4bovoFORhjvwevEm23Cq+z7oF1ESwU2cJ" +
            "ev313N/5aLN/xmqU+UayMEEwzrV8UpN0XZdUzbjiAcCqckEqEz+Eya4Xnlfpn4WT" +
            "gTnnuc2nAgMBAAECggEAJ0+/ionfUT6xKrCvE4RrSWfROq1nP7TFPDLc4CCSU8xT" +
            "Zjwo0fqQG7l/Y0kcHDRmVx8dXzURHIKvgImnWs8meCcMl9FAwY1DRYnA8T2s8o2n" +
            "2S7TTzjvQsRsrdTjPa4w0S1tLxqtcWaIhdjBFr+KWhzPn70rjyNA0Lma5WJIHX9D" +
            "FVi9K8dZxjx6sqgYZ35xmJYuiIf971cjee6rHee3ZAhZaaTFFLFpkJcbToGNIFMN" +
            "u15nIAqHmwBw9TzF7QiI540nCd3X7mAyJfPyf1/wZkBWCL1qa2fGpIJ2dovEttnm" +
            "X7vJdWJ3wMNb5RGIFdykV8g2W2xVLVS7+wZ09nIiEQKBgQDTOiKXZbFqmch2ZxI2" +
            "N6+nP/U0gPlLSs4q6/E32t+CqEfKRf8BqXNJTpbYagFa/BeutrpJDDhURUloQ64S" +
            "62wXD+qzkDArYb3IULVOsrJYc4Po8q0lrpC0vRGwmSWW9BTk/lxMi0FvpJgdLv2g" +
            "velhOoEq3XcuFMjen/e+Z7TiLwKBgQDKWYf7xtbJzq7qY3n9nRZnTIxvOdOvr1I+" +
            "P7zgvyM84brAa7bUNBmKBe/M1To63I7Mdiawz1NFJejoFp42XdY0siD0fgVaSUpG" +
            "tZ5XoPVpebRX/v+Ak8ECssH6AUkCWiTPMvZW7aYlyISNoEt7HyhJ872edRXzG0wv" +
            "31b7k4tGCQKBgQCAPnWuEfIL1N6e9Klb/adKFkzb2cqB6iMOcD3+OYcmnuEncCQJ" +
            "cEYspehz8Lht80y1qP+lRiQVFhQhl6Ximsj/n4xSBSMZ07gUHNxXsasShN/72QtD" +
            "K59z/K7216S45+yfs8d6Obo6/GXWoicfJu7BN3IhAmFPuxLSB7G1CuYJxQKBgDpL" +
            "EKG35qi8oidkAQDPAGVB6DMitZknKMpGEmOsrLodTW+hmEoJuFHK5ApeYygR4hGE" +
            "+CB3mcWR5kb2PR3saolDx7qnk2MvOfak27ji5dA8/3daPsELz863MKqVNDM5ROFs" +
            "DQt96x93ZLhoNVaC41hqn3XGxUwD0S75aFWRa84BAoGBAJZJ1Ha2A+WU7wMSdV4z" +
            "tUPZFgvc6iSaActwHsHdtXmqJY5No1/VArMLM/eSvR8mWjvPGz2i8wDzx1IliidP" +
            "Q9UpUOCY4XpfMhKUhiS7z3WmW6giqupMGCQFEDJZzF5WP2qHjKcA/5Zf5tSYR0RZ" +
            "cw237qaT7xhJ58a2ct7GM9GB"
    val privat =
        "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDPtCz5R/xeA0drleiXzComwkhnOHaeN6JnD4ozdF+Paq5BOEfXnR1MtJNMQ98kdfChlvWRyMIN7EL/OxlA9lLtBjHSYAGtiHHXauU+13b7Xqsbpabuo4CE4d0Jq0BS31+PVfiLpipkdRAeuBvSwufBfX2r6z8wDYGLao4B08yxicCbQYG4w+mMxLfim7QOeIX+FXLMcNgZUxXYJr2WlmQlAzGRQAuMFrikQipmJGf3mUgQIH1iWkdAZqMA3ew5cRlltEdl4lITAtmaRh9c1koS+pAZd9nBwxd7K61ww/BvqWK7jFudlCNEoc91G9fyAcwOk3b8iKADLst6tVmgdGSlAgMBAAECggEBAIzTegbOwxKvIHaWnqyFdjLvWY3635oo2IkOJUL77WrdBycbVMKhOWNvr8tu3VXoTW4SX5An0UMFZOuOk3HTUah5ocAk7h5Nu/o19RclmfuXVWaaa1O0Mghm56qNnUBTSYRy4uE0mdug73wUknDVS7OKNXIiP6aCEcqIRZ6Bj3DzX1IFNCp8KfHLqchL57Nex2zCocU5nxwNgYQDK+afqvwgN/pKOtZg92WbG3j4YyR4OjicxMg73GdmV+OLBVCIr9ARK5Aju//PpUiL7LF9REln4IPkZkniPUmN1kIfZKKlmt5e4oylKGy4pwv7jQshtyL2a8k1f/3hokeuFmsD3QECgYEA8NmBdX7RedFwoxC6DjApId57GzFw2bw3B2R5rgNjUy3pvuEPRrEL4tvbCXd502Ak3K97OQEOiA+do04LPa0+A+EQwjq9ledvoSBvjCSX/MQ91YOWdLuGV7ee3FKn9sonzokzo17hQ/Kxfd3coCAy5zUo04gfGVA+UGgX61Vm0+UCgYEA3MTo+u1cdTGRfKSic/xzOKnWXwDyxoKxOQktAyqfzNQTZHGNo6CMvBWflpN3ioWWSp1G2ZKdMIkPYc0ij+ChWhV4Y1Y63+dpCsnO/HUlP2nTV5SFc0DBvAO2THuiHAGXmeCblETOq3s0uRrV64UNgtpLeMKryOwL+mfN14KDwcECgYB7kZxyA9bFgUcg4nwSu3LfBZ5znTIhBAfXqx0iwmo7StsaK64CvuMySUpf2QSQBkvjTcUSwhAKjrh6CJiL1E50/wvyGuEZ/9ut905DwKKZ9LUkzpZq3atXZcYDlATJAX7a4Fm1///jNKkLwsBnBx4WsZd4r+YEvr650i4zd2WCYQKBgQDDC+E+mGjATZvZAGdai+aMYFi6NM9JHPxQhM/U5Vqrj47WhhB6SQUtwvjtArpxktaWc1++J+9iiyUg5iir7uz+9ssXEH8RhJTkaCnMF/9hiDClRt2kVskTQEBWUECH98wlsjAiDax+CmspQxFOdI3cVtqpBWzaJdnrULyms3OOwQKBgF/DDGM2j5VwAb4FjccakJGAXgqn85/XZqHMggi33Pqpix4xjKIJXEB8mA3CkCXgfvri1+LZ9mOX1PcAg1XodFZKucCYtv33LtKtkuLtf+g2NIxqGTS3RcIr8iHVGjN7ddjq8yUKOYmqsoI1J6c0iC779bqWtPPR5HKB5gwt7SSZ"

    println(

        RSAUtils.decryptBase64WithPrivateKeyBase64(privat, ciaoEncrypted) == ciao

    )

    println(
        RSAUtils.decryptBase64WithPrivateKeyBase64(
            privat,
            "jR/IBBrUTgbKcOwzYRYVGZQuC85/V2JyNZ3hJsGeqEg9ULYsPjGpkpdhWb9PmYaJ/oILNrCXxIyAQCEjjSbcXIYCXvoQsWGtM+J1h9TAXfwE636so8x3lYJXzRWWuccWNGfVPl674Cixrnq7j09MyYhPpEqJ03H24LgTdSoe+PZczZWyVTLf8hsml7Iw71srNCfBQsnyJ5H+UtnpXGt5y6uGfwnIfhXXHVHTq5sHvs9oKeSdcYC64zL0GmhMqONqd1s5bzicLL9FomZqlHIyiIbOAaQmBwyitmxxuGLU85s3hUwgahsBp/7pKQDaulv86WNKcXuKgkR/rY6y9IB3ig=="
        )
    )
}

fun test4() {
    println(
        RSAUtils.encryptInBase64WithPublicBase64Key(pub, ciao)
    )
}

fun test5() {

//    println(RsaUtil.loadPrivateKey(pvt) == RSAUtils.getPrivate(Base64.getDecoder().decode(pvt))) true
//    println(RsaUtil.loadPublicKey(pub) == RSAUtils.getPublic(Base64.getDecoder().decode(pub))) true

    val eliaCiao = RSAUtils.encryptInBase64WithPublicBase64Key(pub, ciao).print()

    val magazCiao = RsaUtil.encrypt(ciao, RsaUtil.loadPublicKey(pub)).print()

    val dec1 = RSAUtils.decryptBase64WithPrivateKeyBase64(pvt, eliaCiao).print()
    val dec2 = RsaUtil.decrypt(eliaCiao, RsaUtil.loadPrivateKey(pvt)).print()

    val dec3 = RsaUtil.decrypt(magazCiao, RsaUtil.loadPrivateKey(pvt)).print()
    val dec4 = RSAUtils.decryptBase64WithPrivateKeyBase64(pvt, magazCiao).print()

    (dec3 == dec4).print()

    (dec1 == dec2).print()

    println(RSAUtils.encryptInBase64WithPublicBase64Key(pub, ciao) == RsaUtil.encrypt(ciao, RsaUtil.loadPublicKey(pub)))
}