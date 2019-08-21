package it.alex


const val ciao = "ciao"

const val pvt = "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCe5kyAvT+ba27n9B2UGOVL9Q/0" +
        "    BiR6MjVRsyQR6T7vUR8k2irEHxeEJJ2kVUD0FEds7pLHvEDOrNr9DJ3RSobsTw4tqvXcdd31y1Qy" +
        "    YzLSMKGmiA13S9bpVT25byXabyKUD2AE3gHQCNY02qXtJINaXqoCXhC2sxAX33wUd3M8qITKZ7c0" +
        "    qjjzAju2nHNlVlEKqWjJPhlxEMtVFhEsZFuikjMvVlU8Tk4Bga0rZfEO35M/Me73qSiATl/GDPAU" +
        "    fyEdfE7G4/mrhzqlBlwqqZBAwFA4E0h8t9iUENYNubf3F2PMeNPXuS/YlbTrN34heA8+4D1soues" +
        "    mzG4caGgdT+bAgMBAAECggEAH0yDszQTzFxcCypljR9eQxjxXIK9OqibIg2kRDbqY59aABtNIzZw" +
        "    nmHL/2ufkLRR4V4Y4WjuZwdbV07d4zTH4NItm8c6CIPbBahYXFh30TktDi1sYZw5p9pXfygqj50m" +
        "    dX2Vzz+focer0dtjpZN0oB9XY4H9zs70k4881Jc2xrKniBY/T+U1BNiESn/O9SxGl+IyoVNlzqrB" +
        "    fq98nYKi5s+HCmPJmjFEDUV6UHOWiFZW+sj+5I0UniMUq/EHSnNyaB6a1RnVz+8p8Ld+kBLTzV9R" +
        "    ZXQTffeWhLi8pMF2+THzGoRWZq9+s8WJGA1q7KaGyPNquAh4uBh3j4a8UaT3UQKBgQDLZA5D+k62" +
        "    3jd0+7l/4ImFTSpgXxyCLftnwkj8mwTZWV8u4ujjhzvLc1q8S1n6oOpG1kHr56HgGioZHZtQuOmU" +
        "    2lNXJsOt9bh0c2psPeGSdQViYfsSEBFTE1ud8X2ugTmn8U7Zugpo3kcSeRBiOfLy2S06+8UsuW3j" +
        "    Ptd4gqEOSQKBgQDIACn8fwW4at5OpvlfBg38Q4n4Lq1Mawg3xw51JT+xDwatZnMJZV+l8XS0/JDZ" +
        "    7wWNwEElwZjM3dkt6IYuyWoFepFmIV9H93gTM05VHKVUPFlJASiN9UkMOrLubYo8iEVdh6+e31sF" +
        "    0Ttw0RgT1O3j1FVGPA1Uc49bwxIVHoRuwwKBgDcS5tH9a2cVEQs6RmacFGDmHj1uQ7f0X4kfEMhl" +
        "    6ZA5JQ77HnjN26EhoUYvWTQGcqmvxrXsSOb37sJSRAY9q/JElCCbPI1UZhgSUJTyxKv1x/l18phX" +
        "    hXlrWnmQNKoWD9ir/N/0AnGXDsOvyIHwkxqzOA4qsp+Drn/EOnBFXvsRAoGBAIDZijM/6oGLaDmn" +
        "    3VTY4724DXU1LTTkZ+D3f1r9anE5ywV/0XEmPF7+lj/bz753/U37pH0cosKp0rd+7KPL42AwPOhd" +
        "    a7NDvbow/bBbyi/gyWz9MBF1C2CzmH9/VuX0rSu6tOxX3Z571B20uBxeu/xh2aZsHfJgmOV3YXj1" +
        "    tkBdAoGBAKGhzY1/KOTkurisaW7phiZlmJLPnz06a0YzT+ecs1RI0AKU3hizANagWfPUfNQZacaa" +
        "    24yo2ffQgz43oSr9oS7BRQoQVYRVPmAYTxrL7Rd66FtsuVTnRqbVM0vLUPKhKqwlHFqKah9H4+ey" +
        "    V4LqJK86id2W4lGhciUVMwuHmml0"

const val pub = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnuZMgL0/m2tu5/QdlBjlS/UP9AYkejI1" +
        "    UbMkEek+71EfJNoqxB8XhCSdpFVA9BRHbO6Sx7xAzqza/Qyd0UqG7E8OLar13HXd9ctUMmMy0jCh" +
        "    pogNd0vW6VU9uW8l2m8ilA9gBN4B0AjWNNql7SSDWl6qAl4QtrMQF998FHdzPKiEyme3NKo48wI7" +
        "    tpxzZVZRCqloyT4ZcRDLVRYRLGRbopIzL1ZVPE5OAYGtK2XxDt+TPzHu96kogE5fxgzwFH8hHXxO" +
        "    xuP5q4c6pQZcKqmQQMBQOBNIfLfYlBDWDbm39xdjzHjT17kv2JW06zd+IXgPPuA9bKLnrJsxuHGh" +
        "    oHU/mwIDAQAB"

fun main() {

    println(
        RSAUtils.encryptInBase64WithPublicBase64Key(pub, ciao)
    )

}


