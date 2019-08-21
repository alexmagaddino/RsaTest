package it.alex

fun <T> T.print(): T {
    println(this)
    return this
}