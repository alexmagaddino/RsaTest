package it.alex

fun <T> T.print(): T {
    println(this)
    return this
}

infix fun <T, S> T.isEqual(other: S){
    println(this == other)
}