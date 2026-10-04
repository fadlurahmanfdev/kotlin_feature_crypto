package com.fadlurahmanfdev.example.data

data class ExampleResult(
    val scenarioTitle: String,
    val lines: List<ResultLine>,
) {
    fun toDisplayText(): String = buildString {
        lines.forEach { line ->
            append(line.label)
            append(": ")
            appendLine(line.value)
        }
    }
}

data class ResultLine(
    val label: String,
    val value: String,
)
