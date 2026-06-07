package com.fadlurahmanfdev.example.presentation

import androidx.lifecycle.ViewModel
import com.fadlurahmanfdev.example.domain.ExampleCryptoUseCase

class MainViewModel(
    private val exampleCryptoUseCase: ExampleCryptoUseCase,
) : ViewModel() {

    fun exampleED25519() {
        exampleCryptoUseCase.exampleED25519()
    }

    fun customSymmetricCrypto() {
        exampleCryptoUseCase.customSymmetricCrypto()
    }

    fun customAsymmetricCrypto() {
        exampleCryptoUseCase.customAsymmetricCrypto()
    }
}
