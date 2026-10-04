package com.fadlurahmanfdev.example.presentation

import android.os.Bundle
import androidx.activity.enableEdgeToEdge
import androidx.appcompat.app.AppCompatActivity
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import androidx.recyclerview.widget.RecyclerView
import com.fadlurahmanfdev.example.R
import com.fadlurahmanfdev.example.data.ExampleResult
import com.fadlurahmanfdev.example.data.FeatureModel
import com.google.android.material.appbar.MaterialToolbar

abstract class AlgorithmExampleActivity : AppCompatActivity(), ListExampleAdapter.Callback {

    protected abstract val toolbarTitle: String
    protected abstract val features: List<FeatureModel>

    private lateinit var rv: RecyclerView
    private lateinit var adapter: ListExampleAdapter

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContentView(R.layout.activity_algorithm_example)
        ViewCompat.setOnApplyWindowInsetsListener(findViewById(R.id.main)) { view, insets ->
            val systemBars = insets.getInsets(WindowInsetsCompat.Type.systemBars())
            view.setPadding(systemBars.left, systemBars.top, systemBars.right, systemBars.bottom)
            insets
        }

        val toolbar = findViewById<MaterialToolbar>(R.id.toolbar)
        toolbar.title = toolbarTitle
        toolbar.setNavigationOnClickListener { onBackPressedDispatcher.onBackPressed() }

        rv = findViewById(R.id.rv)
        rv.setItemViewCacheSize(features.size)
        rv.setHasFixedSize(true)

        adapter = ListExampleAdapter()
        adapter.setCallback(this)
        adapter.setList(features)
        adapter.setHasStableIds(true)
        rv.adapter = adapter
    }

    protected fun showResult(result: ExampleResult) {
        ResultBottomSheet.show(supportFragmentManager, result)
    }
}
