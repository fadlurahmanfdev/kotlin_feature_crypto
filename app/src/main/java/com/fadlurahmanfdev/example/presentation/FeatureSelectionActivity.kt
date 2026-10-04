package com.fadlurahmanfdev.example.presentation

import android.content.Intent
import android.os.Bundle
import androidx.activity.enableEdgeToEdge
import androidx.appcompat.app.AppCompatActivity
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import androidx.recyclerview.widget.RecyclerView
import com.fadlurahmanfdev.example.R
import com.fadlurahmanfdev.example.data.AlgorithmCatalog
import com.fadlurahmanfdev.example.data.FeatureModel
import com.google.android.material.appbar.MaterialToolbar

class FeatureSelectionActivity : AppCompatActivity(), ListExampleAdapter.Callback {

    private val features: List<FeatureModel> = AlgorithmCatalog.entries.map { algorithm ->
        FeatureModel(
            featureIcon = algorithm.iconRes,
            title = algorithm.title,
            desc = algorithm.subtitle,
            enum = algorithm.name,
        )
    }

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
        toolbar.title = getString(R.string.feature_selection_title)
        toolbar.navigationIcon = null

        rv = findViewById(R.id.rv)
        rv.setItemViewCacheSize(features.size)
        rv.setHasFixedSize(true)

        adapter = ListExampleAdapter()
        adapter.setCallback(this)
        adapter.setList(features)
        adapter.setHasStableIds(true)
        rv.adapter = adapter
    }

    override fun onClicked(item: FeatureModel) {
        val algorithm = AlgorithmCatalog.valueOf(item.enum)
        startActivity(Intent(this, algorithm.activityClass))
    }
}
