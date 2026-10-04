package com.fadlurahmanfdev.example.presentation

import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.TextView
import com.fadlurahmanfdev.example.R
import com.fadlurahmanfdev.example.data.ExampleResult
import com.google.android.material.bottomsheet.BottomSheetDialogFragment
import com.google.android.material.button.MaterialButton

class ResultBottomSheet : BottomSheetDialogFragment() {

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?,
    ): View? = inflater.inflate(R.layout.bottom_sheet_example_result, container, false)

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        val title = requireArguments().getString(ARG_TITLE).orEmpty()
        val content = requireArguments().getString(ARG_CONTENT).orEmpty()

        view.findViewById<TextView>(R.id.tvResultTitle).text = title
        view.findViewById<TextView>(R.id.tvResultContent).text = content
        view.findViewById<MaterialButton>(R.id.btnClose).setOnClickListener { dismiss() }
    }

    companion object {
        private const val ARG_TITLE = "arg_title"
        private const val ARG_CONTENT = "arg_content"

        fun show(
            fragmentManager: androidx.fragment.app.FragmentManager,
            result: ExampleResult,
        ) {
            ResultBottomSheet()
                .apply {
                    arguments = Bundle().apply {
                        putString(ARG_TITLE, result.scenarioTitle)
                        putString(ARG_CONTENT, result.toDisplayText())
                    }
                }
                .show(fragmentManager, ResultBottomSheet::class.java.simpleName)
        }
    }
}
