"""Filtering package for brass.

`ai_review_filter` is the only live module — see brass_cli.py's
`filter` subcommand. The dead `IntelligentNoiseFilter` /
`NoiseReductionStats` exports were removed 2026-05-19: they were
parallel to (and less safe than) `scanners.noise_reduction_scanner`,
which is the actually-used implementation in the scan pipeline.
"""
