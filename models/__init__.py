"""
ORACLE-TMF  ·  models/
========================
Data schema package.

The Mutation Artifact Graph (MAG) is the single shared data structure
that flows between all 12 pipeline stages.  It is defined here with
NO dependency on Androguard or any heavy library, so any stage can
safely import it without triggering expensive initialisation.

    from models.mutation_artifact_graph import (
        MutationArtifactGraph,
        DeadCodeArtifact,
        ArtifactClass,
        MutationForecast,
    )
"""
__version__ = "1.0.0"
