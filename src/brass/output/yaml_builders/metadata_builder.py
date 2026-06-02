"""
Metadata builder for YAML files.

Generates common metadata sections used across all YAML intelligence files.
Single responsibility: metadata creation only.
"""

from typing import List, Dict, Any
from collections import OrderedDict

from brass.models.finding import Finding
from .base_builder import BaseYAMLBuilder
from .yaml_utils import YAMLUtils


class YAMLMetadataBuilder(BaseYAMLBuilder):
    """
    Builds metadata sections for YAML files.
    
    Responsible for creating consistent metadata across all generated
    intelligence files including timestamps, project info, and analysis engine.
    """
    
    def build(self, findings: List[Finding]) -> Dict[str, Any]:
        """
        Build metadata section with project and analysis information.
        
        Args:
            findings: All findings (used for count)
            
        Returns:
            Metadata dictionary for YAML files
        """
        metadata = YAMLUtils.build_common_metadata(
            self.project_path, 
            self.generation_time
        )
        metadata['total_findings'] = len(findings)
        
        return metadata