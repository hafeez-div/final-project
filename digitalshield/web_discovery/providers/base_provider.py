"""
Base provider interface for reverse image search providers.
"""

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Dict


class BaseReverseImageProvider(ABC):
    """
    Abstract interface for reverse image search and web detection providers.
    """

    PROVIDER_NAME: str = "Base Provider"

    @abstractmethod
    def search_web(self, image_path: Path) -> Dict[str, Any]:
        """
        Execute reverse image search on an evidence image file.

        Returns a dictionary with standardized keys:
            - full_matching_image_urls: List[str]
            - partial_matching_image_urls: List[str]
            - visually_similar_image_urls: List[str]
            - pages_with_matching_images: List[Dict] with 'url', 'page_title', 'score', 'full_images', 'partial_images'
            - web_entities: List[Dict]
            - best_guess_labels: List[str]
        """
        pass
