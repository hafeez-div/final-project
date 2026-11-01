"""
Tests for Platform Identification, Source Type Classification,
Google Thumbnail Separation, and Scrapling Metadata Enrichment.
"""

from unittest.mock import MagicMock, patch
import pytest

from digitalshield.web_discovery.lens_models import (
    detect_platform_name,
    detect_source_type,
    is_google_thumbnail_url,
)
from digitalshield.web_discovery.google_lens_provider import GoogleLensProvider
from digitalshield.web_discovery.page_enricher import enrich_page, _extract_page_metadata_from_html
from digitalshield.web_discovery.models import WebDiscoveryResult, WebDiscoverySession


class TestPlatformClassification:
    """Test suite for domain and URL based platform identification."""

    def test_social_media_platforms(self):
        assert detect_platform_name("https://twitter.com/user/status/12345") == "X (Twitter)"
        assert detect_platform_name("https://x.com/user/status/12345") == "X (Twitter)"
        assert detect_platform_name("https://t.co/xyz123") == "X (Twitter)"

        assert detect_platform_name("https://www.reddit.com/r/funny/comments/abc/title/") == "Reddit"
        assert detect_platform_name("https://redd.it/xyz123") == "Reddit"

        assert detect_platform_name("https://www.instagram.com/p/Cxyz123/") == "Instagram"
        assert detect_platform_name("https://facebook.com/watch/?v=123") == "Facebook"
        assert detect_platform_name("https://fb.watch/xyz123/") == "Facebook"

        assert detect_platform_name("https://www.youtube.com/watch?v=dQw4w9WgXcQ") == "YouTube"
        assert detect_platform_name("https://youtu.be/dQw4w9WgXcQ") == "YouTube"

        assert detect_platform_name("https://www.tiktok.com/@user/video/123456") == "TikTok"
        assert detect_platform_name("https://www.pinterest.com/pin/123456/") == "Pinterest"
        assert detect_platform_name("https://en.wikipedia.org/wiki/Rowan_Atkinson") == "Wikipedia"
        assert detect_platform_name("https://commons.wikimedia.org/wiki/File:Example.jpg") == "Wikimedia"

    def test_google_thumbnail_detection(self):
        """Google thumbnail caches must be explicitly detected and not mistaken for publishers."""
        thumb_urls = [
            "https://encrypted-tbn0.gstatic.com/images?q=tbn:ANd9GcRKyow",
            "https://encrypted-tbn1.gstatic.com/images?q=tbn:ANd9GcT...",
            "https://encrypted-tbn2.gstatic.com/images?q=tbn:ANd9Gc...",
            "https://encrypted-tbn3.gstatic.com/images?q=tbn:ANd9Gc...",
            "https://lh3.googleusercontent.com/proxy/abc123xyz",
        ]
        for url in thumb_urls:
            assert is_google_thumbnail_url(url) is True
            assert detect_platform_name(url) == "Google (Thumbnail Cache)"
            assert "Thumbnail Cache" in detect_source_type("Google (Thumbnail Cache)", url)

    def test_other_public_websites(self):
        assert detect_platform_name("https://greatestmovies.fandom.com/wiki/Bean") == "Fandom Wiki"
        assert detect_platform_name("https://www.bbc.com/news/world-12345") == "BBC"
        assert detect_platform_name("https://www.imdb.com/title/tt0118689/") == "IMDb"
        assert detect_platform_name("https://some-personal-blog.org/post/1") == "some-personal-blog.org"

    def test_source_type_mapping(self):
        assert detect_source_type("X (Twitter)") == "Social Media Post"
        assert detect_source_type("Reddit") == "Public Forum Post"
        assert detect_source_type("Instagram") == "Social Media Post"
        assert detect_source_type("Facebook") == "Social Media Post"
        assert detect_source_type("YouTube") == "Video Platform"
        assert detect_source_type("TikTok") == "Social Media Video"
        assert detect_source_type("Pinterest") == "Image Board Post"
        assert detect_source_type("Wikipedia") == "Encyclopedia Article"
        assert detect_source_type("IMDb") == "Movie/TV Database Page"
        assert detect_source_type("BBC") == "News Article"

        # Pattern-based fallback
        assert detect_source_type("unknown-site.org", "https://unknown-site.org/wiki/Rowan") == "Encyclopedia Article"
        assert detect_source_type("forum-site.org", "https://forum-site.org/threads/123") == "Public Forum Post"
        assert detect_source_type("generic.org", "https://generic.org/page") == "Public Website"


class TestGoogleLensResponseParsing:
    """Test improved Google Lens response parsing with thumbnail separation."""

    def test_separates_thumbnails_and_source_pages(self):
        mock_data = {
            "visual_matches": [
                {
                    "position": 1,
                    "title": "Mr. Bean Official Reddit Discussion",
                    "link": "https://www.reddit.com/r/MrBean/comments/123/funny/",
                    "source": "Reddit",
                    "thumbnail": "https://encrypted-tbn0.gstatic.com/images?q=tbn:ANd9GcR",
                    "image": "https://i.redd.it/mrbean_highres.jpg",
                },
                {
                    "position": 2,
                    "title": "Bean (film) - Wikipedia",
                    "link": "https://en.wikipedia.org/wiki/Bean_(film)",
                    "source": "Wikipedia",
                    "thumbnail": "https://encrypted-tbn1.gstatic.com/images?q=tbn:ANd9GcS",
                },
            ],
            "organic_results": [
                {
                    "position": 1,
                    "title": "Rowan Atkinson YouTube Clip",
                    "link": "https://www.youtube.com/watch?v=bean123",
                    "thumbnail": "https://encrypted-tbn2.gstatic.com/images?q=tbn:ANd9GcT",
                    "image": "https://i.ytimg.com/vi/bean123/hqdefault.jpg",
                }
            ],
            "best_guess_labels": ["Rowan Atkinson Mr Bean"],
        }

        parsed = GoogleLensProvider._parse_lens_response(mock_data)

        pages = parsed["pages_with_matching_images"]
        assert len(pages) == 3

        # Check Reddit entry
        reddit_entry = next(p for p in pages if "reddit.com" in p["url"])
        assert reddit_entry["url"] == "https://www.reddit.com/r/MrBean/comments/123/funny/"
        assert reddit_entry["thumbnail"] == "https://encrypted-tbn0.gstatic.com/images?q=tbn:ANd9GcR"
        assert reddit_entry["source_image"] == "https://i.redd.it/mrbean_highres.jpg"

        # Check Wikipedia entry
        wiki_entry = next(p for p in pages if "wikipedia.org" in p["url"])
        assert wiki_entry["url"] == "https://en.wikipedia.org/wiki/Bean_(film)"
        assert wiki_entry["thumbnail"] == "https://encrypted-tbn1.gstatic.com/images?q=tbn:ANd9GcS"


class TestScraplingMetadataEnrichment:
    """Test extracting OpenGraph and public metadata."""

    def test_extract_html_metadata(self):
        sample_html = b"""<!DOCTYPE html>
        <html>
        <head>
            <title>Mr Bean Classic Episode - Reddit</title>
            <meta property="og:title" content="Classic Bean Scene | r/MrBean" />
            <meta property="og:image" content="https://preview.redd.it/bean_og.jpg" />
            <meta property="og:url" content="https://www.reddit.com/r/MrBean/comments/123/scene/" />
            <link rel="canonical" href="https://www.reddit.com/r/MrBean/comments/123/scene/" />
            <meta name="author" content="BeanFan99" />
            <time datetime="2026-05-15T10:30:00Z">May 15, 2026</time>
        </head>
        <body>
            <img src="/static/nav_icon.png" />
            <img src="https://i.redd.it/main_photo.jpg" />
        </body>
        </html>
        """
        meta = _extract_page_metadata_from_html(sample_html, base_url="https://www.reddit.com")

        assert meta["page_title"] == "Mr Bean Classic Episode - Reddit"
        assert meta["og_title"] == "Classic Bean Scene | r/MrBean"
        assert meta["og_image"] == "https://preview.redd.it/bean_og.jpg"
        assert meta["canonical_url"] == "https://www.reddit.com/r/MrBean/comments/123/scene/"
        assert meta["author"] == "BeanFan99"
        assert meta["publication_timestamp"] == "2026-05-15T10:30:00Z"
        assert "https://preview.redd.it/bean_og.jpg" in meta["image_urls"]
        assert "https://i.redd.it/main_photo.jpg" in meta["image_urls"]


class TestWebDiscoveryModels:
    """Test WebDiscoveryResult and WebDiscoverySession fields and serialization."""

    def test_web_discovery_result_fields(self):
        wdr = WebDiscoveryResult(
            result_id="WDR-2026-000001",
            session_id="WDS-2026-000001",
            evidence_id="EVD-2026-000001",
            case_id="DS-2026-000001",
            source_url="https://www.reddit.com/r/funny/comments/123/",
            page_title="Funny Post",
            domain="reddit.com",
            platform="Reddit",
            source_type="Public Forum Post",
            is_google_thumbnail=False,
            thumbnail_url="https://encrypted-tbn0.gstatic.com/thumb",
            media_url="https://i.redd.it/image.jpg",
            canonical_url="https://www.reddit.com/r/funny/comments/123/",
            provider_match_type="PAGE_WITH_IMAGE",
            retrieval_timestamp="2026-11-01T12:00:00Z",
            verification_status="High visual similarity",
        )
        d = wdr.to_dict()
        assert d["platform"] == "Reddit"
        assert d["source_type"] == "Public Forum Post"
        assert d["is_google_thumbnail"] is False

        restored = WebDiscoveryResult.from_dict(d)
        assert restored.platform == "Reddit"
        assert restored.source_type == "Public Forum Post"

    def test_web_discovery_session_platform_counts(self):
        sess = WebDiscoverySession(
            session_id="WDS-2026-000001",
            case_id="DS-2026-000001",
            evidence_id="EVD-2026-000001",
            provider="Google Lens",
            started_at="2026-11-01T12:00:00Z",
            completed_at="2026-11-01T12:02:00Z",
            platform_counts={"Reddit": 4, "YouTube": 2, "Wikipedia": 1},
            distinct_platforms=3,
        )
        d = sess.to_dict()
        assert d["platform_counts"]["Reddit"] == 4
        assert d["distinct_platforms"] == 3

        restored = WebDiscoverySession.from_dict(d)
        assert restored.platform_counts["Reddit"] == 4
        assert restored.distinct_platforms == 3


class TestResultsScreenPlatformFiltering:
    """Test GUI ResultsScreen platform filtering tabs and card display."""

    def test_gui_results_screen_filter(self):
        import tkinter as tk
        from digitalshield.gui.screens.results import ResultsScreen, _platform_tab_for

        assert _platform_tab_for("Reddit") == "Reddit"
        assert _platform_tab_for("X (Twitter)") == "X (Twitter)"
        assert _platform_tab_for("Instagram") == "Instagram"
        assert _platform_tab_for("Google (Thumbnail Cache)") == "Other Websites"
        assert _platform_tab_for("randomblog.com") == "Other Websites"

        root = None
        try:
            root = tk.Tk()
            root.withdraw()
        except Exception:
            return  # skip if headless without display

        try:
            mock_app = MagicMock()
            screen = ResultsScreen(root, mock_app)

            sample_results = [
                {
                    "result_id": "WDR-001",
                    "platform": "Reddit",
                    "source_type": "Public Forum Post",
                    "page_title": "Mr Bean on Reddit",
                    "source_url": "https://reddit.com/r/funny/1",
                    "media_url": "https://i.redd.it/pic.jpg",
                    "calculated_similarity": 0.95,
                    "verification_status": "Exact match",
                },
                {
                    "result_id": "WDR-002",
                    "platform": "YouTube",
                    "source_type": "Video Platform",
                    "page_title": "Mr Bean Clip",
                    "source_url": "https://youtube.com/watch?v=123",
                    "media_url": "https://ytimg.com/vi/123.jpg",
                    "calculated_similarity": 0.88,
                    "verification_status": "High similarity",
                },
                {
                    "result_id": "WDR-003",
                    "platform": "Google (Thumbnail Cache)",
                    "source_type": "Google Thumbnail Cache (not original publisher)",
                    "page_title": "Thumbnail preview",
                    "source_url": "https://encrypted-tbn0.gstatic.com/thumb",
                    "media_url": "https://encrypted-tbn0.gstatic.com/thumb",
                    "is_google_thumbnail": True,
                    "calculated_similarity": 0.70,
                    "verification_status": "Partial similarity",
                },
            ]

            # Populate all
            screen._all_results = sample_results
            screen._update_tab_counts(sample_results)
            screen._populate_tree(sample_results)

            children = screen._tree.get_children()
            assert len(children) == 3

            # Filter by Reddit
            screen._filter_by_platform("Reddit")
            children_reddit = screen._tree.get_children()
            assert len(children_reddit) == 1
            vals = screen._tree.item(children_reddit[0])["values"]
            assert vals[0] == "Reddit"

            # Filter by YouTube
            screen._filter_by_platform("YouTube")
            children_yt = screen._tree.get_children()
            assert len(children_yt) == 1
            vals_yt = screen._tree.item(children_yt[0])["values"]
            assert vals_yt[0] == "YouTube"

            # Filter by Other Websites (includes Google thumbnail)
            screen._filter_by_platform("Other Websites")
            children_other = screen._tree.get_children()
            assert len(children_other) == 1

            # Back to All Results
            screen._filter_by_platform("All Results")
            assert len(screen._tree.get_children()) == 3

        finally:
            if root:
                root.destroy()

