from django.core.cache import cache
import logging

logger = logging.getLogger(__name__)

def invalidate_post_caches(post_id):
    """
    Invalidate all caches related to a specific post
    """
    logger.info(f"Invalidating caches for post {post_id}")
    
    # Clear specific post caches
    cache.delete(f"post_detail:{post_id}")
    
    # Since local memory cache doesn't support patterns, we'll use specific keys
    user_keys = [f"post_detail_serialized:{post_id}:{i}" for i in range(1, 100)]  # Assuming user IDs
    for key in user_keys:
        cache.delete(key)
    
    # Clear like count cache
    cache.delete(f"post_{post_id}_likes_count")
    
    # Clear newsfeed caches - we'll use specific page keys
    for page in range(1, 10):  # Assuming up to 10 pages
        for size in [5, 10, 20, 50]:  # Common page sizes
            cache.delete(f"newsfeed:page_{page}_size_{size}")
    
    logger.info(f"Cache invalidation completed for post {post_id}")

def get_feed_cache_key(user_id, params):
    """Create a cache key for news feed"""
    sort_by = params.get('sort_by', 'recent')
    filter_by = params.get('filter_by', 'all')
    time_range = params.get('time_range', 'all')
    page = params.get('page', '1')
    page_size = params.get('page_size', '10')
    
    return f"feed:user_{user_id}_{sort_by}_{filter_by}_{time_range}_page_{page}_size_{page_size}"