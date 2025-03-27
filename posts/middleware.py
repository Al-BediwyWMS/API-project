from time import time
from django.utils.deprecation import MiddlewareMixin
from singletons.logger_singleton import LoggerSingleton

logger = LoggerSingleton().get_logger()

class CacheMonitorMiddleware(MiddlewareMixin):
    """
    Middleware to monitor cache performance for API endpoints
    """
    
    def process_request(self, request):
        # Start timing
        request.start_time = time()
    
    def process_response(self, request, response):
        # Only monitor API endpoints
        if hasattr(request, 'start_time') and request.path.startswith('/posts/'):
            # Calculate request duration
            duration = time() - request.start_time
            
            # Log performance data
            logger.info(
                f"API Request: {request.method} {request.path} | "
                f"Duration: {duration:.4f}s | "
                f"Status: {response.status_code}"
            )
            
            # Add performance data to response headers
            response['X-Request-Duration'] = f"{duration:.4f}s"
        
        return response