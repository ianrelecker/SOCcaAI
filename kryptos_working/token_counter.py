"""
Token counter utilities for SOCca
A simple alternative to tiktoken that doesn't require complex build dependencies
"""

import re
import logging

logger = logging.getLogger('token_counter')

def count_tokens_simple(text):
    """
    Simple token counter that approximates OpenAI's tokenization
    This is less accurate than tiktoken but more reliable for builds
    
    Args:
        text: String to count tokens for
        
    Returns:
        Approximate token count
    """
    # Simple approximation method
    # Average English word is ~4 characters + 1 for space
    # OpenAI tokens are ~4 chars on average
    # This will be an approximation but works for limit checking
    
    if not text:
        return 0
        
    # Basic cleanup
    text = text.strip()
    
    # Count words (space-separated)
    words = len(re.findall(r'\S+', text))
    
    # Count special characters and punctuation
    special_chars = len(re.findall(r'[^\w\s]', text))
    
    # Estimate token count: words + additional for special chars
    # Typically, 3/4 words per token
    estimated_tokens = int(words * 0.75) + int(special_chars * 0.25)
    
    return max(1, estimated_tokens)

def truncate_to_token_limit(text, limit=126000):
    """
    Truncate text to stay within a token limit
    Uses a conservative approach to ensure we stay under the limit
    
    Args:
        text: Text to truncate
        limit: Maximum token limit
        
    Returns:
        Truncated text
    """
    if not text:
        return ""
        
    current_text = text
    iterations = 0
    max_iterations = 10  # Avoid infinite loops
    
    while count_tokens_simple(current_text) > limit and iterations < max_iterations:
        # Cut ~10% of the text from the end each time
        # We go from the end to preserve most important info at the beginning
        cut_point = int(len(current_text) * 0.9)
        current_text = current_text[:cut_point]
        iterations += 1
        logger.info(f"Truncating text: iteration {iterations}")
    
    return current_text