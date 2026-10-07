"""
Token usage tracking for SEVDF LLM calls.
Tracks input/output tokens for all non-Azure model calls.
"""
import os
import csv
import json
import time
from datetime import datetime
from threading import Lock


class TokenTracker:
    """Thread-safe token usage tracker"""
    
    def __init__(self):
        self.records = []
        self.lock = Lock()
        self.start_time = datetime.now()
        
    def add_record(self, model_name, prompt_tokens, completion_tokens, total_tokens,
                   additional_info=None):
        """
        Add a token usage record.

        Args:
            model_name: The model being used
            prompt_tokens: Number of input tokens
            completion_tokens: Number of output tokens
            total_tokens: Total tokens (prompt + completion)
            additional_info: Any additional information to store
        """
        # Skip Azure models
        if model_name and ('azure' in model_name.lower() or 'gpt4' in model_name.lower()):
            return

        with self.lock:
            record = {
                'timestamp': datetime.now().isoformat(),
                'model_name': model_name,
                'prompt_tokens': prompt_tokens,
                'completion_tokens': completion_tokens,
                'total_tokens': total_tokens,
                'additional_info': json.dumps(additional_info) if additional_info else ''
            }
            self.records.append(record)
    
    def save_to_csv(self, output_dir):
        """
        Save token usage records to a CSV file.
        
        Args:
            output_dir: Directory to save the CSV file
        """
        if not self.records:
            return None
            
        os.makedirs(output_dir, exist_ok=True)
        
        # Generate filename with timestamp
        filename = f"token_usage_{self.start_time.strftime('%Y%m%d_%H%M%S')}.csv"
        filepath = os.path.join(output_dir, filename)
        
        with self.lock:
            with open(filepath, 'w', newline='', encoding='utf-8') as csvfile:
                fieldnames = ['timestamp', 'model_name', 'prompt_tokens',
                             'completion_tokens', 'total_tokens', 'additional_info']
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                
                # Write header
                writer.writeheader()
                
                # Write records
                for record in self.records:
                    writer.writerow(record)
                
                # Write summary
                total_prompt = sum(r['prompt_tokens'] for r in self.records)
                total_completion = sum(r['completion_tokens'] for r in self.records)
                total_all = sum(r['total_tokens'] for r in self.records)
                
                # Add summary as comment at end of file
                csvfile.write(f"\n# Summary: {len(self.records)} requests\n")
                csvfile.write(f"# Total prompt tokens: {total_prompt}\n")
                csvfile.write(f"# Total completion tokens: {total_completion}\n")
                csvfile.write(f"# Total tokens: {total_all}\n")
                
        return filepath
    
    def get_summary(self):
        """Get a summary of token usage"""
        with self.lock:
            if not self.records:
                return {
                    'total_requests': 0,
                    'total_prompt_tokens': 0,
                    'total_completion_tokens': 0,
                    'total_tokens': 0,
                    'by_model': {}
                }
            
            summary = {
                'total_requests': len(self.records),
                'total_prompt_tokens': sum(r['prompt_tokens'] for r in self.records),
                'total_completion_tokens': sum(r['completion_tokens'] for r in self.records),
                'total_tokens': sum(r['total_tokens'] for r in self.records),
                'by_model': {}
            }
            
            # Group by model
            for record in self.records:
                model = record['model_name']
                if model not in summary['by_model']:
                    summary['by_model'][model] = {
                        'requests': 0,
                        'prompt_tokens': 0,
                        'completion_tokens': 0,
                        'total_tokens': 0
                    }
                
                summary['by_model'][model]['requests'] += 1
                summary['by_model'][model]['prompt_tokens'] += record['prompt_tokens']
                summary['by_model'][model]['completion_tokens'] += record['completion_tokens']
                summary['by_model'][model]['total_tokens'] += record['total_tokens']
            
            return summary


# Global token tracker instance
_token_tracker = None


def get_token_tracker():
    """Get the global token tracker instance"""
    global _token_tracker
    if _token_tracker is None:
        _token_tracker = TokenTracker()
    return _token_tracker


def reset_token_tracker():
    """Reset the global token tracker"""
    global _token_tracker
    _token_tracker = TokenTracker()