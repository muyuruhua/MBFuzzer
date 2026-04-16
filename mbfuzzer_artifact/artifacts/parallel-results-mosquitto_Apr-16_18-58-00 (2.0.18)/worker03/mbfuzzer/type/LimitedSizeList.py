class LimitedSizeList:
    def __init__(self, max_size):
        self.max_size = max_size
        self.items = []

    def push(self, item):
        if len(self.items) >= self.max_size:
            self.items.pop(0)
        self.items.append(item)

    def print_queue(self):
        if len(self.items) == 0:
            return None
        
        results = ""
        for index, req in enumerate(reversed(self.items)):
            print(f"{index}: {req}")
            results += f"{index}: {req}\n"
        
        return results
    
    def clear(self):
        self.items.clear()
    
    def is_empty(self):
        return len(self.items) == 0

# Example usage:
if __name__ == "__main__":
    # Create a LimitedSizeList instance with max size of 5
    request_queue = LimitedSizeList(5)
    
    # Push requests
    for i in range(1, 8):
        request_queue.push(f"Request {i}")

    # Print the queue
    request_queue.print_queue()
