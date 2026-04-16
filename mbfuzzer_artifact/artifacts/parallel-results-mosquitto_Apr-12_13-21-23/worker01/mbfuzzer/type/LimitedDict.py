from collections import OrderedDict
import threading


# actually, this type could be merge with LimitedSizeSortedDict
class LimitedDict:
    def __init__(self, max_size):
        self.max_size = max_size
        self.data = OrderedDict()
        self.lock = threading.Lock()

    def __iter__(self):
        with self.lock:
            return iter(self.data)
            
    def __setitem__(self, key, value):
        with self.lock:
            if len(self.data) >= self.max_size:
                oldest_key = next(iter(self.data))
                del self.data[oldest_key]
            self.data[key] = value 

    def __getitem__(self, key):
        return self.data.get(key, None)

    def __contains__(self, key):
        return key in self.data

    def delete(self, key):
        with self.lock:
            if key in self.data:
                del self.data[key]
