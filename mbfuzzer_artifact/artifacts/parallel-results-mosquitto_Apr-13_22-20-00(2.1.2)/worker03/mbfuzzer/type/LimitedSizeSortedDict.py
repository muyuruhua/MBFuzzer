from collections import deque
import datetime

class LimitedSizeSortedDict:
    def __init__(self, max_size=100):
        self.max_size = max_size
        self.data_deque = deque(maxlen=max_size)    # format: [(timestamp, message), ...], Note: message must be string type, e.g., 102334

    def add_item(self, timestamp, message):
        item = (timestamp, message)
        
        if len(self.data_deque) == self.max_size:
            self.data_deque.popleft()

        for i, existing_item in enumerate(self.data_deque):
            if timestamp < existing_item[0]:
                self.data_deque.insert(i, item)
                break
        else:
            self.data_deque.append(item)

    def remove_timestamps(self, timestamps):
        to_remove = []
        for i, (ts, _) in enumerate(self.data_deque):
            if ts in timestamps:
                to_remove.append(i)
        
        for index in reversed(to_remove):
            del self.data_deque[index]

    def get_sorted_items(self):
        return list(self.data_deque)

    def clear(self):
        self.data_deque.clear()

    def get_last_timestamp(self):
        data = self.get_sorted_items()
        if len(data) > 0:
            return data[-1][0]
        return None
    
    def get_timestamp_for_target_message(self, target_message):
        data = self.get_sorted_items()
        for timestamp, message in data:
            if message == target_message:
                return timestamp
        return None
    
    def get_queue_length(self):
        return len(self.data_deque)
    
    def get_top_n_sorted_items_as_list(self, n):
        sorted_items = sorted(self.data_deque, key=lambda x: x[0])
        return sorted_items[:n]
    
    def assign_top_n_to_self(self, n, other=None):
        if other is not None and isinstance(other, LimitedSizeSortedDict):
            top_n_items = other.get_top_n_sorted_items_as_list(n)
            self.data_deque = deque(top_n_items, maxlen=self.max_size)
        else:
            raise ValueError("The 'other' argument should be an instance of LimitedSizeSortedDict")
        
    def get_top_n_timestamps(self, n):
        sorted_items = sorted(self.data_deque, key=lambda x: x[0])
        return [timestamp for timestamp, _ in sorted_items[:n]]


if __name__ == "__main__":
    limited_sorted_dict = LimitedSizeSortedDict(100)

    for i in range(120):
        now = datetime.datetime.now()
        timestamp = int(now.timestamp() * 1000)
        limited_sorted_dict.add_item(timestamp, f"Message {i}")

    sorted_messages = limited_sorted_dict.get_sorted_items()
    for ts, msg in sorted_messages:
        print(f"{ts}: {msg}")
    
    print("end: ",sorted_messages[-1][0]) 