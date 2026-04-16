from collections import defaultdict
import threading

class DependencyQueue:
    def __init__(self):
        self.data = defaultdict(list)   # "client": [Dependency1, ...], "broker": [Dependency2, ...]
        self.lock = threading.Lock()

    def add_dependency(self, flag, dependency):
        with self.lock:
            self.data[flag].append(dependency)

    def has_dependency_with_flag(self, flag: str) -> bool:
        with self.lock:
            return len(self.data[flag]) > 0

    def get_dependencies_with_flag(self, flag: str):
        with self.lock:
            dependencies = self.data[flag]
            if dependencies:
                first_dependency = dependencies.pop(0)
                if not dependencies:
                    del self.data[flag]
                return first_dependency
            else:
                return None

    def clear(self, flag):
        with self.lock:
            flag_dependencies = self.data.get(flag, [])
            self.data[flag] = [dependency for dependency in flag_dependencies if "persistent" in dependency.values() or list(dependency.values())[0]['flag'] != flag] 
