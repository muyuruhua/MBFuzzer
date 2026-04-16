import numpy as np

class FieldMutationScheduler:
    def __init__(self, fields, initial_probability=0.1, learning_rate=0.1):
        self.fields = fields
        self.mutation_probabilities = {field: initial_probability for field in fields}
        self.field_effective_mutations = {field: 0 for field in fields}
        self.learning_rate = learning_rate
        self.reward_function = lambda effective_mutations: max(effective_mutations, 0) * (1 if effective_mutations > 0 else 0)

    def update_field_effective_mutations(self, field_effective_counts):
        for key, value in field_effective_counts.items():
            self.field_effective_mutations[key] += value

    def update_mutation_probabilities(self):
        field_effective_counts = self.field_effective_mutations
        for field, effective_count in field_effective_counts.items():
            if effective_count > 0:
                reward = self.reward_function(effective_count)
                new_probability = self.mutation_probabilities[field] + self.learning_rate * reward * (1 - self.mutation_probabilities[field])
                self.mutation_probabilities[field] = np.clip(new_probability, 0, 0.9) 

    def get_mutation_probability(self, field):
        assert field in self.fields, f"Field {field} not found in the list of fields"
        return self.mutation_probabilities[field]
    