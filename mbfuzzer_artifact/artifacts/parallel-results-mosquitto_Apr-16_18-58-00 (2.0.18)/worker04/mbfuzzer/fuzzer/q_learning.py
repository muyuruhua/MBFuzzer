import numpy as np
import pandas as pd
import os
import sys
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))
import globals as g
import hashlib
import random

class QLearningTable:
    def __init__(self, actions=g.ACTIONS, learning_rate=g.ALPHA, reward_decay=g.GAMMA, e_greedy=g.EPSILON):
        self.actions = actions
        self.learning_rate = learning_rate
        self.gamma = reward_decay
        self.epsilon = e_greedy
        self.q_table = {}

    def choose_next_action(self, state):

        self.check_state_exist(state)
        state_actions = self.q_table[state]

        if all(value == 0 for value in state_actions.values()):
            action = random.choice(self.actions)
            return action
        else:
            q_values = np.array(list(state_actions.values()))
            probabilities = np.exp(q_values / g.TAU) / np.sum(np.exp(q_values / g.TAU))
            rand_num = np.random.rand()
            cumulative_prob = 0.0
            for action, prob in zip(self.actions, probabilities):
                cumulative_prob += prob
                if rand_num < cumulative_prob:
                    return action
            return self.actions[-1]

    def check_state_exist(self, state):
        if state not in self.q_table:
            self.q_table[state] = {action: 0 for action in self.actions}

    def learn(self, cur_state, action, reward, next_state):
        if next_state is None:
            next_state = g.STATE_NONE

        self.check_state_exist(cur_state)
        self.check_state_exist(next_state)
        q_predict = self.q_table[cur_state][action] 
        q_target = reward + self.gamma * max(self.q_table[next_state].values()) 
        self.q_table[cur_state][action] += self.learning_rate * (q_target - q_predict)  

    def print_q_table(self):
        """Log the content of q_table"""
        print("Q Table:")
        for state, actions in self.q_table.items():
            print(state, actions)
        print("\n")

    def log_q_table(self):
        """Log the content of q_table"""
        content = "Q Table:\n"
        for state, actions in self.q_table.items():
            content += state + " " + str(actions) + "\n"
            q_values = np.array(list(actions.values()))
            probabilities = np.exp(q_values / g.TAU) / np.sum(np.exp(q_values / g.TAU))
            content += "\t" + str(probabilities) + "\n"
        content += "\n"
        return content


if __name__ == "__main__":
    q_learning = QLearningTable()
    q_learning.check_state_exist("state1")
    q_learning.check_state_exist("state2")
    q_learning.log_q_table()
    q_learning.learn("state1", "CONNECT", 1, "state2")
    q_learning.log_q_table()
    q_learning.learn("state1", "CONNECT", 1, "state2")
    q_learning.log_q_table()
    q_learning.learn("state2", "SUBSCRIBE", 1, "state3")
    q_learning.log_q_table()
    q_learning.learn("state2", "PUBLISH", 1, "state3")
    q_learning.learn("state2", "PUBLISH", 1, "state3")
    q_learning.learn("state2", "PUBLISH", 20, "state3")
    q_learning.log_q_table()
    q_learning.choose_next_action("state1")
    q_learning.choose_next_action("state2")