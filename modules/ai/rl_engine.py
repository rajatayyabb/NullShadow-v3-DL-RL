import random
import time

class NullShadowRL:
    def __init__(self):
        self.state_space = ["recon", "scanning", "exploitation", "post-exploitation"]
        self.actions = [0, 1] # 0: cautious, 1: aggressive
        self.q_table = {state: [0.0] * len(self.actions) for state in self.state_space}
        self.current_ip_layout = "192.168.1.0/24"
        self.learning_rate = 0.1
        self.discount_factor = 0.9
        self.epsilon = 0.1

    def choose_action(self, state):
        if random.uniform(0, 1) < self.epsilon:
            return random.choice(self.actions)
        return self.q_table[state].index(max(self.q_table[state]))

    def update_q_table(self, state, action, reward, next_state):
        old_value = self.q_table[state][action]
        next_max = max(self.q_table[next_state])
        new_value = (1 - self.learning_rate) * old_value + self.learning_rate * (reward + self.discount_factor * next_max)
        self.q_table[state][action] = new_value

    def two_agent_chess_loop(self):
        """Simulates a Red Team vs Blue Team loop."""
        print("[*] Starting Two-Agent Chess Loop...")
        for i in range(3):
            # Red Team Action
            action = random.choice(["scan_port", "brute_force", "exploit_vuln"])
            print(f"[Red Team] Action: {action}")
            
            # Blue Team Action
            defense = random.choice(["block_ip", "rotate_keys", "update_firewall"])
            print(f"[Blue Team] Response: {defense}")
            time.sleep(0.5)

    def shifting_maze(self):
        """Moving Target Defense: Shuffles internal simulated IP layouts."""
        old_layout = self.current_ip_layout
        new_suffix = random.randint(0, 255)
        self.current_ip_layout = f"10.0.{new_suffix}.0/24"
        print(f"[MTD] Shifting Maze: {old_layout} -> {self.current_ip_layout}")
        return self.current_ip_layout

    def reward_shaping_function(self, action_success, malicious_traffic_blocked, user_disruption):
        """Scores the model: positive for blocking malice, heavy negative for user disruption."""
        score = 0
        if malicious_traffic_blocked:
            score += 10
        if action_success:
            score += 5
        if user_disruption:
            score -= 50 # Heavy penalty for disrupting legitimate users
        
        print(f"[RL] Reward Shaping Score: {score}")
        return score

    def run_simulation(self):
        self.two_agent_chess_loop()
        self.shifting_maze()
        self.reward_shaping_function(True, True, False)
