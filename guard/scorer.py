"""Layer 2: a lightweight statistical scorer (token log-odds).

This is deliberately simple and honest: a Naive-Bayes-style scorer that
learns, from a small bundled labeled dataset, how strongly each token is
associated with attack vs. benign prompts. It is a *statistical* scorer —
not a neural network and not a deep-learning model.

How it works:
  1. Tokenize each labeled prompt (lowercase alphanumeric tokens).
  2. For every token, compute a smoothed log-odds weight:
         w(t) = log P(t | attack) - log P(t | benign)
  3. Score a new prompt by averaging the weights of its known tokens and
     passing the result through a logistic function, giving 0-100.

Known limitation: the weights are learned from the same small dataset that
ships with the project, so in-sample accuracy is optimistic. Treat the
measured numbers in the README as a smoke test, not a benchmark.
"""

from __future__ import annotations

import json
import math
import re
from collections import Counter
from pathlib import Path

_TOKEN = re.compile(r"[a-z0-9']+")
_ALPHA = 1.0  # Laplace smoothing


def tokenize(text: str) -> list[str]:
    return _TOKEN.findall(text.lower())


class StatisticalScorer:
    def __init__(self, weights: dict[str, float], prior_log_odds: float = 0.0):
        self.weights = weights
        self.prior_log_odds = prior_log_odds

    @classmethod
    def train(cls, attack_prompts: list[str], benign_prompts: list[str]) -> "StatisticalScorer":
        attack_counts: Counter[str] = Counter()
        benign_counts: Counter[str] = Counter()
        for prompt in attack_prompts:
            attack_counts.update(set(tokenize(prompt)))
        for prompt in benign_prompts:
            benign_counts.update(set(tokenize(prompt)))

        n_attack = max(len(attack_prompts), 1)
        n_benign = max(len(benign_prompts), 1)
        vocab = set(attack_counts) | set(benign_counts)

        weights: dict[str, float] = {}
        for token in vocab:
            p_attack = (attack_counts[token] + _ALPHA) / (n_attack + 2 * _ALPHA)
            p_benign = (benign_counts[token] + _ALPHA) / (n_benign + 2 * _ALPHA)
            weights[token] = math.log(p_attack) - math.log(p_benign)

        prior = math.log(n_attack) - math.log(n_benign)
        return cls(weights, prior)

    @classmethod
    def from_dataset(cls, path: Path) -> "StatisticalScorer":
        data = json.loads(path.read_text(encoding="utf-8"))
        return cls.train(data["attack"], data["benign"])

    def score(self, text: str) -> float:
        """Return a 0-100 statistical risk score for a prompt.

        The average is taken over *all* unique tokens in the prompt, with
        unknown tokens contributing 0. That keeps long documents that happen
        to contain one attack-associated word ("all", "system") from being
        scored as attacks just because few of their tokens are in the
        training vocabulary.
        """
        unique_tokens = set(tokenize(text))
        if not unique_tokens:
            return 8.0  # nothing to score: low, near-neutral
        total = sum(self.weights.get(t, 0.0) for t in unique_tokens)
        avg = total / len(unique_tokens)
        log_odds = self.prior_log_odds + avg * 2.2  # scale averaged weights
        probability = 1.0 / (1.0 + math.exp(-log_odds))
        return round(probability * 100, 1)
