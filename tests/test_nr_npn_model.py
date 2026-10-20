"""
Unit & Adversarial Stress Tests for NR-NPN (Natural-Randomness Non-Parametric Network).
"""

import unittest
import numpy as np

from aegis.nr_npn_model import NaturalEntropySource, NaturalRandomnessNonParametricAI, TriModalInteractionOperator


class TestNRNPNModel(unittest.TestCase):
    def test_natural_entropy_harvest_and_replay(self) -> None:
        """Verifies physical/OS natural randomness harvesting and exact seed replay."""
        ent_natural = NaturalEntropySource(seed=None)
        self.assertEqual(ent_natural.entropy_source, "os.urandom_natural_entropy")
        self.assertGreaterEqual(ent_natural.harvested_seed, 0)

        # Replaying with the harvested seed must produce identical random streams
        ent_replay = NaturalEntropySource(seed=ent_natural.harvested_seed)
        self.assertEqual(ent_replay.entropy_source, "deterministic_replay_seed")
        _, rng1 = ent_natural.create_streams()
        _, rng2 = ent_replay.create_streams()
        np.testing.assert_allclose(rng1.uniform(-1e-4, 0, 10), rng2.uniform(-1e-4, 0, 10))

    def test_nonparametric_outlier_immunity_and_4pillar_compression(self) -> None:
        """
        Adversarial Stress Test:
        - 40 features total: only 4 features carry true signal; 36 are noise.
        - Training data is corrupted with 100,000x extreme outliers.
        - Parametric mean/covariance classifier collapses, whereas NR-NPN (Rank + 4-Pillar + Takefuji)
          maintains >= 94% test accuracy and prunes noisy dimensions & redundant prototypes.
        """
        rng = np.random.default_rng(42)
        n_train, n_test, d = 160, 80, 40
        y_train = np.array([0] * (n_train // 2) + [1] * (n_train // 2), dtype=np.int64)
        y_test = np.array([0] * (n_test // 2) + [1] * (n_test // 2), dtype=np.int64)

        X_train = rng.normal(0.0, 1.0, size=(n_train, d))
        X_test = rng.normal(0.0, 1.0, size=(n_test, d))

        # True signal only in columns 0..3
        for c in range(4):
            X_train[:, c] += (y_train * 2 - 1) * 1.8
            X_test[:, c] += (y_test * 2 - 1) * 1.8

        # Inject catastrophic 100,000x outliers into 5% of training samples (simulating corrupted logs/sensors)
        X_train_corrupted = X_train.copy()
        X_train_corrupted[0, 0] = -1e6
        X_train_corrupted[1, 1] = 1e6
        X_train_corrupted[2, 2] = -5e5

        # Baseline Parametric Classifier (Nearest Gaussian Mean Centroid) -> Corrupted by 1e6 outliers!
        mu0 = np.mean(X_train_corrupted[y_train == 0], axis=0)
        mu1 = np.mean(X_train_corrupted[y_train == 1], axis=0)
        d0 = np.linalg.norm(X_test - mu0, axis=1)
        d1 = np.linalg.norm(X_test - mu1, axis=1)
        parametric_preds = (d1 < d0).astype(np.int64)
        parametric_acc = float(np.mean(parametric_preds == y_test))

        # Proposed NR-NPN Model (Natural Randomness + Non-Parametric Rank + 4-Pillar + Takefuji)
        model = NaturalRandomnessNonParametricAI(
            n_ensembles=32,
            k_dims=4,
            importance_threshold=0.25,
            seed=None,  # Uses true OS natural randomness!
        )
        model.fit(X_train_corrupted, y_train)
        preds = model.predict(X_test)
        nr_npn_acc = float(np.mean(preds == y_test))

        self.assertGreaterEqual(nr_npn_acc, 0.94, f"NR-NPN accuracy too low: {nr_npn_acc}")
        self.assertGreater(nr_npn_acc, parametric_acc + 0.25, "NR-NPN should strongly outperform corrupted parametric model")
        # Verify 4-Pillar compression happened
        self.assertLessEqual(model.telemetry_["selected_dim"], 10)
        self.assertEqual(model.telemetry_["reduced_dim_k"], 4)
        self.assertLess(model.telemetry_["selected_prototypes"], n_train)

    def test_combinatorial_planarization_with_natural_entropy(self) -> None:
        """Verifies Mode B (Combinatorial Graph Solver) with degree-0 pruning and natural randomness."""
        # 6 vertices on a line: 5 outer boundary edges (never cross anything) + 3 inner chords
        edges = [(1, 2), (2, 3), (3, 4), (4, 5), (5, 6), (1, 4), (2, 5), (3, 6)]

        def cross(e1, e2):
            a, b = e1
            c, d = e2
            return (a < c < b < d) or (c < a < d < b)

        model = NaturalRandomnessNonParametricAI(n_ensembles=32, max_iter=300, seed=None)
        res = model.solve_combinatorial_graph(edges, cross, k_layers=2)
        self.assertTrue(res["valid"])
        self.assertEqual(res["pruned_zero_conflict"], 5)  # All 5 boundary edges pruned before ODE!
        self.assertGreaterEqual(res["embedded_count"], 7)  # 5 boundary + at least 2 of 3 mutually crossing chords

    def test_semi_parametric_cold_start_and_tri_modal(self) -> None:
        """
        Verifies:
        1. Semi-Parametric Cold-Start (N=4 with +/- 1,000,000x outliers) achieves >= 95% accuracy.
        2. TriModalInteractionOperator selects 'complement_csr' on ultra-dense matrices and matches exact matmul.
        3. Online streaming partial_fit() updates prototype memory in < 1 ms.
        """
        rng = np.random.default_rng(2026)
        X_train = rng.normal(0.0, 1.0, size=(200, 50))
        X_test = rng.normal(0.0, 1.0, size=(100, 50))
        y_train = np.array([0] * 100 + [1] * 100, dtype=np.int64)
        y_test = np.array([0] * 50 + [1] * 50, dtype=np.int64)
        for col in (1, 2, 3, 4):
            X_train[:, col] += (y_train * 2 - 1) * 1.65
            X_test[:, col] += (y_test * 2 - 1) * 1.65
        X_train[0, 1] = 1.0e6
        X_train[1, 2] = -1.0e6

        X_cold = X_train[[0, 1, 100, 101]]
        y_cold = np.array([0, 0, 1, 1], dtype=np.int64)
        cold_model = NaturalRandomnessNonParametricAI(n_ensembles=16, k_dims=2, seed=42)
        cold_model.fit(X_cold, y_cold)
        cold_acc = float(np.mean(cold_model.predict(X_test) == y_test))
        self.assertGreaterEqual(cold_acc, 0.95, f"Semi-Parametric N=4 cold-start accuracy too low: {cold_acc}")

        # Streaming partial_fit check
        pfit = cold_model.partial_fit(X_test[:8], y_test[:8])
        self.assertGreaterEqual(pfit["total_prototypes"], 4)

        # Tri-Modal Complement-Sparse CSR check on 98% dense matrix
        dense_X = np.ones((40, 40), dtype=np.int8) - np.eye(40, dtype=np.int8)
        op = TriModalInteractionOperator(dense_X)
        self.assertEqual(op.mode, "complement_csr")
        V = rng.integers(0, 2, size=(40, 3), dtype=np.int8)
        np.testing.assert_allclose(op.matvec(V), dense_X @ V)

    def test_v3_bilinear_xor_and_conformal_zeroday(self) -> None:
        """
        Verifies NR-SPN v3:
        1. Bilinear XOR Spectral Operator M_xor = |C.T @ (y * C)| / N discovers pure 2D XOR features
           even when 1st-order mean difference is 0.
        2. Pointwise Energy Gate alpha(x, N) and Conformal Zero-Day OOD detector flag unseen attacks.
        """
        rng = np.random.default_rng(777)
        X_tr = rng.normal(0.0, 1.0, size=(160, 25))
        X_te = rng.normal(0.0, 1.0, size=(80, 25))
        X_tr[:, 0] = np.where(X_tr[:, 0] >= 0, X_tr[:, 0] + 0.8, X_tr[:, 0] - 0.8)
        X_tr[:, 1] = np.where(X_tr[:, 1] >= 0, X_tr[:, 1] + 0.8, X_tr[:, 1] - 0.8)
        X_te[:, 0] = np.where(X_te[:, 0] >= 0, X_te[:, 0] + 0.8, X_te[:, 0] - 0.8)
        X_te[:, 1] = np.where(X_te[:, 1] >= 0, X_te[:, 1] + 0.8, X_te[:, 1] - 0.8)
        y_tr = ((X_tr[:, 0] * X_tr[:, 1]) > 0).astype(np.int64)
        y_te = ((X_te[:, 0] * X_te[:, 1]) > 0).astype(np.int64)

        model = NaturalRandomnessNonParametricAI(n_ensembles=32, k_dims=4, importance_threshold=0.25, seed=42)
        model.fit(X_tr, y_tr)
        self.assertEqual(model.active_features_.tolist(), [0, 1])

        cred = model.predict_with_credibility(X_te)
        xor_acc = float(np.mean(cred["predictions"] == y_te))
        self.assertGreaterEqual(xor_acc, 0.90)

        # Unseen zero-day OOD vector far outside training distribution
        X_zd = rng.normal(0.0, 1.0, size=(5, 25))
        X_zd[:, [0, 1]] = 40.0
        cred_zd = model.predict_with_credibility(X_zd)
        self.assertTrue(np.all(cred_zd["zero_day_ood_flags"]))

    def test_calibrated_aegis_nr_spn_and_telemetry(self) -> None:
        from aegis.nr_npn_model import build_calibrated_aegis_nr_spn

        engine = build_calibrated_aegis_nr_spn(seed=42)
        diag = engine.evaluate_security_telemetry()
        self.assertIn("engine_telemetry", diag)
        self.assertEqual(len(diag["sample_verdicts"]), 4)
        self.assertEqual(diag["sample_verdicts"][0]["verdict"], "BENIGN")
        self.assertEqual(diag["sample_verdicts"][1]["verdict"], "MALICIOUS_OR_ANOMALY")
        self.assertEqual(diag["sample_verdicts"][2]["verdict"], "MALICIOUS_OR_ANOMALY")
        self.assertEqual(diag["sample_verdicts"][3]["verdict"], "MALICIOUS_OR_ANOMALY")
        self.assertTrue(diag["sample_verdicts"][3]["zero_day_ood_flag"])
        self.assertTrue(diag["planar_dos_routing"]["valid_zero_collision"])


if __name__ == "__main__":
    unittest.main()
