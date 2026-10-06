(ns jepsen.hearth.runner-test
  "Result classification (spec: \"Results are classified as pass, fail,
  xfail or xpass\"), on canned results.edn files."
  (:require [clojure.test :refer [deftest is testing]]
            [jepsen.hearth.runner :as runner]))

(defn- canned
  "The :valid? of a canned results.edn under test/resources/runner/."
  [case-name]
  (runner/read-valid (str "test/resources/runner/" case-name "/results.edn")))

(deftest canned-files-read
  (is (true? (canned "valid")))
  (is (false? (canned "invalid")))
  (is (= :unknown (canned "unknown")))
  (testing "Jepsen's tagged literals do not stop the reader"
    (is (false? (canned "invalid-tagged")))))

(deftest pass-and-valid-is-pass
  (is (= {:result :pass} (runner/classify :pass (canned "valid")))))

(deftest pass-and-invalid-or-unknown-is-fail
  (is (= {:result :fail} (runner/classify :pass (canned "invalid"))))
  (is (= {:result :fail} (runner/classify :pass (canned "unknown")))))

(deftest xfail-and-invalid-is-xfail
  (is (= {:result :xfail :gid "G1"}
         (runner/classify {:xfail "G1"} (canned "invalid")))))

(deftest xfail-and-valid-is-xpass
  (is (= {:result :xpass :gid "G1"}
         (runner/classify {:xfail "G1"} (canned "valid")))))

(deftest xfail-and-unknown-is-fail
  (testing "an xfail test that could not decide proves nothing either way"
    (is (= {:result :fail} (runner/classify {:xfail "G1"} (canned "unknown"))))))

(def expectations
  {"w1-set"   :pass
   "w1-lost"  :pass
   "r2-stale" {:xfail "G1"}
   "r3-fixed" {:xfail "G2"}})

(defn- run-of [test case-name]
  {:test test :valid? (canned case-name) :store (str "store/" test)})

(deftest a-fail-fails-the-run
  (let [v (runner/verdict expectations
                          [(run-of "w1-set" "valid")
                           (run-of "w1-lost" "invalid")
                           (run-of "r2-stale" "invalid")
                           (run-of "r3-fixed" "valid")])]
    (is (= 1 (:exit v)))
    (is (= [:pass :fail :xfail :xpass] (map :result (:rows v))))
    (testing "the failed row points at its history and node logs"
      (is (= "store/w1-lost" (:store (second (:rows v))))))))

(deftest xfail-and-xpass-do-not-fail-the-run
  (let [v (runner/verdict expectations
                          [(run-of "w1-set" "valid")
                           (run-of "r2-stale" "invalid")
                           (run-of "r3-fixed" "valid")])]
    (is (= 0 (:exit v)))
    (is (re-find #"XPASS G2 +r3-fixed" (runner/report v)))
    (is (re-find #"XFAIL G1 +r2-stale" (runner/report v)))))

(deftest a-test-without-an-expectation-fails-the-run
  (let [v (runner/verdict expectations [(run-of "unlisted" "valid")])]
    (is (= 1 (:exit v)))
    (is (= :fail (:result (first (:rows v)))))
    (is (re-find #"no expectation" (runner/report v)))))

(deftest the-repository-expectations-file-is-well-formed
  (let [e (runner/load-expectations "expectations.edn")]
    (is (map? e))
    (doseq [[test expect] e]
      (is (or (= :pass expect)
              (and (map? expect) (re-matches #"G[1-9]" (:xfail expect ""))))
          (str test " has expectation " (pr-str expect))))))
