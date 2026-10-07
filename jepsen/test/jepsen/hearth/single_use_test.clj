(ns jepsen.hearth.single-use-test
  "The single-use workload's checker (W4) on hand-written histories, with a
  planted violation (spec: \"The checkers are proven before they are
  trusted\")."
  (:require [clojure.test :refer [deftest is testing]]
            [jepsen.checker :as checker]
            [jepsen.history :as h]
            [jepsen.hearth.single-use :as single-use]))

(defn- redeem
  "A redemption of artifact `n` (its place in the chain) by `process` that
  completes with `type`."
  [process n type]
  [{:process process :type :invoke :f :redeem :value n}
   {:process process :type type :f :redeem :value n}])

(defn- check [& pairs]
  (checker/check (single-use/checker) {} (h/history (vec (apply concat pairs))) {}))

(deftest one-success-per-artifact-is-valid
  (let [r (check (redeem 0 0 :ok) (redeem 1 0 :fail) (redeem 2 0 :info)
                 (redeem 0 1 :fail) (redeem 1 1 :ok))]
    (is (true? (:valid? r)) (pr-str r))
    (is (= 2 (:redeemed r)))))

(deftest two-successes-for-one-artifact-is-invalid
  (testing "planted violation: two :ok redemptions of artifact 1"
    (let [r (check (redeem 0 0 :ok)
                   (redeem 1 1 :ok) (redeem 2 1 :ok) (redeem 0 1 :fail))]
      (is (false? (:valid? r)))
      (is (= {1 2} (:duplicates r)) (pr-str r)))))

(deftest a-run-with-no-success-proves-nothing
  (let [r (check (redeem 0 0 :fail) (redeem 1 0 :info))]
    (is (false? (:valid? r)))
    (is (re-find #"no redemption" (:error r)) (pr-str r))))
