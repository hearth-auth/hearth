(ns jepsen.hearth.audit-test
  "The audit-chain checker (W7) on hand-written histories, with planted
  violations (spec: \"The checkers are proven before they are trusted\")."
  (:require [clojure.test :refer [deftest is testing]]
            [jepsen.checker :as checker]
            [jepsen.history :as h]
            [jepsen.hearth.audit :as audit]))

(def test-map {:nodes ["n1" "n2" "n3"]})

(defn- change [process type]
  [{:process process :type :invoke :f :change :value process}
   {:process process :type type :f :change :value process}])

(defn- verify
  "A :verify on `node` that returns the server's {ok, event_count}."
  [process node ok count]
  [{:process process :type :invoke :f :verify :value nil :node node}
   {:process process :type :ok :f :verify :node node
    :value {:ok ok :event-count count}}])

(defn- check [& ops]
  (checker/check (audit/checker) test-map
                 (h/history (vec (apply concat ops))) {}))

(deftest every-node-verifies-the-chain
  (let [r (check (change 0 :ok) (change 1 :ok)
                 (verify 0 "n1" true 12) (verify 1 "n2" true 12) (verify 2 "n3" true 12))]
    (is (true? (:valid? r)) (pr-str r))))

(deftest a-broken-chain-is-invalid
  (testing "planted violation: n2's chain does not verify"
    (let [r (check (change 0 :ok) (change 1 :ok)
                   (verify 0 "n1" true 12) (verify 1 "n2" false 12) (verify 2 "n3" true 12))]
      (is (false? (:valid? r)))
      (is (= ["n2"] (:broken r)) (pr-str r)))))

(deftest a-node-left-unverified-is-invalid
  (let [r (check (change 0 :ok) (verify 0 "n1" true 12) (verify 1 "n2" true 12))]
    (is (false? (:valid? r)))
    (is (= ["n3"] (:unverified r)) (pr-str r))))

(deftest a-run-with-no-acknowledged-change-proves-nothing
  (let [r (check (change 0 :fail)
                 (verify 0 "n1" true 1) (verify 1 "n2" true 1) (verify 2 "n3" true 1))]
    (is (false? (:valid? r)))
    (is (re-find #"no admin change" (:error r)) (pr-str r))))
